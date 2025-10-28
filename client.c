#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <libssh/libssh.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <math.h>

#define PORT_NUM 8080

// ... (calculate_hash function is fine) ...
void calculate_hash(const char* file_name, unsigned char* hash_out, unsigned int* hash_len) {
    FILE* file = fopen(file_name, "rb");
    if (!file) {
        perror("File not found for hashing");
        exit(EXIT_FAILURE);
    }
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    const EVP_MD* md = EVP_sha256();
    EVP_DigestInit_ex(mdctx, md, NULL);
    unsigned char buffer[1024];
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        EVP_DigestUpdate(mdctx, buffer, bytes_read);
    }
    fclose(file);
    EVP_DigestFinal_ex(mdctx, hash_out, hash_len);
    EVP_MD_CTX_free(mdctx);
}

typedef struct {
    int thread_id;
    int total_threads;
    const char* file_name;
    const char* server_ip;
    int output_fd;
} thread_arg;

void* receive_file_segment(void* arg) {
    thread_arg* t_arg = (thread_arg*)arg;
    ssh_session session;
    ssh_channel channel;
    int rc;

    session = ssh_new();
    if (session == NULL) {
        fprintf(stderr, "Thread %d: Failed to create SSH session.\n", t_arg->thread_id);
        pthread_exit(NULL);
    }
    
    int port = PORT_NUM;

    ssh_options_set(session, SSH_OPTIONS_HOST, t_arg->server_ip);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    
    // **THE FIX IS HERE. TELL IT TO SPEAK MODERN LANGUAGES.**
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    
    // This is still insecure for a real app, but fine for your localhost test
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);

    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Thread %d: Error connecting to server: %s\n", t_arg->thread_id, ssh_get_error(session));
        ssh_free(session);
        pthread_exit(NULL);
    }
    
    rc = ssh_userauth_password(session, "user", "pass");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Thread %d: Authentication failed: %s\n", t_arg->thread_id, ssh_get_error(session));
        ssh_disconnect(session);
        ssh_free(session);
        pthread_exit(NULL);
    }

    channel = ssh_channel_new(session);
    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        pthread_exit(NULL);
    }

    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        pthread_exit(NULL);
    }

    char command[512];
    snprintf(command, sizeof(command), "GET %s %d %d", t_arg->file_name, t_arg->thread_id, t_arg->total_threads);

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        fprintf(stderr, "Thread %d: Failed to exec command.\n", t_arg->thread_id);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        pthread_exit(NULL);
    }
    
    char buffer[4096];
    int nbytes;
    
    long current_offset;
    struct stat st;
    stat(t_arg->file_name, &st);
    long file_size = st.st_size;
    long segment_size = ceil((double)file_size / t_arg->total_threads);
    current_offset = (long)t_arg->thread_id * segment_size;
    
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        ssize_t written = pwrite(t_arg->output_fd, buffer, nbytes, current_offset);
        if (written < 0) {
            perror("pwrite failed");
            break;
        }
        current_offset += written;
    }
    
    printf("Thread %d finished receiving.\n", t_arg->thread_id);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    pthread_exit(NULL);
}

// ... (main function is fine) ...
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_ip> <file_name> <num_threads>\n", argv[0]);
        return -1;
    }

    char* server_ip = argv[1];
    char* file_name = argv[2];
    int num_threads = atoi(argv[3]);

    if(access(file_name, F_OK) != 0) {
        fprintf(stderr, "Error: Source file '%s' not found locally.\n", file_name);
        return -1;
    }

    unsigned char local_hash[EVP_MAX_MD_SIZE];
    unsigned int local_hash_len = 0;
    calculate_hash(file_name, local_hash, &local_hash_len);

    char output_file_name[256];
    snprintf(output_file_name, sizeof(output_file_name), "rcv_%s", file_name);

    int output_fd = open(output_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0) {
        perror("Failed to create output file");
        return -1;
    }

    pthread_t threads[num_threads];
    thread_arg args[num_threads];

    printf("Starting %d threads to download '%s' from %s...\n", num_threads, file_name, server_ip);

    for (int i = 0; i < num_threads; i++) {
        args[i].thread_id = i;
        args[i].total_threads = num_threads;
        args[i].file_name = file_name;
        args[i].server_ip = server_ip;
        args[i].output_fd = output_fd;
        pthread_create(&threads[i], NULL, receive_file_segment, &args[i]);
    }

    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    close(output_fd);
    printf("File transfer complete. Output saved to '%s'.\n", output_file_name);

    unsigned char remote_hash[EVP_MAX_MD_SIZE];
    unsigned int remote_hash_len = 0;
    calculate_hash(output_file_name, remote_hash, &remote_hash_len);

    if (local_hash_len == remote_hash_len && memcmp(local_hash, remote_hash, local_hash_len) == 0) {
        printf("✅ File integrity verified: Hashes match!\n");
    } else {
        printf("❌ File integrity compromised: Hash mismatch!\n");
    }

    printf("Original Hash: ");
    for(int i=0; i < local_hash_len; i++) printf("%02x", local_hash[i]);
    printf("\nReceived Hash: ");
    for(int i=0; i < remote_hash_len; i++) printf("%02x", remote_hash[i]);
    printf("\n");

    return 0;
}