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

// ... (calculate_hash function is unchanged) ...
void calculate_hash(const char* file_name, unsigned char* hash_out, unsigned int* hash_len) {
    FILE* file = fopen(file_name, "rb");
    if (!file) {
        *hash_len = 0; // Indicate error
        return;
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

// **NEW STRUCT MEMBERS**
typedef struct {
    int thread_id;
    int total_threads;
    const char* file_name;
    const char* server_ip;
    int output_fd;
    long file_size; // Threads now get the file size from main
} thread_arg;

// **THREAD LOGIC UPGRADE**
void* receive_file_segment(void* arg) {
    thread_arg* t_arg = (thread_arg*)arg;
    ssh_session session;
    ssh_channel channel;
    int rc;

    session = ssh_new();
    int port = PORT_NUM;
    ssh_options_set(session, SSH_OPTIONS_HOST, t_arg->server_ip);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);
    
    // ... (connection and auth logic is the same) ...
    rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, "Thread %d: Error connecting: %s\n", t_arg->thread_id, ssh_get_error(session));
        ssh_free(session); pthread_exit(NULL);
    }
    rc = ssh_userauth_password(session, "user", "pass");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Thread %d: Auth failed: %s\n", t_arg->thread_id, ssh_get_error(session));
        ssh_disconnect(session); ssh_free(session); pthread_exit(NULL);
    }
    channel = ssh_channel_new(session);
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        ssh_channel_free(channel); ssh_disconnect(session); ssh_free(session); pthread_exit(NULL);
    }

    char command[512];
    snprintf(command, sizeof(command), "GET %s %d %d", t_arg->file_name, t_arg->thread_id, t_arg->total_threads);

    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        ssh_channel_close(channel); ssh_channel_free(channel); ssh_disconnect(session); ssh_free(session); pthread_exit(NULL);
    }
    
    char buffer[4096];
    int nbytes;
    
    // **NO MORE stat()! We use the file size from the server.**
    long segment_size = ceil((double)t_arg->file_size / t_arg->total_threads);
    long current_offset = (long)t_arg->thread_id * segment_size;
    
    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
        pwrite(t_arg->output_fd, buffer, nbytes, current_offset);
        current_offset += nbytes;
    }
    
    printf("Thread %d finished receiving.\n", t_arg->thread_id);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);

    pthread_exit(NULL);
}


// **NEW FUNCTION to get info from the server**
int get_file_info(const char* server_ip, const char* file_name, long* file_size, unsigned char* server_hash) {
    ssh_session session = ssh_new();
    int port = PORT_NUM;
    ssh_options_set(session, SSH_OPTIONS_HOST, server_ip);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);

    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, "Error getting file info: %s\n", ssh_get_error(session));
        ssh_free(session); return -1;
    }
    if (ssh_userauth_password(session, "user", "pass") != SSH_AUTH_SUCCESS) {
        fprintf(stderr, "Auth failed for info check: %s\n", ssh_get_error(session));
        ssh_disconnect(session); ssh_free(session); return -1;
    }

    ssh_channel channel = ssh_channel_new(session);
    ssh_channel_open_session(channel);

    char command[512];
    snprintf(command, sizeof(command), "INFO %s", file_name);
    ssh_channel_request_exec(channel, command);

    char buffer[512] = {0};
    ssh_channel_read(channel, buffer, sizeof(buffer), 0);

    if (strncmp(buffer, "ERROR", 5) == 0) {
        fprintf(stderr, "Server error: %s\n", buffer);
        ssh_channel_close(channel); ssh_channel_free(channel); ssh_disconnect(session); ssh_free(session); return -1;
    }

    // Parse the response "size hash_hex_string"
    char hash_hex[EVP_MAX_MD_SIZE * 2 + 1] = {0};
    sscanf(buffer, "%ld %s", file_size, hash_hex);
    
    // Convert hex string back to binary hash
    for (size_t i = 0; i < strlen(hash_hex) / 2; i++) {
        sscanf(hash_hex + 2 * i, "%2hhx", &server_hash[i]);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}

// **MAIN LOGIC UPGRADE**
int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_ip> <file_name> <num_threads>\n", argv[0]);
        return -1;
    }

    char* server_ip = argv[1];
    char* file_name = argv[2];
    int num_threads = atoi(argv[3]);

    // **Step 1: Get the file's real info from the server.**
    long file_size = 0;
    unsigned char server_hash[EVP_MAX_MD_SIZE];
    printf("Asking server for info about '%s'...\n", file_name);
    if (get_file_info(server_ip, file_name, &file_size, server_hash) != 0) {
        fprintf(stderr, "Could not get file info from server. Does the file exist there?\n");
        return -1;
    }
    printf("Server says file size is %ld bytes. Starting download.\n", file_size);


    // **Step 2: Prepare for download.**
    char output_file_name[256];
    snprintf(output_file_name, sizeof(output_file_name), "rcv_%s", file_name);
    int output_fd = open(output_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);


    // **Step 3: Start the parallel download.**
    pthread_t threads[num_threads];
    thread_arg args[num_threads];
    for (int i = 0; i < num_threads; i++) {
        args[i].thread_id = i;
        args[i].total_threads = num_threads;
        args[i].file_name = file_name;
        args[i].server_ip = server_ip;
        args[i].output_fd = output_fd;
        args[i].file_size = file_size; // Give each thread the correct total size
        pthread_create(&threads[i], NULL, receive_file_segment, &args[i]);
    }
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    close(output_fd);
    printf("File transfer complete. Output saved to '%s'.\n", output_file_name);


    // **Step 4: Verify the download against the server's hash.**
    unsigned char client_hash[EVP_MAX_MD_SIZE];
    unsigned int client_hash_len = 0;
    calculate_hash(output_file_name, client_hash, &client_hash_len);

    if (client_hash_len > 0 && memcmp(server_hash, client_hash, client_hash_len) == 0) {
        printf("✅ File integrity verified: Hashes match!\n");
    } else {
        printf("❌ File integrity compromised: Hash mismatch!\n");
    }

    printf("Server Hash:   ");
    for(int i=0; i < 32; i++) printf("%02x", server_hash[i]);
    printf("\nReceived Hash: ");
    for(int i=0; i < client_hash_len; i++) printf("%02x", client_hash[i]);
    printf("\n");

    return 0;
}