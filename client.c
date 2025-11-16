#include <libssh/libssh.h>
#include <libssh/sftp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <math.h>
#include <openssl/evp.h>
#include <time.h>
#include <dirent.h>
#include <libgen.h>

#define PORT_NUM 8080

// ANSI color codes
#define COLOR_RED     "\x1b[31m"
#define COLOR_GREEN   "\x1b[32m"
#define COLOR_YELLOW  "\x1b[33m"
#define COLOR_BLUE    "\x1b[34m"
#define COLOR_CYAN    "\x1b[36m"
#define COLOR_RESET   "\x1b[0m"

// Global progress tracking
typedef struct {
    long bytes_downloaded;
    long total_bytes;
    time_t start_time;
    pthread_mutex_t lock;
    int active;
} progress_t;

progress_t global_progress = {0, 0, 0, PTHREAD_MUTEX_INITIALIZER, 1};

// Hash calculation function
void calculate_hash(const char* file_name, unsigned char* hash_out, unsigned int* hash_len) {
    FILE* file = fopen(file_name, "rb");
    if (!file) {
        *hash_len = 0;
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

// Thread arguments structure
typedef struct {
    int thread_id;
    int total_threads;
    const char* file_name;
    const char* server_ip;
    int output_fd;
    long file_size;
} thread_arg;

// Progress display thread
void* progress_display(void *arg) {
    while (global_progress.active) {
        pthread_mutex_lock(&global_progress.lock);
        
        if (global_progress.total_bytes == 0) {
            pthread_mutex_unlock(&global_progress.lock);
            usleep(100000);
            continue;
        }
        
        float percent = (float)global_progress.bytes_downloaded / global_progress.total_bytes * 100.0;
        long elapsed = time(NULL) - global_progress.start_time;
        if (elapsed == 0) elapsed = 1;
        
        float speed_mbps = (global_progress.bytes_downloaded / (float)elapsed) / (1024.0 * 1024.0);
        long remaining_bytes = global_progress.total_bytes - global_progress.bytes_downloaded;
        long eta = (global_progress.bytes_downloaded > 0) ? 
                   (remaining_bytes * elapsed) / global_progress.bytes_downloaded : 0;
        
        // Draw progress bar
        printf("\r" COLOR_CYAN "[");
        int bar_width = 40;
        int filled = (int)(percent / 100.0 * bar_width);
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) printf("=");
            else if (i == filled) printf(">");
            else printf(" ");
        }
        printf("] " COLOR_RESET);
        printf(COLOR_GREEN "%.1f%%" COLOR_RESET " | ", percent);
        printf(COLOR_YELLOW "%.2f MB/s" COLOR_RESET " | ", speed_mbps);
        printf("ETA: " COLOR_BLUE "%02ld:%02ld" COLOR_RESET, eta/60, eta%60);
        fflush(stdout);
        
        pthread_mutex_unlock(&global_progress.lock);
        usleep(200000);  // 200ms refresh
    }
    printf("\n");
    return NULL;
}

// Thread function with retry logic and offset reset fix
void* receive_file_segment(void* arg) {
    thread_arg* t_arg = (thread_arg*)arg;
    
    // Calculate chunk boundaries
    long chunk_size = t_arg->file_size / t_arg->total_threads;
    long start_byte = (long)t_arg->thread_id * chunk_size;
    long end_byte;

    if (t_arg->thread_id == t_arg->total_threads - 1) {
        end_byte = t_arg->file_size - 1;
    } else {
        end_byte = start_byte + chunk_size - 1;
    }

    long bytes_expected = end_byte - start_byte + 1;
    long current_offset = start_byte;
    long bytes_received = 0;
    
    char buffer[65536];  // 64KB buffer
    int nbytes;
    
    int max_retries = 3;
    int retry_count = 0;
    
retry_transfer:
    // ========== CRITICAL FIX: Reset offset on retry ==========
    bytes_received = 0;
    current_offset = start_byte;  // Reset write position to start of chunk
    
    if (retry_count > 0) {
        fprintf(stderr, COLOR_YELLOW "\nThread %d: Retry %d/%d (redownloading chunk)\n" COLOR_RESET,
                t_arg->thread_id, retry_count, max_retries);
        sleep(2 + retry_count);
    }
    
    // Each thread creates its own SSH session
    ssh_session session = ssh_new();
    if (!session) {
        fprintf(stderr, COLOR_RED "Thread %d: Failed to create SSH session\n" COLOR_RESET, t_arg->thread_id);
        pthread_exit(NULL);
    }
    
    int port = PORT_NUM;
    ssh_options_set(session, SSH_OPTIONS_HOST, t_arg->server_ip);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);
    
    long timeout = 120;
    ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
    
    int rc = ssh_connect(session);
    if (rc != SSH_OK) {
        fprintf(stderr, COLOR_RED "Thread %d: Connect failed: %s\n" COLOR_RESET,
                t_arg->thread_id, ssh_get_error(session));
        ssh_free(session);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }
    
    rc = ssh_userauth_password(session, "user", "pass");
    if (rc != SSH_AUTH_SUCCESS) {
        fprintf(stderr, COLOR_RED "Thread %d: Auth failed\n" COLOR_RESET, t_arg->thread_id);
        ssh_disconnect(session);
        ssh_free(session);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }
    
    ssh_channel channel = ssh_channel_new(session);
    if (!channel) {
        fprintf(stderr, COLOR_RED "Thread %d: Channel creation failed\n" COLOR_RESET, t_arg->thread_id);
        ssh_disconnect(session);
        ssh_free(session);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }
    
    rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK) {
        fprintf(stderr, COLOR_RED "Thread %d: Channel open failed\n" COLOR_RESET, t_arg->thread_id);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }
    
    char command[512];
    snprintf(command, sizeof(command), "GET %s %d %d", t_arg->file_name, t_arg->thread_id, t_arg->total_threads);
    
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        fprintf(stderr, COLOR_RED "Thread %d: Exec failed\n" COLOR_RESET, t_arg->thread_id);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }
    
    // Robust read loop
    while (bytes_received < bytes_expected) {
        long remaining = bytes_expected - bytes_received;
        size_t to_request = (remaining < sizeof(buffer)) ? remaining : sizeof(buffer);
        
        nbytes = ssh_channel_read(channel, buffer, to_request, 0);
        
        if (nbytes < 0) {
            fprintf(stderr, COLOR_RED "\nThread %d: Read error\n" COLOR_RESET, t_arg->thread_id);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            ssh_disconnect(session);
            ssh_free(session);
            
            // Subtract bytes we thought we had from progress
            pthread_mutex_lock(&global_progress.lock);
            global_progress.bytes_downloaded -= bytes_received;
            pthread_mutex_unlock(&global_progress.lock);
            
            if (retry_count < max_retries) {
                retry_count++;
                goto retry_transfer;
            }
            pthread_exit(NULL);
        }
        
        if (nbytes == 0) {
            if (bytes_received < bytes_expected) {
                fprintf(stderr, COLOR_RED "\n❌ Thread %d: Early EOF (got %ld/%ld)\n" COLOR_RESET,
                        t_arg->thread_id, bytes_received, bytes_expected);
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                ssh_disconnect(session);
                ssh_free(session);
                
                // Subtract bytes we thought we had from progress
                pthread_mutex_lock(&global_progress.lock);
                global_progress.bytes_downloaded -= bytes_received;
                pthread_mutex_unlock(&global_progress.lock);
                
                if (retry_count < max_retries) {
                    retry_count++;
                    goto retry_transfer;
                }
            }
            break;
        }
        
        pwrite(t_arg->output_fd, buffer, nbytes, current_offset);
        current_offset += nbytes;
        bytes_received += nbytes;
        
        pthread_mutex_lock(&global_progress.lock);
        global_progress.bytes_downloaded += nbytes;
        pthread_mutex_unlock(&global_progress.lock);
    }
    
    if (bytes_received == bytes_expected) {
        printf(COLOR_GREEN "\n✓ Thread %d: Complete (%ld bytes)\n" COLOR_RESET, t_arg->thread_id, bytes_received);
    }
    
    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    pthread_exit(NULL);
}

// Get file info from server
int get_file_info(const char* server_ip, const char* file_name, long* file_size, 
    unsigned char* server_hash) {
    ssh_session session = ssh_new();
    int port = PORT_NUM;
    ssh_options_set(session, SSH_OPTIONS_HOST, server_ip);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);

    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, COLOR_RED "✗ Error getting file info: %s\n" COLOR_RESET, 
                ssh_get_error(session));
        ssh_free(session);
        return -1;
    }

    if (ssh_userauth_password(session, "user", "pass") != SSH_AUTH_SUCCESS) {
        fprintf(stderr, COLOR_RED "✗ Auth failed\n" COLOR_RESET);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    ssh_channel channel = ssh_channel_new(session);
    ssh_channel_open_session(channel);

    char command[512];
    snprintf(command, sizeof(command), "INFO %s", file_name);
    ssh_channel_request_exec(channel, command);

    char buffer[512] = {0};
    ssh_channel_read(channel, buffer, sizeof(buffer), 0);

    if (strncmp(buffer, "ERROR", 5) == 0) {
        fprintf(stderr, COLOR_RED "\n✗ Server error: %s\n" COLOR_RESET, buffer);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        ssh_disconnect(session);
        ssh_free(session);
        return -1;
    }

    char hash_hex[EVP_MAX_MD_SIZE * 2 + 1] = {0};
    sscanf(buffer, "%ld %s", file_size, hash_hex);

    for (size_t i = 0; i < strlen(hash_hex) / 2; i++) {
        sscanf(hash_hex + 2 * i, "%2hhx", &server_hash[i]);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    return 0;
}

// List server files
void list_server_files(const char* server_ip) {
    ssh_session session = ssh_new();
    int port = PORT_NUM;
    ssh_options_set(session, SSH_OPTIONS_HOST, server_ip);
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    ssh_options_set(session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);
    
    if (ssh_connect(session) != SSH_OK) {
        fprintf(stderr, COLOR_RED "✗ Error connecting: %s\n" COLOR_RESET, ssh_get_error(session));
        ssh_free(session);
        return;
    }
    
    if (ssh_userauth_password(session, "user", "pass") != SSH_AUTH_SUCCESS) {
        fprintf(stderr, COLOR_RED "✗ Auth failed\n" COLOR_RESET);
        ssh_disconnect(session);
        ssh_free(session);
        return;
    }
    
    ssh_channel channel = ssh_channel_new(session);
    ssh_channel_open_session(channel);
    ssh_channel_request_exec(channel, "LIST");
    
    char buffer[16384] = {0};
    int total_read = 0;
    int nbytes;
    
    while ((nbytes = ssh_channel_read(channel, buffer + total_read, 
        sizeof(buffer) - total_read - 1, 0)) > 0) {
        total_read += nbytes;
    }
    
    printf(COLOR_GREEN "\n📁 Available files on server:\n" COLOR_RESET);
    printf("%s\n", buffer);
    
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
}

int main(int argc, char* argv[]) {
    char server_ip[256], file_path[256];
    int num_threads;

    // Check if arguments provided
    if (argc == 4) {
        // Use command line arguments
        strncpy(server_ip, argv[1], sizeof(server_ip) - 1);
        strncpy(file_path, argv[2], sizeof(file_path) - 1);
        num_threads = atoi(argv[3]);
        
        if (num_threads < 1) {
            fprintf(stderr, COLOR_RED "Invalid thread count!\n" COLOR_RESET);
            return -1;
        }
    } else if (argc == 1) {
        // Interactive mode - prompt for inputs
        printf(COLOR_CYAN "Enter server IP or domain: " COLOR_RESET);
        fflush(stdout);
        if (!fgets(server_ip, sizeof(server_ip), stdin)) return -1;
        server_ip[strcspn(server_ip, "\n")] = 0;

        printf(COLOR_CYAN "Enter absolute path of file on server: " COLOR_RESET);
        fflush(stdout);
        if (!fgets(file_path, sizeof(file_path), stdin)) return -1;
        file_path[strcspn(file_path, "\n")] = 0;

        printf(COLOR_CYAN "Enter number of threads: " COLOR_RESET);
        fflush(stdout);
        if (scanf("%d", &num_threads) != 1 || num_threads < 1) {
            fprintf(stderr, COLOR_RED "Invalid thread count!\n" COLOR_RESET);
            return -1;
        }
        getchar(); // eat trailing newline
    } else {
        // Wrong number of arguments
        fprintf(stderr, COLOR_YELLOW "Usage: %s [<server_ip> <file_path> <num_threads>]\n" COLOR_RESET, argv[0]);
        fprintf(stderr, "  Run without arguments for interactive mode\n");
        return -1;
    }

    // Create Downloads directory if needed
    struct stat st = {0};
    if (stat("Downloads", &st) == -1) {
        mkdir("Downloads", 0755);
    }

    long file_size = 0;
    unsigned char server_hash[EVP_MAX_MD_SIZE];
    printf(COLOR_BLUE "\nAsking server for info about '%s'...\n" COLOR_RESET, file_path);
    
    if (get_file_info(server_ip, file_path, &file_size, server_hash) != 0) {
        fprintf(stderr, COLOR_RED "✗ Could not get file info from server\n" COLOR_RESET);
        return -1;
    }

    printf(COLOR_GREEN "✓ File size: %ld bytes (%.2f MB)\n" COLOR_RESET, 
           file_size, file_size / (1024.0 * 1024.0));

    char *file_name_only = basename(file_path);
    char output_filename[512];
    snprintf(output_filename, sizeof(output_filename), "Downloads/%s", file_name_only);

    int output_fd = open(output_filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0) {
        perror(COLOR_RED "Failed to create output file" COLOR_RESET);
        return -1;
    }

    global_progress.total_bytes = file_size;
    global_progress.bytes_downloaded = 0;
    global_progress.start_time = time(NULL);
    global_progress.active = 1;

    pthread_t progress_thread;
    pthread_create(&progress_thread, NULL, progress_display, NULL);

    printf(COLOR_BLUE "\nStarting %d download threads...\n" COLOR_RESET, num_threads);
    pthread_t threads[num_threads];
    thread_arg args[num_threads];
    
    for (int i = 0; i < num_threads; i++) {
        args[i].thread_id = i;
        args[i].total_threads = num_threads;
        args[i].file_name = file_path;
        args[i].server_ip = server_ip;
        args[i].output_fd = output_fd;
        args[i].file_size = file_size;
        pthread_create(&threads[i], NULL, receive_file_segment, &args[i]);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }

    global_progress.active = 0;
    pthread_join(progress_thread, NULL);

    close(output_fd);
    printf(COLOR_GREEN "\n✓ Transfer complete: '%s'\n" COLOR_RESET, output_filename);

    printf(COLOR_BLUE "\n🔐 Verifying integrity...\n" COLOR_RESET);
    unsigned char client_hash[EVP_MAX_MD_SIZE];
    unsigned int client_hash_len = 0;
    calculate_hash(output_filename, client_hash, &client_hash_len);

    if (client_hash_len > 0 && memcmp(server_hash, client_hash, client_hash_len) == 0) {
        printf(COLOR_GREEN "\n✓ Hash verified!\n" COLOR_RESET);
    } else {
        printf(COLOR_RED "\n✗ Hash mismatch!\n" COLOR_RESET);
    }

    printf("\nServer:   ");
    for(int i=0; i < 32; i++) printf("%02x", server_hash[i]);
    printf("\nReceived: ");
    for(int i=0; i < client_hash_len; i++) printf("%02x", client_hash[i]);
    printf("\n");

    return 0;
}