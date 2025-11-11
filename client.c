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

// ========== NEW: Shared session structure ==========
typedef struct {
    ssh_session session;
    pthread_mutex_t session_lock;  // protect session during channel creation
} shared_session_t;

shared_session_t* global_session = NULL;

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

// ========== NEW: Single session, multi-channel thread function with retry ==========
void* receive_file_segment(void* arg) {
    thread_arg* t_arg = (thread_arg*)arg;
    ssh_channel channel = NULL;
    int rc;
    
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
    
    // ========== RETRY LOGIC ==========
    int max_retries = 3;
    int retry_count = 0;
    
retry_transfer:
    if (retry_count > 0) {
        fprintf(stderr, COLOR_YELLOW "\n🔄 Thread %d: Retry attempt %d/%d (already got %ld/%ld bytes)\n" COLOR_RESET,
                t_arg->thread_id, retry_count, max_retries, bytes_received, bytes_expected);
        sleep(2);  // wait before retry
    }
    
    // Create a new channel on the shared session
    pthread_mutex_lock(&global_session->session_lock);
    channel = ssh_channel_new(global_session->session);
    if (!channel) {
        pthread_mutex_unlock(&global_session->session_lock);
        fprintf(stderr, COLOR_RED "Thread %d: Failed to create channel\n" COLOR_RESET, t_arg->thread_id);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }
    
    rc = ssh_channel_open_session(channel);
    pthread_mutex_unlock(&global_session->session_lock);
    
    if (rc != SSH_OK) {
        fprintf(stderr, COLOR_RED "Thread %d: Failed to open channel session\n" COLOR_RESET, t_arg->thread_id);
        ssh_channel_free(channel);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }

    // Send GET command
    char command[512];
    snprintf(command, sizeof(command), "GET %s %d %d", t_arg->file_name, 
             t_arg->thread_id, t_arg->total_threads);
    
    rc = ssh_channel_request_exec(channel, command);
    if (rc != SSH_OK) {
        fprintf(stderr, COLOR_RED "Thread %d: Failed to execute command\n" COLOR_RESET, t_arg->thread_id);
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        
        if (retry_count < max_retries) {
            retry_count++;
            goto retry_transfer;
        }
        pthread_exit(NULL);
    }

    // ========== ROBUST READ LOOP ==========
    while (bytes_received < bytes_expected) {
        long remaining = bytes_expected - bytes_received;
        size_t to_request = (remaining < sizeof(buffer)) ? remaining : sizeof(buffer);
        
        nbytes = ssh_channel_read(channel, buffer, to_request, 0);
        
        // Handle errors
        if (nbytes < 0) {
            fprintf(stderr, COLOR_RED "\n❌ Thread %d: Read error: %s\n" COLOR_RESET, 
                    t_arg->thread_id, ssh_get_error(global_session->session));
            
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            
            if (retry_count < max_retries) {
                retry_count++;
                goto retry_transfer;
            } else {
                fprintf(stderr, COLOR_RED "Thread %d: Max retries exceeded\n" COLOR_RESET, t_arg->thread_id);
                pthread_exit(NULL);
            }
        }
        
        // Handle EOF
        if (nbytes == 0) {
            if (bytes_received < bytes_expected) {
                fprintf(stderr, COLOR_RED "\n❌ Thread %d: Channel closed early! Got %ld/%ld bytes\n" COLOR_RESET,
                        t_arg->thread_id, bytes_received, bytes_expected);
                
                ssh_channel_close(channel);
                ssh_channel_free(channel);
                
                if (retry_count < max_retries) {
                    retry_count++;
                    goto retry_transfer;
                } else {
                    fprintf(stderr, COLOR_RED "Thread %d: Max retries exceeded\n" COLOR_RESET, t_arg->thread_id);
                    pthread_exit(NULL);
                }
            }
            break;
        }
        
        // Write received data
        pwrite(t_arg->output_fd, buffer, nbytes, current_offset);
        current_offset += nbytes;
        bytes_received += nbytes;
        
        // Update progress
        pthread_mutex_lock(&global_progress.lock);
        global_progress.bytes_downloaded += nbytes;
        pthread_mutex_unlock(&global_progress.lock);
    }

    // Verify completion
    if (bytes_received == bytes_expected) {
        printf(COLOR_GREEN "\n✓ Thread %d: Successfully received %ld bytes [%ld - %ld]\n" COLOR_RESET,
               t_arg->thread_id, bytes_received, start_byte, end_byte);
    } else {
        fprintf(stderr, COLOR_YELLOW "\n⚠ Thread %d: Incomplete - expected %ld, got %ld bytes (%.1f%%)\n" COLOR_RESET,
                t_arg->thread_id, bytes_expected, bytes_received, 
                (bytes_received * 100.0) / bytes_expected);
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    pthread_exit(NULL);
}

// ========== MODIFIED: Get file info (uses separate session) ==========
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
        fprintf(stderr, COLOR_RED "✗ Auth failed for info check: %s\n" COLOR_RESET, 
                ssh_get_error(session));
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
        fprintf(stderr, COLOR_RED "✗ Server error: %s\n" COLOR_RESET, buffer);
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
        fprintf(stderr, COLOR_RED "✗ Error connecting: %s\n" COLOR_RESET, 
                ssh_get_error(session));
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

// ========== MODIFIED MAIN: Create single session, spawn threads with channels ==========
int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip> [--list | <file_path> <num_threads>]\n", argv[0]);
        fprintf(stderr, "Examples:\n");
        fprintf(stderr, "  %s 192.168.1.100 --list\n", argv[0]);
        fprintf(stderr, "  %s 192.168.1.100 /path/to/file.zip 8\n", argv[0]);
        return -1;
    }
    
    char* server_ip = argv[1];
    
    // Handle list command
    if (argc == 3 && strcmp(argv[2], "--list") == 0) {
        list_server_files(server_ip);
        return 0;
    }
    
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <server_ip> <file_path> <num_threads>\n", argv[0]);
        fprintf(stderr, "   or: %s <server_ip> --list\n", argv[0]);
        return -1;
    }
    
    char* file_path = argv[2];
    int num_threads = atoi(argv[3]);
    
    // Create Downloads directory
    struct stat st = {0};
    if (stat("Downloads", &st) == -1) {
        mkdir("Downloads", 0755);
        printf(COLOR_BLUE "📂 Created Downloads directory\n" COLOR_RESET);
    }
    
    char *file_name_only = basename(file_path);
    
    // Step 1: Get file info
    long file_size = 0;
    unsigned char server_hash[EVP_MAX_MD_SIZE];
    printf(COLOR_BLUE "🔍 Asking server for info about '%s'...\n" COLOR_RESET, file_path);
    
    if (get_file_info(server_ip, file_path, &file_size, server_hash) != 0) {
        fprintf(stderr, COLOR_RED "✗ Could not get file info from server\n" COLOR_RESET);
        return -1;
    }
    
    printf(COLOR_GREEN "✓ Server says file size is %ld bytes (%.2f MB)\n" COLOR_RESET, 
           file_size, file_size / (1024.0 * 1024.0));
    
    // Step 2: Prepare output file
    char output_file_path[512];
    snprintf(output_file_path, sizeof(output_file_path), "Downloads/%s", file_name_only);
    
    int output_fd = open(output_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0) {
        perror(COLOR_RED "✗ Failed to create output file" COLOR_RESET);
        return -1;
    }
    
    // ========== NEW: Create single shared SSH session ==========
    printf(COLOR_BLUE "🔐 Establishing SSH session to %s...\n" COLOR_RESET, server_ip);
    
    global_session = malloc(sizeof(shared_session_t));
    global_session->session = ssh_new();
    pthread_mutex_init(&global_session->session_lock, NULL);
    
    int port = PORT_NUM;
    ssh_options_set(global_session->session, SSH_OPTIONS_HOST, server_ip);
    ssh_options_set(global_session->session, SSH_OPTIONS_PORT, &port);
    ssh_options_set(global_session->session, SSH_OPTIONS_HOSTKEYS, "rsa-sha2-512,rsa-sha2-256,ssh-rsa");
    ssh_options_set(global_session->session, SSH_OPTIONS_STRICTHOSTKEYCHECK, 0);
    
    // Increase timeouts for stability
    long timeout = 300;  // 5 minutes
    ssh_options_set(global_session->session, SSH_OPTIONS_TIMEOUT, &timeout);
    
    if (ssh_connect(global_session->session) != SSH_OK) {
        fprintf(stderr, COLOR_RED "✗ Connection failed: %s\n" COLOR_RESET, 
                ssh_get_error(global_session->session));
        ssh_free(global_session->session);
        free(global_session);
        close(output_fd);
        return -1;
    }
    
    if (ssh_userauth_password(global_session->session, "user", "pass") != SSH_AUTH_SUCCESS) {
        fprintf(stderr, COLOR_RED "✗ Authentication failed\n" COLOR_RESET);
        ssh_disconnect(global_session->session);
        ssh_free(global_session->session);
        free(global_session);
        close(output_fd);
        return -1;
    }
    
    printf(COLOR_GREEN "✓ SSH session established\n" COLOR_RESET);
    
    // Initialize progress tracking
    global_progress.total_bytes = file_size;
    global_progress.bytes_downloaded = 0;
    global_progress.start_time = time(NULL);
    global_progress.active = 1;
    
    // Start progress display thread
    pthread_t progress_thread;
    pthread_create(&progress_thread, NULL, progress_display, NULL);
    
    // Step 3: Spawn download threads (all use same session, different channels)
    printf(COLOR_BLUE "🚀 Spawning %d download threads on single SSH session...\n" COLOR_RESET, num_threads);
    pthread_t threads[num_threads];
    thread_arg args[num_threads];
    
    for (int i = 0; i < num_threads; i++) {
        args[i].thread_id = i;
        args[i].total_threads = num_threads;
        args[i].file_name = file_path;
        args[i].output_fd = output_fd;
        args[i].file_size = file_size;
        pthread_create(&threads[i], NULL, receive_file_segment, &args[i]);
    }
    
    for (int i = 0; i < num_threads; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // Stop progress display
    global_progress.active = 0;
    pthread_join(progress_thread, NULL);
    
    close(output_fd);
    
    // Cleanup SSH session
    ssh_disconnect(global_session->session);
    ssh_free(global_session->session);
    pthread_mutex_destroy(&global_session->session_lock);
    free(global_session);
    
    printf(COLOR_GREEN "\n✓ File transfer complete. Saved to '%s'\n" COLOR_RESET, output_file_path);
    
    // Step 4: Verify hash
    printf(COLOR_BLUE "🔐 Verifying file integrity...\n" COLOR_RESET);
    unsigned char client_hash[EVP_MAX_MD_SIZE];
    unsigned int client_hash_len = 0;
    calculate_hash(output_file_path, client_hash, &client_hash_len);
    
    if (client_hash_len > 0 && memcmp(server_hash, client_hash, client_hash_len) == 0) {
        printf(COLOR_GREEN "✓ File integrity verified: Hashes match!\n" COLOR_RESET);
    } else {
        printf(COLOR_RED "✗ File integrity compromised: Hash mismatch!\n" COLOR_RESET);
    }
    
    printf("\nServer Hash:   ");
    for(int i=0; i < 32; i++) printf("%02x", server_hash[i]);
    printf("\nReceived Hash: ");
    for(int i=0; i < client_hash_len; i++) printf("%02x", client_hash[i]);
    printf("\n");
    
    return 0;
}

