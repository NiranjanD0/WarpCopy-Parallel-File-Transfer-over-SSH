#include <libssh/libssh.h>
#include <libssh/server.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>
#include <pthread.h>
#include <openssl/evp.h>
#include <dirent.h>
#include <time.h>

#define PORT_NUM 8080

// Hash calculation function
void calculate_hash(const char* file_name, unsigned char* hash_out, unsigned int* hash_len) {
    FILE* file = fopen(file_name, "rb");
    if (!file) {
        perror("File not found for hashing");
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

// ========== FIX #3: Improved send_file_segment with bounds checking ==========
void send_file_segment(ssh_channel channel, const char *file_name, long start_byte, long end_byte) {
    int fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        perror("File open failed");
        return;
    }

    struct stat st;
    fstat(fd, &st);
    long actual_file_size = st.st_size;
    
    if (end_byte >= actual_file_size) {
        end_byte = actual_file_size - 1;
    }

    long bytes_to_send = end_byte - start_byte + 1;
    char buffer[65536];
    
    if (lseek(fd, start_byte, SEEK_SET) < 0) {
        perror("lseek failed");
        close(fd);
        return;
    }

    printf("Sending segment [%ld - %ld] = %ld bytes\n", start_byte, end_byte, bytes_to_send);

    while (bytes_to_send > 0) {
        ssize_t to_read = (bytes_to_send < sizeof(buffer)) ? bytes_to_send : sizeof(buffer);
        ssize_t bytes_read = read(fd, buffer, to_read);
        
        if (bytes_read <= 0) {
            if (bytes_read < 0) perror("read failed");
            break;
        }

        int sent = ssh_channel_write(channel, buffer, bytes_read);
        if (sent == SSH_ERROR) {
            fprintf(stderr, "Error writing to SSH channel.\n");
            break;
        }

        bytes_to_send -= bytes_read;
    }

    // Give client time to receive all data before closing channel
    usleep(100000);  // 100ms delay - THIS IS THE FIX, no flush needed
    
    close(fd);
    printf("Segment transfer complete: [%ld - %ld]\n", start_byte, end_byte);
}


// Handle LIST command
void handle_list_command(ssh_channel channel) {
    DIR *dir = opendir(".");
    if (!dir) {
        const char *error_msg = "ERROR: Could not open directory\n";
        ssh_channel_write(channel, error_msg, strlen(error_msg));
        return;
    }
    
    struct dirent *entry;
    char response[16384] = "";
    
    snprintf(response, sizeof(response), 
             "%-50s %15s %20s\n", "Filename", "Size (bytes)", "Modified");
    strcat(response, "--------------------------------------------------------------------------------\n");
    
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            struct stat st;
            if (stat(entry->d_name, &st) == 0) {
                char line[512];
                char time_str[64];
                strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", 
                        localtime(&st.st_mtime));
                
                snprintf(line, sizeof(line), "%-50s %15ld %20s\n", 
                        entry->d_name, st.st_size, time_str);
                strcat(response, line);
            }
        }
    }
    closedir(dir);
    
    ssh_channel_write(channel, response, strlen(response));
}

// Client handler args
typedef struct {
    ssh_session session;
} client_handler_args;

// Handle client request thread
void* handle_client_request(void* args) {
    client_handler_args* thread_args = (client_handler_args*)args;
    ssh_session session = thread_args->session;
    ssh_channel channel = NULL;
    int auth = 0;

    ssh_message message;
    do {
        message = ssh_message_get(session);
        if (message && ssh_message_type(message) == SSH_REQUEST_AUTH) {
            if (ssh_message_subtype(message) == SSH_AUTH_METHOD_PASSWORD) {
                auth = 1;
                ssh_message_auth_reply_success(message, 0);
            } else {
                ssh_message_auth_set_methods(message, SSH_AUTH_METHOD_PASSWORD);
                ssh_message_reply_default(message);
            }
        } else if(message) {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    } while (message && !auth);

    if (!auth) {
        ssh_disconnect(session);
        ssh_free(session);
        free(thread_args);
        return NULL;
    }

    do {
        message = ssh_message_get(session);
        if (message != NULL && ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN && 
            ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        }
        if (message != NULL) ssh_message_free(message);
    } while (message != NULL && !channel);

    if (channel == NULL) {
        ssh_disconnect(session);
        ssh_free(session);
        free(thread_args);
        return NULL;
    }

    do {
        message = ssh_message_get(session);
        if (message != NULL && ssh_message_type(message) == SSH_REQUEST_CHANNEL && 
            ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_EXEC) {
            const char* command = ssh_message_channel_request_command(message);
            printf("Received command: %s\n", command);

            char file_name[512];
            
            if (strncmp(command, "LIST", 4) == 0) {
                ssh_message_channel_request_reply_success(message);
                ssh_message_free(message);
                handle_list_command(channel);
                break;
            } else if (strncmp(command, "GET ", 4) == 0) {
                int segment_num, total_segments;
                if (sscanf(command, "GET %511s %d %d", file_name, &segment_num, &total_segments) == 3) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);

                    FILE* file = fopen(file_name, "rb");
                    if(file) {
                        fseek(file, 0, SEEK_END);
                        long file_size = ftell(file);
                        fclose(file);

                        // ========== FIX #4: Match client's chunk calculation EXACTLY ==========
                        // OLD CODE: long segment_size = ceil((double)file_size / total_segments);
                        // PROBLEM: ceil() on server != division on client, misaligned chunks
                        
                        // NEW CODE: Same integer division logic as client
                        long chunk_size = file_size / total_segments;
                        long start_byte = (long)segment_num * chunk_size;
                        long end_byte;

                        // Last segment gets everything remaining (handles non-divisible file sizes)
                        if (segment_num == total_segments - 1) {
                            end_byte = file_size - 1;
                        } else {
                            end_byte = start_byte + chunk_size - 1;
                        }

                        printf("Thread %d requesting: [%ld - %ld] = %ld bytes\n", 
                               segment_num, start_byte, end_byte, end_byte - start_byte + 1);

                        if(start_byte < file_size) {
                            send_file_segment(channel, file_name, start_byte, end_byte);
                        }
                    } else {
                        const char* error_msg = "ERROR: File not found\n";
                        ssh_channel_write(channel, error_msg, strlen(error_msg));
                    }
                    break;
                }
            } else if (strncmp(command, "INFO ", 5) == 0) {
                if (sscanf(command, "INFO %511s", file_name) == 1) {
                    ssh_message_channel_request_reply_success(message);
                    ssh_message_free(message);

                    FILE* file = fopen(file_name, "rb");
                    if (file) {
                        fseek(file, 0, SEEK_END);
                        long file_size = ftell(file);
                        fclose(file);

                        unsigned char file_hash[EVP_MAX_MD_SIZE];
                        unsigned int hash_len = 0;
                        calculate_hash(file_name, file_hash, &hash_len);

                        char response[512];
                        snprintf(response, sizeof(response), "%ld ", file_size);
                        for(unsigned int i=0; i<hash_len; i++) {
                            sprintf(response + strlen(response), "%02x", file_hash[i]);
                        }
                        strcat(response, "\n");
                        ssh_channel_write(channel, response, strlen(response));
                    } else {
                        const char *error_msg = "ERROR: File not found\n";
                        ssh_channel_write(channel, error_msg, strlen(error_msg));
                    }
                    break;
                }
            }
        }
        if (message != NULL) ssh_message_free(message);
    } while (message != NULL);

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    ssh_disconnect(session);
    ssh_free(session);
    free(thread_args);
    return NULL;
}

int main() {
    ssh_bind sshbind;
    ssh_session session;

    ssh_init();
    sshbind = ssh_bind_new();

    int port = PORT_NUM;
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, "/etc/ssh/ssh_host_rsa_key");

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    printf("Server listening on port %d...\n", PORT_NUM);

    while (1) {
        session = ssh_new();
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting connection: %s\n", ssh_get_error(sshbind));
            ssh_free(session);
            continue;
        }

        if (ssh_handle_key_exchange(session) != SSH_OK) {
            fprintf(stderr, "Key exchange error: %s\n", ssh_get_error(session));
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        pthread_t client_thread;
        client_handler_args* args = malloc(sizeof(client_handler_args));
        args->session = session;

        if (pthread_create(&client_thread, NULL, handle_client_request, args) != 0) {
            perror("Failed to create thread");
            ssh_disconnect(session);
            ssh_free(session);
            free(args);
        }

        pthread_detach(client_thread);
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    return 0;
}
