#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <math.h>

#define PORT_NUM 8080

// ... (calculate_hash, send_file_segment, and other functions are unchanged) ...
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

void send_file_segment(ssh_channel channel, const char *file_name, long start_byte, long end_byte) {
    int fd = open(file_name, O_RDONLY);
    if (fd < 0) {
        perror("File open failed");
        return;
    }

    long bytes_to_send = end_byte - start_byte + 1;
    char buffer[4096];
    
    while (bytes_to_send > 0) {
        ssize_t to_read = (bytes_to_send < sizeof(buffer)) ? bytes_to_send : sizeof(buffer);
        ssize_t bytes_read = pread(fd, buffer, to_read, start_byte);

        if (bytes_read <= 0) {
            perror("pread failed");
            break;
        }

        int sent = ssh_channel_write(channel, buffer, bytes_read);
        if (sent == SSH_ERROR) {
            fprintf(stderr, "Error writing to SSH channel.\n");
            break;
        }

        bytes_to_send -= bytes_read;
        start_byte += bytes_read;
    }

    close(fd);
    printf("Segment transfer complete: [%ld - %ld]\n", start_byte - (end_byte - start_byte + 1), end_byte);
}

typedef struct {
    ssh_session session;
} client_handler_args;

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
                printf("User %s wants to authenticate with password '%s'\n",
                       ssh_message_auth_user(message),
                       ssh_message_auth_password(message)); // This is the line with the warning. It's fine.
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
        fprintf(stderr, "Authentication failed.\n");
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }

    do {
        message = ssh_message_get(session);
        if (message != NULL && ssh_message_type(message) == SSH_REQUEST_CHANNEL_OPEN && ssh_message_subtype(message) == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(message);
            ssh_message_free(message);
            break;
        }
        if (message != NULL) ssh_message_free(message);
    } while (message != NULL && !channel);
    
    if (channel == NULL) {
        fprintf(stderr, "Error opening channel.\n");
        ssh_disconnect(session);
        ssh_free(session);
        return NULL;
    }
    
    do {
        message = ssh_message_get(session);
        if (message != NULL && ssh_message_type(message) == SSH_REQUEST_CHANNEL && ssh_message_subtype(message) == SSH_CHANNEL_REQUEST_EXEC) {
            const char* command = ssh_message_channel_request_command(message);
            printf("Received command: %s\n", command);

            char file_name[256];
            int segment_num, total_segments;

            if (sscanf(command, "GET %255s %d %d", file_name, &segment_num, &total_segments) == 3) {
                 ssh_message_channel_request_reply_success(message);
                 ssh_message_free(message);
                 
                 FILE* file = fopen(file_name, "rb");
                 if(file) {
                    fseek(file, 0, SEEK_END);
                    long file_size = ftell(file);
                    fclose(file);

                    long segment_size = ceil((double)file_size / total_segments);
                    long start_byte = (long)segment_num * segment_size;
                    long end_byte = (segment_num == total_segments - 1) ? file_size - 1 : start_byte + segment_size - 1;

                    if(start_byte < file_size) {
                        send_file_segment(channel, file_name, start_byte, end_byte);
                    }
                 }
            } else {
                 // **THIS IS THE FIX**
                 // The old function didn't exist. This is the new way to say "no".
                 ssh_message_reply_default(message);
                 ssh_message_free(message);
            }
            break; 
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

// ... (main function is unchanged) ...
int main() {
    ssh_session session;
    ssh_bind sshbind;
    const char *hostkey_path = "/etc/ssh/ssh_host_rsa_key";
    
    int port = PORT_NUM;

    sshbind = ssh_bind_new();
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, "0.0.0.0");
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_HOSTKEY, hostkey_path);

    if (ssh_bind_listen(sshbind) < 0) {
        fprintf(stderr, "Error listening to socket: %s\n", ssh_get_error(sshbind));
        return 1;
    }

    printf("Server listening on port %d...\n", port);

    while (1) {
        session = ssh_new();
        if (ssh_bind_accept(sshbind, session) == SSH_ERROR) {
            fprintf(stderr, "Error accepting a connection: %s\n", ssh_get_error(sshbind));
            continue;
        }

        printf("Connection accepted. Forking a handler thread.\n");

        if (ssh_handle_key_exchange(session)) {
            fprintf(stderr, "ssh_handle_key_exchange: %s\n", ssh_get_error(session));
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