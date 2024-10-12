#ifndef AESDSOCKET_H__
#define AESDSOCKET_H__

#include <stdbool.h>

typedef struct thread_info
{
    pthread_t thread_id;
    int client_sockfd;
} thread_info_t;


typedef struct client_data
{
    int client_sockfd;
    char* buffer;
    ssize_t count;
} client_data_t;

typedef struct file_ref
{
    const char *filename;
    const char *mode;
    FILE *file;
    size_t ref_count;
    pthread_mutex_t mutex;
} file_ref_t;

void file_ref_init(file_ref_t* file_ref, const char *filename, const char *mode);
FILE* file_ref_acquire(file_ref_t *file_ref);
void file_ref_release(file_ref_t *file_ref);
void file_ref_destroy(file_ref_t *file_ref);


int setup_signal_handlers();
int setup_syslog();
int setup_socket();

void log_error(const char *format, ...);
void log_signal(int signal);
void log_client_connection(struct sockaddr_in* client_addr);

// int create_file();
int create_detached_thread();

void handle_signal(int signal);
void* handle_client(void *arg);
int handle_ioctl_command(FILE* file, const char *cmd_str);

int listen_socket();

int send_data_to_client(FILE* file, int client_sockfd, bool need_fseek);

void write_data_to_file(FILE* file, const char* buffer);

int run_daemon();

void cleanup_resources();

#endif
