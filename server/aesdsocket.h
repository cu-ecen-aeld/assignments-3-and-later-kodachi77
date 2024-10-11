#ifndef AESDSOCKET_H__
#define AESDSOCKET_H__

#include <sys/queue.h>
#include <stdbool.h>

typedef struct thread_info
{
    pthread_t thread_id;
    int client_sockfd;
    SLIST_ENTRY(thread_info)
    entries;
} thread_info_t;


typedef struct client_data
{
    int client_sockfd;
    char* buffer;
    ssize_t count;
} client_data_t;


int setup_signal_handlers();
int setup_syslog();
int setup_socket();

void log_error(const char *format, ...);
void log_signal(int signal);
void log_client_connection(struct sockaddr_in* client_addr);

int create_file();
int create_detached_thread();

void handle_signal(int signal);
void* handle_client(void *arg);

int listen_socket();

int send_data_to_client(int client_sockfd, bool need_fseek);

void write_data_to_file(const char* buffer);

int run_daemon();

void cleanup_resources();

#endif
