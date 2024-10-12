#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <execinfo.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "aesdsocket.h"
#include "../aesd-char-driver/aesd_ioctl.h"

#define USE_AESD_CHAR_DEVICE 1

#define PORT 9000
#define BACKLOG 16
#define NET_BUFFER_SIZE 2048
#define MSG_BUFFER_SIZE 2048

#if USE_AESD_CHAR_DEVICE
#define FILE_PATH "/dev/aesdchar"
#else
#define FILE_PATH "/var/tmp/aesdsocketdata"
#endif

// BACKGROUND:
// 3 different threading implementations are now located in aesdcoket_multi.c. They are:
// - classic threaded
// - epoll single-treaded
// - epoll with a thread pool
// For this assignment we will use classic threaded implementation.
// Due to limitiations of the unit tests for the assignment we will have to open and close 
// the file on-demand (for each client connection). In order to help with that we will introduce
// a file reference counter. The file will be opened only once and closed when the reference counter
// reaches 0.

#define EXIT()         \
    do                 \
    {                  \
        goto app_exit; \
    } while (0)
#define LOG_ERROR_AND_EXIT(...) \
    do                          \
    {                           \
        log_error(__VA_ARGS__); \
        exit_code = -1;         \
        goto app_exit;          \
    } while (0)

// Global variables
int sockfd = -1;
file_ref_t file_ref = {0};
int daemon_mode = 0;
int child_process = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
volatile sig_atomic_t signal_received = 0;

void file_ref_init(file_ref_t* file_ref, const char *filename, const char *mode)
{
    //assert(pthread_equal(pthread_self(), main_thread_id)); 

    file_ref->filename = strdup(filename);
    file_ref->mode = strdup(mode);
    file_ref->file = NULL;
    file_ref->ref_count = 0;
    pthread_mutex_init(&file_ref->mutex, NULL);
}

FILE* file_ref_acquire(file_ref_t *file_ref)
{
    pthread_mutex_lock(&file_ref->mutex);
    if (file_ref->ref_count == 0)
    {
        file_ref->file = fopen(file_ref->filename, file_ref->mode);
        if (!file_ref->file)
        {
            log_error("Failed to open file: %s", file_ref->filename);
            pthread_mutex_unlock(&file_ref->mutex);
            return NULL;
        }
    }
    file_ref->ref_count++;
    pthread_mutex_unlock(&file_ref->mutex);
    return file_ref->file;
}

void file_ref_release(file_ref_t *file_ref)
{
    pthread_mutex_lock(&file_ref->mutex);
    if (file_ref->file == NULL)
    {
        pthread_mutex_unlock(&file_ref->mutex);
        return;
    }

    if (--file_ref->ref_count == 0)
    {
        fclose(file_ref->file);
        file_ref->file = NULL;
    }
    pthread_mutex_unlock(&file_ref->mutex);
}

void file_ref_destroy(file_ref_t *file_ref)
{
    //assert(pthread_equal(pthread_self(), main_thread_id)); 

    pthread_mutex_lock(&file_ref->mutex);
    if (file_ref->file != NULL)
    {
        fclose(file_ref->file);
        file_ref->file = NULL;
    }
    pthread_mutex_unlock(&file_ref->mutex);
    pthread_mutex_destroy(&file_ref->mutex);
    free((void*)file_ref->filename);
    free((void*)file_ref->mode);
}

static inline int is_daemon()
{
    return daemon_mode && child_process ? 1 : 0;
}

void log_error(const char *format, ...)
{
    va_list args;
    char buffer[MSG_BUFFER_SIZE + 7];

    // Start processing the arguments
    va_start(args, format);

    strcpy(buffer, "Error: ");

    // Format the error message into the buffer
    vsnprintf(buffer + 7, MSG_BUFFER_SIZE, format, args);

    // Log the error to syslog
    syslog(LOG_ERR, "%s", buffer);

    // We only want to print to stderr if it is not a daemon.
    if (!is_daemon())
    {
        fprintf(stderr, "%s. Exiting.\n", buffer);
    }

    // Clean up the argument list
    va_end(args);
}

void log_signal(int signal)
{
    if (signal)
    {
        const char *sig_str = strsignal(signal);

        char buffer[MSG_BUFFER_SIZE] = {0};
        snprintf(buffer, MSG_BUFFER_SIZE, "Caught signal '%s', exiting.", sig_str);
        syslog(LOG_INFO, "%s", buffer);

        if (!is_daemon())
        {
            fprintf(stderr, "%s\n", buffer);
        }
    }
}

void log_client_connection(struct sockaddr_in *client_addr)
{
    char client_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &client_addr->sin_addr, client_ip, INET_ADDRSTRLEN);
    char buffer[MSG_BUFFER_SIZE] = {0};
    snprintf(buffer, MSG_BUFFER_SIZE, "Accepted connection from %s", client_ip);
    syslog(LOG_INFO, "%s", buffer);

    if (!is_daemon())
    {
        fprintf(stdout, "%s\n", buffer);
    }
}

void handle_signal(int signal)
{
    if (signal == SIGSEGV)
    {
        void *array[16];
        size_t size;

        // get void*'s for all entries on the stack
        size = backtrace(array, 16);

        // print out all the frames to stderr
        backtrace_symbols_fd(array, size, STDERR_FILENO);
        exit(1);
    }
    if (signal == SIGINT || signal == SIGTERM)
    {
        signal_received = signal;
    }
}

int handle_ioctl_command(FILE* file, const char *cmd_str)
{
    if (!file || !cmd_str)
        return -1;

    int retval = -1;

    int fd = fileno(file);
    if(fd < 0) {
        log_error("Failed to get file descriptor: %s", strerror(errno));
        goto ioctl_exit;
    }

    struct aesd_seekto seekto;
    if (sscanf(cmd_str, "AESDCHAR_IOCSEEKTO:%u,%u", &seekto.write_cmd, &seekto.write_cmd_offset) == 2)
    {
        if (ioctl(fd, AESDCHAR_IOCSEEKTO, &seekto) != 0)
        {
            log_error("ioctl AESDCHAR_IOCSEEKTO failed: %s", strerror(errno));
            goto ioctl_exit;
        }
        retval = 0;
    }
ioctl_exit:
    return retval;
}

void *handle_client(void *arg)
{
    thread_info_t *thread_info = (thread_info_t *)arg;
    int client_sockfd = thread_info->client_sockfd;

    char* cmd_buffer = NULL;
    size_t cmd_buffer_size = 0;
    char buffer[NET_BUFFER_SIZE] = {0};
    int n;

    while ((n = recv(client_sockfd, buffer, NET_BUFFER_SIZE - 1, 0)) > 0)
    {
        buffer[n] = '\0';

        cmd_buffer = realloc(cmd_buffer, cmd_buffer_size + n + 1);
        if (!cmd_buffer)
        {
            log_error("Failed to allocate memory for command buffer.");
            goto thread_exit;
        }
        strncpy(cmd_buffer + cmd_buffer_size, buffer, n + 1);
        cmd_buffer_size += n;

        if (strchr(buffer, '\n'))
        {
            FILE* file = file_ref_acquire(&file_ref);
            if(!file) {
                log_error("Failed to acquire file reference.");
                goto thread_exit;
            }
#if USE_AESD_CHAR_DEVICE
            if (strncmp(cmd_buffer, "AESDCHAR_IOCSEEKTO:", 19) == 0)
            {
                if (handle_ioctl_command(file, cmd_buffer) == 0)
                {
                    send_data_to_client(file, client_sockfd, false);
                    goto thread_exit;
                }
                else
                {
                    log_error("Invalid ioctl command: %s", buffer);
                    goto thread_exit;
                }
            }
#endif       
            // since we're using fputs that is buffered we need to lock the file mutex
            pthread_mutex_lock(&file_mutex);
            write_data_to_file(file, buffer);
            send_data_to_client(file, client_sockfd, true);
	        pthread_mutex_unlock(&file_mutex);
            goto thread_exit;
        }
    }

thread_exit:
    free(cmd_buffer);

    close(client_sockfd);

    file_ref_release(&file_ref);

    free(thread_info);

    void *retval = NULL;
    pthread_exit(retval);
    return retval;
}

void cleanup_resources()
{
    if (sockfd >= 0)
    {
        close(sockfd);
    }

    file_ref_destroy(&file_ref);

    pthread_mutex_destroy(&file_mutex);

#if !USE_AESD_CHAR_DEVICE    
    if (signal_received == SIGINT || signal_received == SIGTERM)
    {
        remove(FILE_PATH);
    }
#endif
}

int send_data_to_client(FILE* file, int client_sockfd, bool need_fseek)
{
    assert(file && client_sockfd >= 0);
    if (!file || client_sockfd < 0)
        return -1;

    if(need_fseek)
        fseek(file, 0, SEEK_SET);

    char buffer[NET_BUFFER_SIZE] = {0};
    int result = 0;

    while (fgets(buffer, NET_BUFFER_SIZE, file) != NULL) 
    {
        size_t line_length = strlen(buffer);
        size_t total_sent = 0;
        while (total_sent < line_length)
        {
            ssize_t sent = send(client_sockfd, buffer + total_sent, line_length - total_sent, 0);
            if (sent < 0)
            {
                log_error("Failed to send data: %s.", strerror(errno));
                result = -1;
                break;
            }
            total_sent += sent;
        }

        if (total_sent < line_length)
        {
            log_error("Failed to send complete file.");
            result = -1;
            break;
        }
    }


    fseek(file, 0, SEEK_END);

    return result;
}

// this function is not thread safe
void write_data_to_file(FILE* file, const char *buffer)
{
    assert(file && buffer);
    if (!file || !buffer)
        return;

    fputs(buffer, file);
    fflush(file); 
}

int run_daemon()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        log_error("Daemon start (fork) failed: %s", strerror(errno));
        return -1;
    }

    if (pid > 0)
    {
        exit(0); // Parent process exits
    }

    child_process = 1;

    if (setsid() < 0)
    {
        log_error("Daemon start (setsid) failed: %s", strerror(errno));
        return -1;
    }

    umask(0);

    pid_t sid = chdir("/");
    if (sid < 0)
    {
        log_error("Daemon start (chdir) failed: %s", strerror(errno));
        return -1;
    }

    int dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd == -1)
    {
        log_error("Failed to open /dev/null: %s", strerror(errno));
        return -1;
    }

    if (dup2(dev_null_fd, STDIN_FILENO) == -1)
    {
        log_error("Failed to redirect stdin to /dev/null: %s", strerror(errno));
        close(dev_null_fd);
        return -1;
    }

    if (dup2(dev_null_fd, STDOUT_FILENO) == -1)
    {
        log_error("Failed to redirect stdout to /dev/null: %s", strerror(errno));
        close(dev_null_fd);
        return -1;
    }

    if (dup2(dev_null_fd, STDERR_FILENO) == -1)
    {
        log_error("Failed to redirect stderr to /dev/null: %s", strerror(errno));
        close(dev_null_fd);
        return -1;
    }

    close(dev_null_fd);

    return 0;
}

int setup_signal_handlers()
{
    struct sigaction sa = {0};
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    int result = sigaction(SIGINT, &sa, NULL);
    result |= sigaction(SIGTERM, &sa, NULL);
    result |= sigaction(SIGSEGV, &sa, NULL);
    if (result != 0)
    {
        log_error("Failed to setup signal handlers: %s", strerror(errno));
        return -1;
    }

    return 0;
}

int setup_syslog()
{
    openlog("aesdsocket", LOG_PID | LOG_CONS, daemon_mode ? LOG_DAEMON : LOG_USER);
    atexit(&closelog);
    return 0;
}

int setup_socket()
{
    assert(sockfd < 0);
    if (sockfd >= 0)
    {
        log_error("Socket already opened");
        return -1;
    }

    int _sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (_sockfd < 0)
    {
        log_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    const int enable = 1;
    if (setsockopt(_sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        log_error("Failed to set SO_REUSEADDR socket option: %s", strerror(errno));
        close(_sockfd);
        return -1;
    }

    // bind
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);
    if (bind(_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        log_error("Failed to bind socket: %s", strerror(errno));
        close(_sockfd);
        return -1;
    }

    sockfd = _sockfd;
    return 0;
}

// int create_file()
// {
//     if (!file) {
//         file = fopen(FILE_PATH, "a+");
//         if (!file) {
//             log_error("Failed to open file: %s", strerror(errno));
//             return -1;
//         }
//     }

//     return 0;
// }

int create_detached_thread(int client_sockfd)
{
    thread_info_t *thread_info = malloc(sizeof(thread_info_t));
    if (!thread_info)
    {
        log_error("Failed to allocate memory: %s", strerror(errno));
        return -1;
    }

    thread_info->client_sockfd = client_sockfd;
    if (pthread_create(&thread_info->thread_id, NULL, handle_client, thread_info) != 0)
    {
        log_error("Failed to create thread: %s", strerror(errno));
        free(thread_info);
        return -1;
    }
    else
    {
        pthread_detach(thread_info->thread_id);
    }
    return 0;
}

int listen_socket()
{
    assert(sockfd >= 0);
    if (sockfd < 0)
    {
        log_error("Server socket is not valid.");
        return -1;
    }
    if (listen(sockfd, BACKLOG) < 0)
    {
        log_error("Failed to listen on socket: %s", strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        daemon_mode = 1;
    }

    int ret = setup_signal_handlers();
    ret |= setup_syslog();
    ret |= setup_socket();
    if (ret < 0)
    {
        EXIT();
    }

    if (daemon_mode && run_daemon() < 0)
    {
        EXIT();
    }

    file_ref_init(&file_ref, FILE_PATH, "a+");

    if (listen_socket() < 0)
    {
        EXIT();
    }

    while (!signal_received)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd < 0)
        {
            if (errno == EINTR && signal_received)
            {
                break;
            }
            log_error("Failed to accept connection: %s", strerror(errno));
            continue;
        }

        log_client_connection(&client_addr);

        if (create_detached_thread(client_sockfd) < 0)
        {
            close(client_sockfd);
            continue;
        }
    }
app_exit:

    cleanup_resources();
    return signal_received ? -1 : 0;
}
