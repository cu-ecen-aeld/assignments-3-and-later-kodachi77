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
#include <sys/sendfile.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/epoll.h>

#include "aesdsocket.h"
#include "hashmap.h"
#include "thread_pool.h"

#define PORT 9000
#define BACKLOG 16
#define NET_BUFFER_SIZE 1024
#define MSG_BUFFER_SIZE 1024
#define FILE_PATH "/var/tmp/aesdsocketdata"
#define INVALID_TIMER (timer_t)(-1)
#define MAX_EVENTS 512

// BACKGROUND:
// Initially I implemented this assignment using threads. To make things simpler I used detached threads, because they are as good as joinable one.
// You just need to free resources correctly. This implementation was ok, but considering that we're here using single ever-increasing file
// (and both disk and network access is extremely slow) my guess was that if I used event loop (epoll in my case) I can get similar performance
// with a single threaded app. So I implemented it as a second option and got slightly better performance than in the threaded case.
// To test things - I also added thread pool and offloaded sending file contents over the wire (using sendfile) to threads.
// I create JMeter test to test these scenarios. See .jmx file and a performance comparison image.

//#define JMETER_LOAD_TEST 1

#define EPOLL_LOOP 1
// #define EPOLL_LOOP_MULTI_THREADED 1

#ifdef EPOLL_LOOP_MULTI_THREADED
#define EPOLL_LOOP 1
#endif

#ifndef EPOLL_LOOP
#define CLASSIC_MULTI_THREADED 1
#endif

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
FILE *file = NULL;
int daemon_mode = 0;
int child_process = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
timer_t timer_id = INVALID_TIMER;
volatile sig_atomic_t signal_received = 0;

#ifdef EPOLL_LOOP
struct hashmap *packets_map = NULL;
int epoll_fd = -1;
#endif

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

void handle_timer(union sigval sv)
{
    (void)sv;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[128];
    strftime(timestamp, sizeof(timestamp), "timestamp: %a, %d %b %Y %H:%M:%S %z\n", tm_info);

    pthread_mutex_lock(&file_mutex);
    write_data_to_file(timestamp);
    pthread_mutex_unlock(&file_mutex);
}

void *handle_client(void *arg)
{
    thread_info_t *thread_info = (thread_info_t *)arg;
    int client_sockfd = thread_info->client_sockfd;

    char buffer[NET_BUFFER_SIZE] = {0};
    int n;

    while ((n = recv(client_sockfd, buffer, NET_BUFFER_SIZE - 1, 0)) > 0)
    {
        buffer[n] = '\0';

#ifdef JMETER_LOAD_TEST
        if (strncmp(buffer, "RESET", 5) == 0)
        {
            int fd = fileno(file);
            if (fd < 0)
            {
                log_error("Failed to get file descriptor: %s", strerror(errno));
                goto thread_exit;
            }
            pthread_mutex_lock(&file_mutex);
            int ret = ftruncate(fd, 0);
            if (ret < 0)
            {
                log_error("Failed to truncate file: %s", strerror(errno));
            }
            pthread_mutex_unlock(&file_mutex);

            const char *response = "OK\n";
            if (send(client_sockfd, response, strlen(response), 0) == -1)
            {
                log_error("Failed to send response to client: %s", strerror(errno));
                goto thread_exit;
            }

            goto thread_exit;
        }
#endif

        {
            pthread_mutex_lock(&file_mutex);
            write_data_to_file(buffer);
            pthread_mutex_unlock(&file_mutex);
        }

        if (strchr(buffer, '\n'))
        {
            pthread_mutex_lock(&file_mutex);
            send_data_to_client(client_sockfd);
            pthread_mutex_unlock(&file_mutex);
	    goto thread_exit;
        }
    }

thread_exit:
    close(client_sockfd);

    free(thread_info);

    void *retval = NULL;
    pthread_exit(retval);

    return NULL;
}

// function resurns 0 on success, -1 on error, -2 if peer closed the connection, -3 on reset
// if it returns 0 - we had data, but no more data is coming, if >0 then more data is coming
int handle_client_non_blocking(client_data_t *data)
{
    int client_sockfd = data->client_sockfd;
    char buffer[NET_BUFFER_SIZE] = {0};
    ssize_t count;
    while (1)
    {
        count = read(client_sockfd, buffer, sizeof(buffer));
        if (count == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // If the socket is non-blocking and we would block, wait for it to be ready
                continue;
            }
            else
            {
                log_error("Failed to read data: %s", strerror(errno));
                return -1;
            }
        }
        else if (count == 0)
        {
            // Peer closed the connection
            return -2; // was 0
        }
        else
        {
#ifdef JMETER_LOAD_TEST
            if (strncmp(buffer, "RESET", 5) == 0)
            {
                int fd = fileno(file);
                if (fd < 0)
                {
                    log_error("Failed to get file descriptor: %s", strerror(errno));
                    return -1;
                }
                pthread_mutex_lock(&file_mutex);
                int ret = ftruncate(fd, 0);
                if (ret < 0)
                {
                    log_error("Failed to truncate file: %s", strerror(errno));
                }
                pthread_mutex_unlock(&file_mutex);

                const char *response = "OK\n";
                if (send(client_sockfd, response, strlen(response), 0) == -1)
                {
                    log_error("Failed to send response to client: %s", strerror(errno));
                    return -1;
                }

                return -3;
            }
#endif

            if (strchr(buffer, '\n'))
            {
                pthread_mutex_lock(&file_mutex);
                if (data->count)
                {
                    write_data_to_file(data->buffer);
                }
                write_data_to_file(buffer);

                pthread_mutex_unlock(&file_mutex);

#ifdef EPOLL_LOOP_MULTI_THREADED
                return 0;
#else
                return send_data_to_client_non_blocking(client_sockfd);
#endif
            }
            else
            {
                data->buffer = realloc(data->buffer, data->count + count);
                if (!data->buffer)
                {
                    log_error("Failed to allocate memory: %s", strerror(errno));
                    return -1;
                }
                memcpy(data->buffer + data->count, buffer, count);
                data->count += count;

                return count;
            }
        }
    }
    return -1;
}

void cleanup_resources()
{
    if (sockfd >= 0)
    {
        close(sockfd);
    }

    pthread_mutex_lock(&file_mutex);
    if (file)
    {
        fclose(file);
        file = NULL;
    }
    pthread_mutex_unlock(&file_mutex);

    pthread_mutex_destroy(&file_mutex);

    if (timer_id != INVALID_TIMER)
    {
        timer_delete(timer_id);
    }

    if (signal_received == SIGINT || signal_received == SIGTERM)
    {
        remove(FILE_PATH);
    }
}

int send_data_to_client(int client_sockfd)
{
    assert(client_sockfd >= 0);
    if (client_sockfd < 0)
        return -1;

    fseek(file, 0, SEEK_SET);

    char buffer[NET_BUFFER_SIZE];
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

int send_data_to_client_non_blocking(int client_sockfd)
{
    assert(client_sockfd >= 0);
    if (client_sockfd < 0)
        return -1;

    int file_fd = fileno(file);
    if (file_fd < 0)
    {
        log_error("Failed to get file descriptor: %s.", strerror(errno));
        return -1;
    }

    // Get the file size using fstat
    struct stat file_stat;
    if (fstat(file_fd, &file_stat) == -1)
    {
        log_error("Failed to get file status: %s", strerror(errno));
        return -1;
    }

    off_t offset = 0;
    int result = 0;

    while (offset < file_stat.st_size)
    {
        ssize_t sent = sendfile(client_sockfd, file_fd, &offset, file_stat.st_size);
        if (sent == -1)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                // If the socket is non-blocking and we would block, wait for it to be ready
                continue;
            }
            else
            {
                log_error("Failed to send file: %s", strerror(errno));
                result = -1;
                break;
            }
        }
    }

    return result;
}

// this function is not thread safe
void write_data_to_file(const char *buffer)
{
    assert(file && buffer);
    if (!file || !buffer)
        return;

    fputs(buffer, file);
    fflush(file);
}

int create_timer()
{
    struct sigevent sev;
    struct itimerspec its;

    // Set up the signal event to use a thread
    sev.sigev_notify = SIGEV_THREAD;          // Notify via a thread
    sev.sigev_value.sival_ptr = &timer_id;    // Can pass argument to thread function
    sev.sigev_notify_function = handle_timer; // Function to run when timer expires
    sev.sigev_notify_attributes = NULL;       // Use default thread attributes

    // Create the timer
    if (timer_create(CLOCK_REALTIME, &sev, &timer_id) == -1)
    {
        log_error("Failed to create timer: %s.", strerror(errno));
        return -1;
    }

    its.it_value.tv_sec = 10; // Initial expiration after 10 seconds
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10; // Timer interval of 10 second
    its.it_interval.tv_nsec = 0;

    // Start the timer
    if (timer_settime(timer_id, 0, &its, NULL) == -1)
    {
        log_error("Failed to start timer: %s.", strerror(errno));
        return -1;
    }

    return 0;
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

int create_file()
{
    assert(!file);
    if (file)
    {
        log_error("File is already opened");
        fclose(file);
        file = NULL;
        return -1;
    }

    file = fopen(FILE_PATH, "a+");
    if (!file)
    {
        log_error("Failed to open file: %s", strerror(errno));
        return -1;
    }

    return 0;
}

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

int make_socket_non_blocking(int sockfd)
{
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags < 0)
    {
        log_error("Failed to get client socket flags: %s", strerror(errno));
        return -1;
    }

    if (fcntl(sockfd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        log_error("Failed to set client socket to non-blocking: %s", strerror(errno));
        return -1;
    }
    return 0;
}

#ifdef EPOLL_LOOP

static size_t hash_fn(long key, void *ctx)
{
    (void)ctx;
    return key;
}
static bool equal_fn(long key1, long key2, void *ctx)
{
    (void)ctx;
    return key1 == key2;
}

static void unregister_client_data(client_data_t *data)
{
    int client_sockfd = data->client_sockfd;
    hashmap__delete(packets_map, client_sockfd, NULL, NULL);
    free(data->buffer);
    free(data);

    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client_sockfd, NULL);
    close(client_sockfd);
}

void handle_client_non_blocking_task(void *arg)
{
    client_data_t *data = (client_data_t *)arg;
    send_data_to_client_non_blocking(data->client_sockfd);
    unregister_client_data(data);
}

#endif

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

    if (create_file() < 0 || create_timer() < 0 || listen_socket() < 0)
    {
        EXIT();
    }

#if CLASSIC_MULTI_THREADED
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

#endif

#ifdef EPOLL_LOOP

#ifdef EPOLL_LOOP_MULTI_THREADED
    long num_cores = sysconf(_SC_NPROCESSORS_ONLN);

    if (num_cores == -1)
    {
        num_cores = 4;
    }
    threadpool thread_pool = thpool_init(num_cores);
    if (!thread_pool)
    {
        log_error("Failed to create thread pool.");
        EXIT();
    }
#endif

    packets_map = hashmap__new(hash_fn, equal_fn, NULL);
    if (!packets_map)
    {
        log_error("Failed to create hashmap.");
        EXIT();
    }

    epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
    {
        log_error("Failed to create epoll.");
        EXIT();
    }

    struct epoll_event event = {0}, events[MAX_EVENTS] = {0};
    event.events = EPOLLIN; // Watch for incoming connections or data
    event.data.fd = sockfd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sockfd, &event);

    // Event loop for handling incoming connections and data
    while (!signal_received)
    {
        int num_fds = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        for (int i = 0; i < num_fds; i++)
        {
            if (events[i].data.fd == sockfd)
            {
                // accept a new connection
                struct sockaddr_in client_addr;
                socklen_t client_len = sizeof(client_addr);
                int client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
                if (client_sockfd < 0)
                {
                    if (errno == EINTR && signal_received)
                    {
                        EXIT();
                    }
                    log_error("Failed to accept connection: %s", strerror(errno));
                    continue;
                }

                log_client_connection(&client_addr);

                if (make_socket_non_blocking(client_sockfd) < 0)
                {
                    close(client_sockfd);
                    continue;
                }

                // Add client socket to epoll monitoring
                event.events = EPOLLIN;
                event.data.fd = client_sockfd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_sockfd, &event);
            }
            else
            {
                if (events[i].events & EPOLLIN)
                {
                    client_data_t *data = NULL;
                    if (!hashmap__find(packets_map, events[i].data.fd, &data))
                    {
                        data = malloc(sizeof(client_data_t));
                        if (!data)
                        {
                            log_error("Failed to allocate memory: %s", strerror(errno));
                            continue;
                        }
                        data->client_sockfd = events[i].data.fd;
                        data->buffer = NULL;
                        data->count = 0;

                        hashmap__add(packets_map, events[i].data.fd, (void *)data);
                    }
                    // Handle data from existing clients
                    int ret = handle_client_non_blocking(data);
                    if (ret > 0)
                    {
                        // more data is coming
                    }
                    else if (ret == 0)
                    {
#ifndef EPOLL_LOOP_MULTI_THREADED
                        // no more data, in single threaded mode we can unregister client data here
                        unregister_client_data(data);
#endif
                    }
                    else if (ret < 0)
                    {
                        // error
                        unregister_client_data(data);
                    }
#ifdef EPOLL_LOOP_MULTI_THREADED
                    if (ret >= 0 && thpool_add_work(thread_pool, handle_client_non_blocking_task, (void *)data) != 0)
                    {
                        log_error("Failed to add task to a thread pool.");
                        continue;
                    }
#endif
                }

                if (events[i].events & (EPOLLERR | EPOLLHUP))
                {
                    client_data_t *data = NULL;
                    if (hashmap_find(packets_map, events[i].data.fd, (void *)data))
                    {
                        unregister_client_data(data);
                    }
                    else
                    {
                        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, events[i].data.fd, NULL);
                        close(events[i].data.fd);
                    }
                }
            }
        }
    }

    client_data_t *data;
    struct hashmap_entry *cur, *tmp;
    size_t bkt;

app_exit:
    if(epoll_fd >= 0)
    {
        close(epoll_fd);
    }

#ifdef EPOLL_LOOP_MULTI_THREADED
    if(thread_pool)
    {
        thpool_wait(thread_pool);
        thpool_destroy(thread_pool);
    }
#endif
    if(packets_map)
    {
        hashmap__for_each_entry_safe(packets_map, cur, tmp, bkt)
        {
            data = (client_data_t *)cur->pvalue;
            unregister_client_data(data);
        }
        hashmap__free(packets_map);
    }

    cleanup_resources();
    return signal_received ? -1 : 0;

#endif // EPOLL_LOOP
}
