#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include <sys/queue.h>
#include <pthread.h>

#include "aesdsocket.h"

#define PORT 9000
#define BACKLOG 16
#define NET_BUFFER_SIZE 1024
#define MSG_BUFFER_SIZE 1024
#define FILE_PATH "/var/tmp/aesdsocketdata"

// Global variables
int sockfd = -1;
int client_sockfd = -1;
FILE *file = NULL;
int daemon_mode = 0;
int child_process = 0;
pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
timer_t timer_id = (timer_t)(-1);

typedef struct thread_info
{
    pthread_t thread_id;
    int client_sockfd;
    int done;
    SLIST_ENTRY(thread_info)
    entries;
} thread_info_t;

// SLIST_HEAD(thread_list, thread_info)
// head; // = SLIST_HEAD_INITIALIZER(head);

int is_daemon()
{
    return daemon_mode && child_process ? 1 : 0;
}

void report_error(const char *format, ...)
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

void signal_handler(int signal)
{
    if (signal != SIGINT && signal != SIGTERM)
        return;

    const char *sig_str = strsignal(signal);

    char buffer[MSG_BUFFER_SIZE] = {0};
    snprintf(buffer, MSG_BUFFER_SIZE, "Caught signal '%s', exiting.", sig_str);
    syslog(LOG_INFO, "%s", buffer);

    if (!is_daemon())
    {
        fprintf(stderr, "%s\n", buffer);
    }

    // Close all client connections and join threads
    // thread_info_t *item;
    // while (!SLIST_EMPTY(&head))
    // {
    //     item = SLIST_FIRST(&head);
    //     pthread_join(item->thread_id, NULL);
    //     assert (item->client_sockfd < 0);

    //     SLIST_REMOVE_HEAD(&head, entries); 
    //     free(item);
    // }

    if (sockfd >= 0)
    {
        close(sockfd);
    }

    pthread_mutex_destroy(&file_mutex);

    if (file)
    {
        fclose(file);
    }

    if (timer_id != (timer_t)(-1))
    {
        timer_delete(timer_id);
    }

    if (signal == SIGINT || signal == SIGTERM)
    {
        remove(FILE_PATH);
    }

    exit(0);
}

void setup_signal_handlers()
{
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));

    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

// this function is not thread-safe!!!
int send_data_to_client(int client_sockfd)
{
    assert(client_sockfd >= 0);
    if (client_sockfd < 0)
        return -1;

    fseek(file, 0, SEEK_SET);

    char buffer[NET_BUFFER_SIZE];
    //size_t bytes_read;

    int result = 0;

    while (fgets(buffer, NET_BUFFER_SIZE, file) != NULL)
    {
        // Check if the line starts with "timestamp"
        if (strncmp(buffer, "timestamp", 9) == 0)
        {
            continue; // Skip this line
        }

        size_t line_length = strlen(buffer);
        size_t total_sent = 0;
        while (total_sent < line_length)
        {
            ssize_t sent = send(client_sockfd, buffer + total_sent, line_length - total_sent, 0);
            if (sent < 0)
            {
                report_error("Failed to send data: %s.", strerror(errno));
                result = -1;
                break;
            }
            total_sent += sent;
        }

        if (total_sent < line_length)
        {
            report_error("Failed to send complete file.");
            result = -1;
            break;
        }
    }

    // Set cursor position to file end (to cover case of error above)
    fseek(file, 0, SEEK_END);

    return result;
}

void* handle_client(void *arg)
{
    thread_info_t *thread_info = (thread_info_t *)arg;
    int client_sockfd = thread_info->client_sockfd;

    char buffer[NET_BUFFER_SIZE];
    int n;

    while ((n = recv(client_sockfd, buffer, NET_BUFFER_SIZE - 1, 0)) > 0)
    {
        buffer[n] = '\0';
        //assert(strncmp(buffer, "timestamp", 9) != 0);

        write_data_to_file(buffer);

        if (strchr(buffer, '\n'))
        {
            int write_failed = 0;
            {
                pthread_mutex_lock(&file_mutex);

                write_failed = send_data_to_client(client_sockfd);

                pthread_mutex_unlock(&file_mutex);
            }

            if (write_failed)
            {
                break;
            }
        }
    }

    const char* client_ip = "client";
    syslog(LOG_INFO, "Closed connection from %s", client_ip);
    close(client_sockfd);

    thread_info->client_sockfd = -1;
    thread_info->done = 1;
    free(thread_info);

    void *retval = NULL;
    pthread_exit(retval);

    return NULL;
}

void write_data_to_file(const char *buffer)
{
    {
        pthread_mutex_lock(&file_mutex);

        fputs(buffer, file);
        fflush(file);

        pthread_mutex_unlock(&file_mutex);
    }
}

void handle_timer(union sigval sv)
{
    (void)sv;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[128];
    strftime(timestamp, sizeof(timestamp), "timestamp:%a, %d %b %Y %H:%M:%S %z\n", tm_info);

    pthread_mutex_lock(&file_mutex);

    fputs(timestamp, file);
    fflush(file);

    pthread_mutex_unlock(&file_mutex);
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
        report_error("Failed to create timer: %s.", strerror(errno));
        return -1;
    }

    its.it_value.tv_sec = 0; // Initial expiration after 0 seconds
    its.it_value.tv_nsec = 0;
    its.it_interval.tv_sec = 10; // Timer interval of 10 second
    its.it_interval.tv_nsec = 0;

    // Start the timer
    if (timer_settime(timer_id, 0, &its, NULL) == -1)
    {
        report_error("Failed to start timer: %s.", strerror(errno));
        return -1;
    }

    return 0;
}

int run_daemon()
{
    pid_t pid = fork();

    if (pid < 0)
    {
        return -1;
    }

    if (pid > 0)
    {
        exit(0); // Parent process exits
    }

    child_process = 1;

    if (setsid() < 0)
    {
        return -1;
    }

    umask(0);

    pid_t sid = chdir("/");
    if (sid < 0)
    {
        return -1;
    }

    int dev_null_fd = open("/dev/null", O_RDWR);
    if (dev_null_fd == -1)
    {
        report_error("Failed to open /dev/null: %s", strerror(errno));
        return -1;
    }

    if (dup2(dev_null_fd, STDIN_FILENO) == -1)
    {
        report_error("Failed to redirect stdin to /dev/null: %s", strerror(errno));
        close(dev_null_fd);
        return -1;
    }

    if (dup2(dev_null_fd, STDOUT_FILENO) == -1)
    {
        report_error("Failed to redirect stdout to /dev/null: %s", strerror(errno));
        close(dev_null_fd);
        return -1;
    }

    if (dup2(dev_null_fd, STDERR_FILENO) == -1)
    {
        report_error("Failed to redirect stderr to /dev/null: %s", strerror(errno));
        close(dev_null_fd);
        return -1;
    }

    close(dev_null_fd);

    return 0;
}

int main(int argc, char *argv[])
{
    if (argc == 2 && strcmp(argv[1], "-d") == 0)
    {
        daemon_mode = 1;
    }

    setup_signal_handlers();

    // syslog
    openlog("aesdsocket", LOG_PID | LOG_CONS, daemon_mode ? LOG_DAEMON : LOG_USER);
    atexit(&closelog);

    // socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        report_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    // setsockopt
    const int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0)
    {
        report_error("Failed to set SO_REUSEADDR socket option: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    // bind
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);
    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
    {
        report_error("Failed to bind socket: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    // run daemon
    if (daemon_mode)
    {
        if (run_daemon() < 0)
        {
            report_error("Failed to start daemon: %s", strerror(errno));
            close(sockfd);
            return -1;
        }
    }

    // listen
    if (listen(sockfd, BACKLOG) < 0)
    {
        report_error("Failed to listen on socket: %s", strerror(errno));
        close(sockfd);
        return -1;
    }
    // mutex
//    if (pthread_mutex_init(&file_mutex) != 0) {
//	report_error("Failed to initialize mutex: %s.", strerror(errno));
//	close(sockfd);
//	return -1;
//    }

    // file
    file = fopen(FILE_PATH, "a+");
    if (!file)
    {
        report_error("Failed to open file: %s", strerror(errno));
        close(sockfd);
        return -1;
    }

    // timer
    if (create_timer() < 0)
    {
        close(sockfd);
        fclose(file);
        return -1;
    }

    //SLIST_INIT(&head);

    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd < 0)
        {
            report_error("Failed to accept connection: %s", strerror(errno));
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", client_ip);

        // Iterate over each thread - check if it is ready. If there are none, create a new one
        // thread_info_t *current, *next;
        // S_LIST_FOREACH_SAFE(current, next, &head, thread_info, next)
        // {
        //     if (current->done)
        //     {
        //         assert(current->client_sockfd < 0);
        //         S_LIST_DELETE_SAFE(current, &head, thread_info, entries);
        //         free(current);
        //     }
        // }

        // Create a new thread
        thread_info_t *thread_info = malloc(sizeof(thread_info_t));
        if (!thread_info)
        {
            report_error("Failed to allocate memory: %s", strerror(errno));
            close(client_sockfd);
            continue;
        }

        thread_info->client_sockfd = client_sockfd;
        thread_info->done = 0;
        if (pthread_create(&thread_info->thread_id, NULL, handle_client, thread_info) != 0)
        {
            report_error("Failed to create thread: %s", strerror(errno));
            close(client_sockfd);
            continue;
        }
        else
        {
            //SLIST_INSERT_HEAD(&head, thread_info, entries);
            pthread_detach(thread_info->thread_id);
        }
    }

    // We don't need to close sockfd and file her because we cannot really get here.

    return 0;
}
