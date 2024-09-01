#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <syslog.h>
#include <signal.h>
#include <fcntl.h>


#define PORT 9000
#define BACKLOG 16
#define NET_BUFFER_SIZE 1024
#define MSG_BUFFER_SIZE 1024
#define FILE_PATH "/var/tmp/aesdsocketdata"


// Global variables
int sockfd;
int client_sockfd;
FILE *file;
int daemon_mode = 0;
int child_process = 0;

int is_daemon() {
    return daemon_mode && child_process ? 1 : 0;
}

void report_error(const char* format, ...) {
    va_list args;
    char buffer[MSG_BUFFER_SIZE+7];

    // Start processing the arguments
    va_start(args, format);

    strcpy(buffer, "Error: ");

    // Format the error message into the buffer
    vsnprintf(buffer+7, MSG_BUFFER_SIZE, format, args);

    // Log the error to syslog
    syslog(LOG_ERR, "%s", buffer);

    // We only want to print to stderr if it is not a daemon.
    if (!is_daemon()) {
        fprintf(stderr, "%s. Exiting.\n", buffer);
    }

    // Clean up the argument list
    va_end(args);
}


void signal_handler(int signal) {
    const char *sig_str = strsignal(signal);

    char buffer[MSG_BUFFER_SIZE] = {0};
    snprintf(buffer, MSG_BUFFER_SIZE, "Caught signal '%s', exiting.", sig_str);
    syslog(LOG_INFO, "%s", buffer);
    if (!is_daemon()) {
	fprintf(stderr, "%s\n", buffer);
    }
    
    if (client_sockfd >= 0) {
        close(client_sockfd);
        syslog(LOG_INFO, "Closed client connection.");
    }
    
    if (sockfd >= 0) {
        close(sockfd);
    }

    if (file) {
        fclose(file);
    }

    if (signal == SIGINT || signal == SIGTERM) {
        remove(FILE_PATH);
    }

    exit(0);
}

void setup_signal_handlers() {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
}

int run_daemon() {
    pid_t pid = fork();
    
    if (pid < 0) {
        return -1;
    }

    if (pid > 0) {
        exit(0); // Parent process exits
    }

    child_process = 1;

    if (setsid() < 0) {
        return -1;
    }

    umask(0);

    pid_t sid = chdir("/");
    if (sid < 0) {
        return -1;
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    return 0;
}

int main(int argc, char *argv[]) {

    if (argc == 2 && strcmp(argv[1], "-d") == 0) {
        daemon_mode = 1;
    }

    setup_signal_handlers();

    openlog("aesdsocket", LOG_PID | LOG_CONS, daemon_mode ? LOG_DAEMON : LOG_USER);
    atexit(&closelog);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        report_error("Failed to create socket: %s", strerror(errno));
        return -1;
    }

    const int enable = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) < 0) {
        report_error("Failed to set SO_REUSEADDR socket option: %s", strerror(errno));
	return -1;
    }

    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        report_error("Failed to bind socket: %s", strerror(errno));
        return -1;
    }

    if (daemon_mode) {
        if (run_daemon() < 0) {
            report_error("Failed to start daemon: %s", strerror(errno));
            return -1;
        }
    }

    if (listen(sockfd, BACKLOG) < 0) {
        report_error( "Failed to listen on socket: %s", strerror(errno));
        return -1;
    }

    while (1) {
        client_sockfd = accept(sockfd, (struct sockaddr *)&client_addr, &client_len);
        if (client_sockfd < 0) {
            report_error("Failed to accept connection: %s", strerror(errno));
            continue;
        }

        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
        syslog(LOG_INFO, "Accepted connection from %s", client_ip);

        file = fopen(FILE_PATH, "a+");
        if (!file) {
            report_error("Failed to open file: %s", strerror(errno));
            close(client_sockfd);
            continue;
        }

        char buffer[NET_BUFFER_SIZE];
        int n;
	int write_failed = 0;

        while ((n = recv(client_sockfd, buffer, NET_BUFFER_SIZE - 1, 0)) > 0) {
            buffer[n] = '\0';
            fprintf(file, "%s", buffer);
            fflush(file);

            if (strchr(buffer, '\n')) {
		// send contents of the file back to the client
                fseek(file, 0, SEEK_SET);

		char write_buffer[NET_BUFFER_SIZE];
		size_t bytes_read;

		write_failed = 0;

		while ((bytes_read = fread(buffer, 1, NET_BUFFER_SIZE, file)) > 0) {
		    size_t total_sent = 0;
		    while (total_sent < bytes_read) {
		        ssize_t sent = send(client_sockfd, buffer + total_sent, bytes_read - total_sent, 0);
		        if (sent < 0) {
		            report_error("Failed to send data: %s.", strerror(errno));
			    write_failed = 1;
		            break;
			}
	        	total_sent += sent;
	    	    }

	    	    if (total_sent < bytes_read) {
	        	report_error("Failed to send complete file.");
			write_failed = 1;
	        	break;
	    	    }
		}

		// Set cursor position to file end (to cover case of error above)
		fseek(file, 0, SEEK_END);

		if (write_failed) {
		    break;    
		}
            }
        }

        syslog(LOG_INFO, "Closed connection from %s", client_ip);
        close(client_sockfd);
        fclose(file);
        file = NULL;
    }

    // We don't need to close sockfd and file her because we cannot really get here.

    return 0;
}
