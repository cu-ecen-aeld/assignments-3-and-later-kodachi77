#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#define MAX_ERROR_MSG_SIZE 1024

void report_error(const char* format, ...) {
    va_list args;
    char buffer[MAX_ERROR_MSG_SIZE];

    // Start processing the arguments
    va_start(args, format);

    strcpy(buffer, "Error: ");

    // Format the error message into the buffer
    vsnprintf(buffer+7, MAX_ERROR_MSG_SIZE, format, args);

    // Log the error to syslog
    syslog(LOG_ERR, "%s", buffer);

    // Print the error to stderr
    fprintf(stderr, "%s. Exiting with code 1.\n", buffer);

    // Clean up the argument list
    va_end(args);
}


int main(int argc, char *argv[]) {
    // Initialize syslog with LOG_USER facility
    openlog("writer", LOG_PID | LOG_CONS, LOG_USER);
    atexit(&closelog);

    // Check if the correct number of arguments is provided
    if (argc != 3) {
	report_error("Invalid number of arguments.");
        fprintf(stderr, "Usage: %s <writefile> <writestr>\n", argv[0]);
        exit(1);
    }

    // Arguments
    char *writefile = argv[1];
    char *writestr = argv[2];

    // Attempt to open the file for writing
    FILE *file = fopen(writefile, "w");
    if (file == NULL) {
        report_error("Could not create or open file '%s': %s", writefile, strerror(errno));
        exit(1);
    }

    
    // Write the string to the file
    int ret = fprintf(file, "%s", writestr);
    if( ret < 0 || ret < strlen(writestr)) {
	report_error("Failed to write string %s to a file.", writestr);
	fclose(file);
	exit(1);
    }

    // Log the successful writing operation
    syslog(LOG_DEBUG, "Writing '%s' to '%s'", writestr, writefile);

    // Close the file
    fclose(file);

    return 0;
}