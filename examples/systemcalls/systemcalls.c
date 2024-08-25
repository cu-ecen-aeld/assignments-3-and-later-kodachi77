#include "systemcalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    // Check argument correctness
    if (cmd == NULL) {
        return false;
    }

    // Call the system() function
    int ret = system(cmd);

    // Check for errors as described in https://www.man7.org/linux/man-pages/man3/system.3.html
    // This code made explicit on purpose. We could have done this in one if.
    if (ret == -1) {
        // system() itself failed
        return false;
    } else if (WIFSIGNALED(ret) && (WTERMSIG (ret) == SIGINT || WTERMSIG (ret) == SIGQUIT)) {
        // The command was terminated by a signal
        return false;
    } else if (WIFEXITED(ret) && WEXITSTATUS(ret)) {
        // The command exited with a non-zero status
        return false;
    }

    return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    va_end(args);

    // Fork the process
    pid_t pid = fork();
    if (pid == -1) {
        // Fork failed
        return false;
    } else if (pid == 0) {
        // Child process: execute the command using execv
        execv(command[0], command);
        // If execv returns, it means there was an error. Return non-zero status.
        exit(1);
    } else {
        // Parent process: wait for the child process to complete
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            // waitpid failed
            return false;
        }

        // Check if the child process terminated normally
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }

    return false;
}

/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;

    va_end(args);

    // Fork the process
    pid_t pid = fork();
    if (pid == -1) {
        // Fork failed
        return false;
    } else if (pid == 0) {
        // Child process: redirect stdout to the output file

        // Open the output file
        int fd = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            // Opening file failed
            exit(1);
        }

        // Redirect stdout to the file
        if (dup2(fd, STDOUT_FILENO) < 0) {
            // Redirecting stdout failed
            close(fd);
            exit(1);
        }

        // Close old file descriptor
        close(fd);

        // Execute the command using execv
        execv(command[0], command);
	// If execv returns this means error happened.
        exit(1);
    } else {
        // Parent process: wait for the child process to complete
        int status;
        if (waitpid(pid, &status, 0) == -1) {
            // waitpid failed
            return false;
        }

        // Check if the child process terminated normally
        return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }

    return false;
}
