#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

// Optional: use these functions to add debug or error prints to your application
#define LOG_DEBUG(msg,...)
//#define LOG_DEBUG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define LOG_ERROR(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{
    struct thread_data *data = (struct thread_data *)thread_param;

    // Sleep for the specified time before trying to obtain the mutex
    usleep(data->wait_to_obtain_ms * 1000);

    // Attempt to lock the mutex
    if (pthread_mutex_lock(data->mutex) == 0) {
        // Sleep while holding the mutex
        usleep(data->wait_to_release_ms * 1000);

        // Unlock the mutex
        pthread_mutex_unlock(data->mutex);

        // Mark the thread as successfully completed
        data->thread_complete_success = true;
    } else {
        // Failed to lock the mutex
        data->thread_complete_success = false;
    }

    // Return the thread data structure
    return thread_param;
}


bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex, int wait_to_obtain_ms, int wait_to_release_ms)
{
    // Check if arguments are correct.
    if (!mutex)
    {
	LOG_ERROR("Invalid arguments: mutex is null");
	return false;
    }

    if( wait_to_obtain_ms < 0 || wait_to_release_ms < 0)
    {
	LOG_ERROR("Invalid arguments: wait argument(-s) are less than 0.");
	return false;
    }

    // Allocate memory for thread_data
    struct thread_data *data = (struct thread_data *)malloc(sizeof(struct thread_data));
    if (!data)
    {
	LOG_ERROR("Failed to allocate memory. Error code: %d\n", errno);
        return false;
    }

    // Initialize the thread_data fields
    data->mutex = mutex;
    data->wait_to_obtain_ms = wait_to_obtain_ms;
    data->wait_to_release_ms = wait_to_release_ms;
    data->thread_complete_success = false;

    // Create the thread
    if (pthread_create(thread, NULL, threadfunc, data) != 0) {
        // Failed to create the thread, free the allocated memory
        free(data);
        return false;
    }

    // Successfully started the thread
    return true;
}

