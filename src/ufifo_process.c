#include "ufifo_internal.h"

#include <pthread.h>
#include <unistd.h>

static pthread_once_t process_identity_once = PTHREAD_ONCE_INIT;
static pid_t process_pid;
static int process_identity_error;

static void __ufifo_process_identity_after_fork(void)
{
    process_pid = getpid();
}

static void __ufifo_process_identity_register(void)
{
    process_pid = getpid();
    /* POSIX fork runs this child hook; raw fork/clone syscalls are outside the handle contract. */
    process_identity_error = pthread_atfork(NULL, NULL, __ufifo_process_identity_after_fork);
}

int __ufifo_process_identity_init(void)
{
    int ret = pthread_once(&process_identity_once, __ufifo_process_identity_register);

    if (ret != 0)
        return -ret;
    return process_identity_error == 0 ? 0 : -process_identity_error;
}

pid_t __ufifo_process_pid(void)
{
    return process_pid;
}
