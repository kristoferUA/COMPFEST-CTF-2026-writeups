#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <sys/prctl.h>
#include <unistd.h>

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void init_security(void)
{
    if (prctl(PR_SET_DUMPABLE, 1) != 0)
        die("prctl(PR_SET_DUMPABLE)");
    if (prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY) != 0)
        die("prctl(PR_SET_PTRACER)");
}

int main(void)
{
    init_security();

    raise(SIGSTOP);

    for (;;)
        pause();
}
