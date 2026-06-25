/* greet — a genuinely benign demo program (real, compiled executable).
 * Prints a greeting and the current date. No network, no exec, no file writes.
 * Committed alongside its source so it is fully transparent/reproducible. */
#include <stdio.h>
#include <time.h>

int main(int argc, char **argv) {
    const char *who = (argc > 1) ? argv[1] : "world";
    time_t now = time(NULL);
    printf("Hello, %s!\n", who);
    printf("The time is %s", ctime(&now));
    return 0;
}
