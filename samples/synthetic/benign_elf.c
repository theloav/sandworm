/*
 * SANDWORM benign synthetic ELF source.
 *
 * Build note:
 *     cc -o benign_elf benign_elf.c
 *
 * Behavior (harmless): opens a marker file and "beacons" by attempting a
 * connect() to the simulated-network responder. No real host is contacted and
 * nothing is persisted. It exists so the ELF static + (gated) Linux dynamic
 * lanes have a real binary to chew on. The committed repo ships only this
 * source — never a built executable on a shared path.
 */
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("/tmp/sandworm_elf_marker", "w");
    if (f) { fputs("SANDWORM-MARKER: elf executed\n", f); fclose(f); }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(80);
    inet_pton(AF_INET, "10.0.0.1", &addr.sin_addr); /* simulated network only */
    connect(s, (struct sockaddr *)&addr, sizeof(addr)); /* will fail outside sim */
    close(s);
    printf("SANDWORM-MARKER: done\n");
    return 0;
}
