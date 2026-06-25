/* wordcount — a genuinely benign demo program (real, compiled executable).
 * Counts words/lines/chars from stdin, like a tiny `wc`. Pure computation:
 * no network, no process execution, no persistence. */
#include <stdio.h>
#include <ctype.h>

int main(void) {
    long lines = 0, words = 0, chars = 0;
    int c, in_word = 0;
    while ((c = getchar()) != EOF) {
        chars++;
        if (c == '\n') lines++;
        if (isspace(c)) in_word = 0;
        else if (!in_word) { in_word = 1; words++; }
    }
    printf("%ld %ld %ld\n", lines, words, chars);
    return 0;
}
