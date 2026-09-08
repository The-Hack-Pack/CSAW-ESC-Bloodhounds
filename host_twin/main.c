#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "target.h"

/* usage: ./target race [iters] [widen]
 *        ./target cred [iters] [widen]      -- exits 1 if privilege escalated
 *        ./target cred-baseline [checks]   -- sequential control, must be 0
 *        ./target config <hexstring>
 */
int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s race|cred|cred-baseline|config ...\n", argv[0]); return 2; }

    if (!strcmp(argv[1], "race")) {
        int iters = argc > 2 ? atoi(argv[2]) : 2000;
        int widen = argc > 3 ? atoi(argv[3]) : 0;
        return run_race(iters, widen);
    }
    if (!strcmp(argv[1], "cred-baseline")) {
        int checks = argc > 2 ? atoi(argv[2]) : 200;
        int n = run_cred_baseline(checks);
        printf("sequential control: %d escalation(s) in %d checks (expect 0)\n", n, checks);
        return n > 0 ? 1 : 0;
    }
    if (!strcmp(argv[1], "cred")) {
        int iters = argc > 2 ? atoi(argv[2]) : 200;
        int widen = argc > 3 ? atoi(argv[3]) : 0;
        int n = run_cred_race(iters, widen);
        printf("check_credential granted admin %d time(s) for a non-admin record\n", n);
        return n > 0 ? 1 : 0;
    }
    if (!strcmp(argv[1], "config") && argc > 2) {
        size_t hl = strlen(argv[2]) / 2;
        unsigned char *buf = malloc(hl ? hl : 1);
        for (size_t i = 0; i < hl; i++)
            sscanf(argv[2] + 2 * i, "%2hhx", &buf[i]);
        int r = parse_config(buf, hl);
        free(buf);
        printf("parse_config -> %d\n", r);
        return 0;
    }
    return 2;
}
