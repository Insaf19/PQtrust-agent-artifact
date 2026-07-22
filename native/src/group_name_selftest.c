#include "bench_common.h"

#include <stdio.h>

static int expect_equal(const char *left, const char *right)
{
    if (!pqtrust_ascii_case_equal(left, right)) {
        fprintf(stderr, "expected equal group names: %s %s\n", left, right);
        return 1;
    }
    return 0;
}

static int expect_different(const char *left, const char *right)
{
    if (pqtrust_ascii_case_equal(left, right)) {
        fprintf(stderr, "expected different group names: %s %s\n", left, right);
        return 1;
    }
    return 0;
}

int main(void)
{
    int failures = 0;
    failures += expect_equal("X25519", "x25519");
    failures += expect_equal("x25519", "X25519");
    failures += expect_equal("SecP384r1MLKEM1024", "secp384r1mlkem1024");
    failures += expect_different("X25519", "X25519MLKEM768");
    failures += expect_different("X25519", "X25519 ");
    failures += expect_different("X25519", "");
    return failures == 0 ? 0 : 1;
}
