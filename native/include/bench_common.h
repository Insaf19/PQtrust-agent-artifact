#ifndef PQTRUST_BENCH_COMMON_H
#define PQTRUST_BENCH_COMMON_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define PQTRUST_SCHEMA_VERSION 1
#define PQTRUST_TLS_GROUP_NAME_MAX 128

typedef struct {
    int argc;
    char **argv;
    int warmups;
    int measured_count;
    uint64_t seed;
} batch_metadata_t;

uint64_t pqtrust_now_ns(clockid_t clock_id);
uint64_t pqtrust_seed_next(uint64_t *state);
void pqtrust_shuffle(size_t *values, size_t count, uint64_t *state);
char *pqtrust_strdup(const char *value);
char **pqtrust_split_csv(const char *csv, int *count);
void pqtrust_free_csv(char **items, int count);
bool pqtrust_parse_int(const char *text, int *value);
bool pqtrust_parse_u64(const char *text, uint64_t *value);
bool pqtrust_ascii_case_equal(const char *left, const char *right);
void pqtrust_print_openssl_errors(void);
int pqtrust_write_batch_metadata(
    const char *output_path,
    const char *executable_path,
    const batch_metadata_t *metadata
);
char *pqtrust_metadata_path(const char *output_path);

#endif
