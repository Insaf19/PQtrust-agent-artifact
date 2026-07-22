#include "bench_common.h"

#include "json_output.h"

#include <errno.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>

uint64_t pqtrust_now_ns(clockid_t clock_id)
{
    struct timespec ts;
    if (clock_gettime(clock_id, &ts) != 0) {
        return 0;
    }
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

uint64_t pqtrust_seed_next(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    *state = x;
    return x * 2685821657736338717ULL;
}

void pqtrust_shuffle(size_t *values, size_t count, uint64_t *state)
{
    if (count < 2) {
        return;
    }
    for (size_t i = count - 1; i > 0; i--) {
        size_t j = (size_t)(pqtrust_seed_next(state) % (i + 1));
        size_t tmp = values[i];
        values[i] = values[j];
        values[j] = tmp;
    }
}

char *pqtrust_strdup(const char *value)
{
    size_t len = strlen(value);
    char *copy = malloc(len + 1U);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, value, len + 1U);
    return copy;
}

char **pqtrust_split_csv(const char *csv, int *count)
{
    char *copy = pqtrust_strdup(csv);
    char **items = NULL;
    int used = 0;
    int cap = 0;

    if (copy == NULL) {
        return NULL;
    }

    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save)) {
        if (*tok == '\0') {
            free(copy);
            pqtrust_free_csv(items, used);
            return NULL;
        }
        if (used == cap) {
            int next_cap = cap == 0 ? 4 : cap * 2;
            char **next = realloc(items, sizeof(char *) * (size_t)next_cap);
            if (next == NULL) {
                free(copy);
                pqtrust_free_csv(items, used);
                return NULL;
            }
            items = next;
            cap = next_cap;
        }
        items[used] = pqtrust_strdup(tok);
        if (items[used] == NULL) {
            free(copy);
            pqtrust_free_csv(items, used);
            return NULL;
        }
        used++;
    }

    free(copy);
    *count = used;
    return used > 0 ? items : NULL;
}

void pqtrust_free_csv(char **items, int count)
{
    if (items == NULL) {
        return;
    }
    for (int i = 0; i < count; i++) {
        free(items[i]);
    }
    free(items);
}

bool pqtrust_parse_int(const char *text, int *value)
{
    char *end = NULL;
    errno = 0;
    long parsed = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed < 0 || parsed > 100000000L) {
        return false;
    }
    *value = (int)parsed;
    return true;
}

bool pqtrust_parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return false;
    }
    *value = (uint64_t)parsed;
    return true;
}

bool pqtrust_ascii_case_equal(const char *left, const char *right)
{
    if (left == NULL || right == NULL) {
        return false;
    }
    for (; *left != '\0' && *right != '\0'; left++, right++) {
        unsigned char l = (unsigned char)*left;
        unsigned char r = (unsigned char)*right;
        if (l >= 'A' && l <= 'Z') {
            l = (unsigned char)(l + ('a' - 'A'));
        }
        if (r >= 'A' && r <= 'Z') {
            r = (unsigned char)(r + ('a' - 'A'));
        }
        if (l != r) {
            return false;
        }
    }
    return *left == '\0' && *right == '\0';
}

void pqtrust_print_openssl_errors(void)
{
    ERR_print_errors_fp(stderr);
}

char *pqtrust_metadata_path(const char *output_path)
{
    const char *tls_name = "tls_handshakes.jsonl";
    const char *mldsa_name = "mldsa.jsonl";
    size_t out_len = strlen(output_path);
    const char *replacement = NULL;
    size_t suffix_len = 0;

    if (out_len >= strlen(tls_name)
        && strcmp(output_path + out_len - strlen(tls_name), tls_name) == 0) {
        replacement = "tls_batch_metadata.json";
        suffix_len = strlen(tls_name);
    } else if (out_len >= strlen(mldsa_name)
        && strcmp(output_path + out_len - strlen(mldsa_name), mldsa_name) == 0) {
        replacement = "mldsa_batch_metadata.json";
        suffix_len = strlen(mldsa_name);
    } else {
        replacement = ".metadata.json";
        suffix_len = 0;
    }

    size_t prefix_len = suffix_len == 0 ? out_len : out_len - suffix_len;
    size_t total = prefix_len + strlen(replacement) + 1U;
    char *path = malloc(total);
    if (path == NULL) {
        return NULL;
    }
    memcpy(path, output_path, prefix_len);
    memcpy(path + prefix_len, replacement, strlen(replacement) + 1U);
    return path;
}

int pqtrust_write_batch_metadata(
    const char *output_path,
    const char *executable_path,
    const batch_metadata_t *metadata
)
{
    char *path = pqtrust_metadata_path(output_path);
    if (path == NULL) {
        return 1;
    }
    FILE *out = fopen(path, "w");
    free(path);
    if (out == NULL) {
        return 1;
    }

    struct rusage usage;
    memset(&usage, 0, sizeof(usage));
    (void)getrusage(RUSAGE_SELF, &usage);

    char resolved_executable[4096];
    const char *executable_absolute = executable_path;
    if (realpath(executable_path, resolved_executable) != NULL) {
        executable_absolute = resolved_executable;
    }

    bool first = true;
    json_begin(out);
    json_int_field(out, &first, "schema_version", 1);
    json_string_field(out, &first, "measurement_scope", "batch");
    json_string_field(
        out,
        &first,
        "memory_semantics",
        "maximum_rss_bytes is process batch-level max RSS, not per operation"
    );
    json_int_field(out, &first, "maximum_rss_bytes", (long long)usage.ru_maxrss * 1024LL);
    json_string_field(out, &first, "executable_path_absolute", executable_absolute);
    json_string_field(out, &first, "openssl_runtime_version", OpenSSL_version(OPENSSL_VERSION));
    json_string_field(out, &first, "compiler_version", __VERSION__);
    json_string_array_field(out, &first, "invocation_arguments", metadata->argc, metadata->argv);
    json_int_field(out, &first, "warmup_count", metadata->warmups);
    json_int_field(out, &first, "measured_count", metadata->measured_count);
    json_uint_field(out, &first, "seed", (unsigned long long)metadata->seed);
    json_end(out);
    json_flush_line(out);

    if (fclose(out) != 0) {
        return 1;
    }
    return 0;
}
