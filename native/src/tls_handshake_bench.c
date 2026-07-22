#include "bench_common.h"
#include "json_output.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **groups;
    int group_count;
    const char *certificate;
    const char *private_key;
    const char *ca_certificate;
    int warmups;
    int repetitions;
    uint64_t seed;
    const char *output;
} tls_args_t;

typedef struct {
    bool success;
    char negotiated_group[PQTRUST_TLS_GROUP_NAME_MAX];
    char server_negotiated_group[PQTRUST_TLS_GROUP_NAME_MAX];
    char tls_version[32];
    char cipher_suite[64];
    uint64_t wall_time_ns;
    uint64_t process_cpu_time_ns;
    size_t client_to_server_bytes;
    size_t server_to_client_bytes;
    long certificate_verify_result;
    int session_reused;
    int error_code;
} tls_result_t;

typedef enum {
    /* Successful handshake and post-handshake validation. */
    TLS_BENCH_ERROR_NONE = 0,
    /* OpenSSL API, BIO, context, or handshake failure; inspect OpenSSL stderr stack. */
    TLS_BENCH_ERROR_OPENSSL = 1,
    /* Completed handshake failed benchmark post-handshake validation. */
    TLS_BENCH_ERROR_VALIDATION = 2,
    /* OpenSSL did not report usable owned client/server group names. */
    TLS_BENCH_ERROR_GROUP_NAME = 3,
} tls_bench_error_t;

static void usage(void)
{
    fputs(
        "tls_handshake_bench --groups CSV --certificate PATH --private-key PATH "
        "--ca-certificate PATH --warmups N --repetitions N --seed N --output PATH\n",
        stderr
    );
}

static bool parse_args(int argc, char **argv, tls_args_t *args)
{
    memset(args, 0, sizeof(*args));
    args->seed = 1;
    for (int i = 1; i < argc; i++) {
        if (i + 1 >= argc) {
            return false;
        }
        const char *key = argv[i++];
        const char *value = argv[i];
        if (strcmp(key, "--groups") == 0) {
            args->groups = pqtrust_split_csv(value, &args->group_count);
        } else if (strcmp(key, "--certificate") == 0) {
            args->certificate = value;
        } else if (strcmp(key, "--private-key") == 0) {
            args->private_key = value;
        } else if (strcmp(key, "--ca-certificate") == 0) {
            args->ca_certificate = value;
        } else if (strcmp(key, "--warmups") == 0) {
            if (!pqtrust_parse_int(value, &args->warmups)) {
                return false;
            }
        } else if (strcmp(key, "--repetitions") == 0) {
            if (!pqtrust_parse_int(value, &args->repetitions)) {
                return false;
            }
        } else if (strcmp(key, "--seed") == 0) {
            if (!pqtrust_parse_u64(value, &args->seed)) {
                return false;
            }
        } else if (strcmp(key, "--output") == 0) {
            args->output = value;
        } else {
            return false;
        }
    }
    return args->groups != NULL && args->group_count > 0 && args->certificate != NULL
        && args->private_key != NULL && args->ca_certificate != NULL && args->output != NULL;
}

static bool copy_group_name(char *destination, size_t destination_size, const char *source)
{
    if (source == NULL || *source == '\0') {
        return false;
    }
    int written = snprintf(destination, destination_size, "%s", source);
    return written > 0 && (size_t)written < destination_size;
}

static bool copy_nonempty_string(char *destination, size_t destination_size, const char *source)
{
    if (source == NULL || *source == '\0') {
        return false;
    }
    int written = snprintf(destination, destination_size, "%s", source);
    return written > 0 && (size_t)written < destination_size;
}

static void print_validation_failure(
    const char *requested_group,
    const tls_result_t *result,
    const char *condition
)
{
    fprintf(
        stderr,
        "tls_handshake_bench validation failed: requested_group=%s "
        "client_negotiated_group=%s server_negotiated_group=%s condition=%s error_code=%d\n",
        requested_group == NULL ? "" : requested_group,
        result->negotiated_group[0] == '\0' ? "<unavailable>" : result->negotiated_group,
        result->server_negotiated_group[0] == '\0' ? "<unavailable>"
                                                   : result->server_negotiated_group,
        condition == NULL ? "unknown" : condition,
        result->error_code
    );
}

static bool validate_tls_result(
    const char *requested_group,
    const tls_result_t *result,
    int client_finished,
    int server_finished,
    const char **failed_condition
)
{
    if (client_finished != 1) {
        *failed_condition = "client handshake did not complete";
        return false;
    }
    if (server_finished != 1) {
        *failed_condition = "server handshake did not complete";
        return false;
    }
    if (strcmp(result->tls_version, "TLSv1.3") != 0) {
        *failed_condition = "unexpected TLS version";
        return false;
    }
    if (result->negotiated_group[0] == '\0') {
        *failed_condition = "client negotiated group unavailable";
        return false;
    }
    if (result->server_negotiated_group[0] == '\0') {
        *failed_condition = "server negotiated group unavailable";
        return false;
    }
    if (!pqtrust_ascii_case_equal(result->negotiated_group, requested_group)) {
        *failed_condition = "requested and negotiated groups differ";
        return false;
    }
    if (!pqtrust_ascii_case_equal(result->negotiated_group, result->server_negotiated_group)) {
        *failed_condition = "client and server negotiated groups differ";
        return false;
    }
    if (strcmp(result->cipher_suite, "TLS_AES_256_GCM_SHA384") != 0) {
        *failed_condition = "unexpected TLS cipher suite";
        return false;
    }
    if (result->certificate_verify_result != X509_V_OK) {
        *failed_condition = "certificate verification failed";
        return false;
    }
    if (result->session_reused != 0) {
        *failed_condition = "session was reused";
        return false;
    }
    if (result->client_to_server_bytes == 0 || result->server_to_client_bytes == 0) {
        *failed_condition = "encrypted handshake byte counts were not positive";
        return false;
    }
    *failed_condition = NULL;
    return true;
}

static SSL_CTX *make_server_ctx(const tls_args_t *args, const char *group)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) {
        return NULL;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1
        || SSL_CTX_set1_groups_list(ctx, group) != 1
        || SSL_CTX_use_certificate_file(ctx, args->certificate, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_use_PrivateKey_file(ctx, args->private_key, SSL_FILETYPE_PEM) != 1
        || SSL_CTX_check_private_key(ctx) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    return ctx;
}

static SSL_CTX *make_client_ctx(const tls_args_t *args, const char *group)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        return NULL;
    }
    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION) != 1
        || SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384") != 1
        || SSL_CTX_set1_groups_list(ctx, group) != 1
        || SSL_CTX_load_verify_locations(ctx, args->ca_certificate, NULL) != 1) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx, 0);
    SSL_CTX_set_options(ctx, SSL_OP_NO_TICKET);
    return ctx;
}

static int pump(BIO *source, BIO *destination, size_t *counter)
{
    char buf[4096];
    int moved_any = 0;
    for (;;) {
        int pending = BIO_pending(source);
        if (pending <= 0) {
            return moved_any;
        }
        int read_len = BIO_read(source, buf, sizeof(buf));
        if (read_len <= 0) {
            return -1;
        }
        int written = BIO_write(destination, buf, read_len);
        if (written != read_len) {
            return -1;
        }
        *counter += (size_t)read_len;
        moved_any = 1;
    }
}

static tls_result_t run_handshake(const tls_args_t *args, const char *group)
{
    tls_result_t result;
    memset(&result, 0, sizeof(result));
    result.certificate_verify_result = -1;
    result.error_code = TLS_BENCH_ERROR_OPENSSL;

    SSL_CTX *server_ctx = make_server_ctx(args, group);
    SSL_CTX *client_ctx = make_client_ctx(args, group);
    SSL *server = NULL;
    SSL *client = NULL;
    BIO *client_in = NULL;
    BIO *client_out = NULL;
    BIO *server_in = NULL;
    BIO *server_out = NULL;

    if (server_ctx == NULL || client_ctx == NULL) {
        goto done;
    }
    server = SSL_new(server_ctx);
    client = SSL_new(client_ctx);
    if (server == NULL || client == NULL) {
        goto done;
    }
    if (SSL_set1_host(client, "localhost") != 1) {
        goto done;
    }
    SSL_set_connect_state(client);
    SSL_set_accept_state(server);

    client_in = BIO_new(BIO_s_mem());
    client_out = BIO_new(BIO_s_mem());
    server_in = BIO_new(BIO_s_mem());
    server_out = BIO_new(BIO_s_mem());
    if (client_in == NULL || client_out == NULL || server_in == NULL || server_out == NULL) {
        goto done;
    }
    SSL_set_bio(client, client_in, client_out);
    SSL_set_bio(server, server_in, server_out);
    client_in = NULL;
    client_out = NULL;
    server_in = NULL;
    server_out = NULL;

    uint64_t wall_start = pqtrust_now_ns(CLOCK_MONOTONIC_RAW);
    uint64_t cpu_start = pqtrust_now_ns(CLOCK_PROCESS_CPUTIME_ID);
    for (int iter = 0; iter < 10000; iter++) {
        int cr = SSL_do_handshake(client);
        int ce = cr == 1 ? SSL_ERROR_NONE : SSL_get_error(client, cr);
        int sr = SSL_do_handshake(server);
        int se = sr == 1 ? SSL_ERROR_NONE : SSL_get_error(server, sr);

        if (pump(SSL_get_wbio(client), SSL_get_rbio(server), &result.client_to_server_bytes) < 0
            || pump(SSL_get_wbio(server), SSL_get_rbio(client), &result.server_to_client_bytes)
                < 0) {
            goto done;
        }
        if (SSL_is_init_finished(client) == 1 && SSL_is_init_finished(server) == 1) {
            break;
        }
        if (!((ce == SSL_ERROR_WANT_READ || ce == SSL_ERROR_WANT_WRITE || ce == SSL_ERROR_NONE)
              && (se == SSL_ERROR_WANT_READ || se == SSL_ERROR_WANT_WRITE
                  || se == SSL_ERROR_NONE))) {
            goto done;
        }
        if (iter == 9999) {
            goto done;
        }
    }
    uint64_t cpu_end = pqtrust_now_ns(CLOCK_PROCESS_CPUTIME_ID);
    uint64_t wall_end = pqtrust_now_ns(CLOCK_MONOTONIC_RAW);

    result.wall_time_ns = wall_end - wall_start;
    result.process_cpu_time_ns = cpu_end - cpu_start;
    const char *client_group = SSL_get0_group_name(client);
    const char *server_group = SSL_get0_group_name(server);
    if (!copy_group_name(result.negotiated_group, sizeof(result.negotiated_group), client_group)
        || !copy_group_name(
            result.server_negotiated_group,
            sizeof(result.server_negotiated_group),
            server_group
        )) {
        result.error_code = TLS_BENCH_ERROR_GROUP_NAME;
        print_validation_failure(group, &result, "negotiated group unavailable or too long");
        goto done;
    }
    if (!copy_nonempty_string(result.tls_version, sizeof(result.tls_version), SSL_get_version(client))
        || !copy_nonempty_string(
            result.cipher_suite,
            sizeof(result.cipher_suite),
            SSL_get_cipher_name(client)
        )) {
        result.error_code = TLS_BENCH_ERROR_VALIDATION;
        print_validation_failure(group, &result, "TLS version or cipher suite unavailable");
        goto done;
    }
    result.certificate_verify_result = SSL_get_verify_result(client);
    result.session_reused = SSL_session_reused(client);
    const char *failed_condition = NULL;
    result.success = validate_tls_result(
        group,
        &result,
        SSL_is_init_finished(client),
        SSL_is_init_finished(server),
        &failed_condition
    );
    result.error_code = result.success ? TLS_BENCH_ERROR_NONE : TLS_BENCH_ERROR_VALIDATION;
    if (!result.success) {
        print_validation_failure(group, &result, failed_condition);
    }

done:
    if (!result.success && result.error_code == TLS_BENCH_ERROR_OPENSSL) {
        pqtrust_print_openssl_errors();
    }
    BIO_free(client_in);
    BIO_free(client_out);
    BIO_free(server_in);
    BIO_free(server_out);
    SSL_free(client);
    SSL_free(server);
    SSL_CTX_free(client_ctx);
    SSL_CTX_free(server_ctx);
    return result;
}

static void write_record(
    FILE *out,
    int sequence,
    int block,
    int position,
    const char *group,
    const tls_result_t *result
)
{
    bool first = true;
    json_begin(out);
    json_int_field(out, &first, "schema_version", PQTRUST_SCHEMA_VERSION);
    json_string_field(out, &first, "benchmark", "tls13_handshake");
    json_int_field(out, &first, "sequence", sequence);
    json_int_field(out, &first, "block", block);
    json_int_field(out, &first, "position_in_block", position);
    json_string_field(out, &first, "requested_group", group);
    json_string_field(out, &first, "negotiated_group", result->negotiated_group);
    json_string_field(out, &first, "server_negotiated_group", result->server_negotiated_group);
    json_string_field(out, &first, "tls_version", result->tls_version);
    json_string_field(out, &first, "cipher_suite", result->cipher_suite);
    json_uint_field(out, &first, "wall_time_ns", result->wall_time_ns);
    json_uint_field(out, &first, "process_cpu_time_ns", result->process_cpu_time_ns);
    json_uint_field(out, &first, "client_to_server_bytes", result->client_to_server_bytes);
    json_uint_field(out, &first, "server_to_client_bytes", result->server_to_client_bytes);
    json_uint_field(
        out,
        &first,
        "total_handshake_bytes",
        result->client_to_server_bytes + result->server_to_client_bytes
    );
    json_int_field(out, &first, "certificate_verify_result", result->certificate_verify_result);
    json_bool_field(out, &first, "session_reused", result->session_reused != 0);
    json_bool_field(out, &first, "success", result->success);
    json_int_field(out, &first, "error_code", result->error_code);
    json_end(out);
    json_flush_line(out);
}

int main(int argc, char **argv)
{
    tls_args_t args;
    if (!parse_args(argc, argv, &args)) {
        usage();
        return 2;
    }

    OPENSSL_init_ssl(0, NULL);

    for (int i = 0; i < args.group_count; i++) {
        for (int w = 0; w < args.warmups; w++) {
            tls_result_t warmup = run_handshake(&args, args.groups[i]);
            if (!warmup.success) {
                pqtrust_free_csv(args.groups, args.group_count);
                return 1;
            }
        }
    }

    FILE *out = fopen(args.output, "w");
    if (out == NULL) {
        pqtrust_free_csv(args.groups, args.group_count);
        return 1;
    }

    size_t *order = calloc((size_t)args.group_count, sizeof(size_t));
    if (order == NULL) {
        fclose(out);
        pqtrust_free_csv(args.groups, args.group_count);
        return 1;
    }

    uint64_t rng = args.seed == 0 ? 1 : args.seed;
    int sequence = 0;
    int exit_code = 0;
    for (int block = 0; block < args.repetitions; block++) {
        for (int i = 0; i < args.group_count; i++) {
            order[i] = (size_t)i;
        }
        pqtrust_shuffle(order, (size_t)args.group_count, &rng);
        for (int pos = 0; pos < args.group_count; pos++) {
            const char *group = args.groups[order[pos]];
            tls_result_t result = run_handshake(&args, group);
            write_record(out, sequence, block, pos, group, &result);
            if (!result.success) {
                exit_code = 1;
            }
            sequence++;
        }
    }
    if (fclose(out) != 0) {
        exit_code = 1;
    }

    batch_metadata_t metadata = {
        .argc = argc,
        .argv = argv,
        .warmups = args.warmups * args.group_count,
        .measured_count = args.repetitions * args.group_count,
        .seed = args.seed,
    };
    if (pqtrust_write_batch_metadata(args.output, argv[0], &metadata) != 0) {
        exit_code = 1;
    }

    free(order);
    pqtrust_free_csv(args.groups, args.group_count);
    return exit_code;
}
