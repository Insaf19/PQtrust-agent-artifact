#include "bench_common.h"
#include "json_output.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    const char *algorithm;
    const char *private_path;
    const char *public_path;
    EVP_PKEY *private_key;
    EVP_PKEY *public_key;
} key_case_t;

typedef struct {
    const char *mldsa65_private;
    const char *mldsa65_public;
    const char *mldsa87_private;
    const char *mldsa87_public;
    char **message_sizes_raw;
    int *message_sizes;
    int message_size_count;
    int warmups;
    int repetitions;
    uint64_t seed;
    const char *output;
} mldsa_args_t;

typedef struct {
    bool success;
    bool verification_success;
    bool negative_self_test_passed;
    uint64_t sign_time_ns;
    uint64_t verify_time_ns;
    size_t signature_size_bytes;
    int error_code;
} mldsa_result_t;

static void usage(void)
{
    fputs(
        "mldsa_bench --mldsa65-private PATH --mldsa65-public PATH "
        "--mldsa87-private PATH --mldsa87-public PATH --message-sizes CSV "
        "--warmups N --repetitions N --seed N --output PATH\n",
        stderr
    );
}

static bool parse_args(int argc, char **argv, mldsa_args_t *args)
{
    memset(args, 0, sizeof(*args));
    args->seed = 1;
    for (int i = 1; i < argc; i++) {
        if (i + 1 >= argc) {
            return false;
        }
        const char *key = argv[i++];
        const char *value = argv[i];
        if (strcmp(key, "--mldsa65-private") == 0) {
            args->mldsa65_private = value;
        } else if (strcmp(key, "--mldsa65-public") == 0) {
            args->mldsa65_public = value;
        } else if (strcmp(key, "--mldsa87-private") == 0) {
            args->mldsa87_private = value;
        } else if (strcmp(key, "--mldsa87-public") == 0) {
            args->mldsa87_public = value;
        } else if (strcmp(key, "--message-sizes") == 0) {
            args->message_sizes_raw = pqtrust_split_csv(value, &args->message_size_count);
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
    if (args->message_sizes_raw == NULL || args->message_size_count <= 0) {
        return false;
    }
    args->message_sizes = calloc((size_t)args->message_size_count, sizeof(int));
    if (args->message_sizes == NULL) {
        return false;
    }
    for (int i = 0; i < args->message_size_count; i++) {
        if (!pqtrust_parse_int(args->message_sizes_raw[i], &args->message_sizes[i])
            || args->message_sizes[i] <= 0) {
            return false;
        }
    }
    return args->mldsa65_private != NULL && args->mldsa65_public != NULL
        && args->mldsa87_private != NULL && args->mldsa87_public != NULL && args->output != NULL;
}

static EVP_PKEY *load_key(const char *path, bool private_key)
{
    FILE *file = fopen(path, "r");
    EVP_PKEY *key = NULL;
    if (file == NULL) {
        return NULL;
    }
    if (private_key) {
        key = PEM_read_PrivateKey(file, NULL, NULL, NULL);
    } else {
        key = PEM_read_PUBKEY(file, NULL, NULL, NULL);
    }
    fclose(file);
    return key;
}

static unsigned char *make_message(size_t size, int repetition)
{
    unsigned char *message = malloc(size);
    if (message == NULL) {
        return NULL;
    }
    size_t produced = 0;
    uint32_t counter = 0;
    while (produced < size) {
        unsigned char digest[SHA256_DIGEST_LENGTH];
        char header[128];
        int header_len = snprintf(
            header,
            sizeof(header),
            "PQTrust-MLDSA-Smoke-v1:%zu:%d:%u",
            size,
            repetition,
            counter
        );
        if (header_len < 0) {
            free(message);
            return NULL;
        }
        if (SHA256((const unsigned char *)header, (size_t)header_len, digest) == NULL) {
            free(message);
            return NULL;
        }
        size_t take = size - produced < sizeof(digest) ? size - produced : sizeof(digest);
        memcpy(message + produced, digest, take);
        produced += take;
        counter++;
    }
    return message;
}

static bool sign_message(
    EVP_PKEY *key,
    const unsigned char *message,
    size_t message_len,
    unsigned char **signature,
    size_t *signature_len
)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    bool ok = EVP_DigestSignInit(ctx, NULL, NULL, NULL, key) == 1
        && EVP_DigestSign(ctx, NULL, signature_len, message, message_len) == 1;
    if (ok) {
        *signature = malloc(*signature_len);
        ok = *signature != NULL
            && EVP_DigestSign(ctx, *signature, signature_len, message, message_len) == 1;
    }
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool verify_message(
    EVP_PKEY *key,
    const unsigned char *message,
    size_t message_len,
    const unsigned char *signature,
    size_t signature_len
)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        return false;
    }
    int rc = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, key) == 1) {
        rc = EVP_DigestVerify(ctx, signature, signature_len, message, message_len);
    }
    EVP_MD_CTX_free(ctx);
    return rc == 1;
}

static mldsa_result_t run_case(key_case_t *key_case, int message_size, int repetition)
{
    mldsa_result_t result;
    memset(&result, 0, sizeof(result));
    result.error_code = 1;
    unsigned char *message = make_message((size_t)message_size, repetition);
    unsigned char *signature = NULL;
    size_t signature_len = 0;
    if (message == NULL) {
        goto done;
    }

    uint64_t sign_start = pqtrust_now_ns(CLOCK_PROCESS_CPUTIME_ID);
    bool signed_ok = sign_message(
        key_case->private_key,
        message,
        (size_t)message_size,
        &signature,
        &signature_len
    );
    uint64_t sign_end = pqtrust_now_ns(CLOCK_PROCESS_CPUTIME_ID);
    if (!signed_ok) {
        goto done;
    }
    result.sign_time_ns = sign_end - sign_start;
    result.signature_size_bytes = signature_len;

    uint64_t verify_start = pqtrust_now_ns(CLOCK_PROCESS_CPUTIME_ID);
    result.verification_success = verify_message(
        key_case->public_key,
        message,
        (size_t)message_size,
        signature,
        signature_len
    );
    uint64_t verify_end = pqtrust_now_ns(CLOCK_PROCESS_CPUTIME_ID);
    result.verify_time_ns = verify_end - verify_start;

    if (message_size > 0) {
        message[0] ^= 0x01U;
        result.negative_self_test_passed = !verify_message(
            key_case->public_key,
            message,
            (size_t)message_size,
            signature,
            signature_len
        );
    }
    result.success = result.verification_success && result.negative_self_test_passed;
    result.error_code = result.success ? 0 : 2;

done:
    if (!result.success) {
        pqtrust_print_openssl_errors();
    }
    free(signature);
    free(message);
    return result;
}

static void write_record(
    FILE *out,
    int sequence,
    int block,
    int position,
    const char *algorithm,
    int message_size,
    const mldsa_result_t *result
)
{
    bool first = true;
    json_begin(out);
    json_int_field(out, &first, "schema_version", PQTRUST_SCHEMA_VERSION);
    json_string_field(out, &first, "benchmark", "mldsa");
    json_int_field(out, &first, "sequence", sequence);
    json_int_field(out, &first, "block", block);
    json_int_field(out, &first, "position_in_block", position);
    json_string_field(out, &first, "algorithm", algorithm);
    json_int_field(out, &first, "message_size_bytes", message_size);
    json_uint_field(out, &first, "sign_time_ns", result->sign_time_ns);
    json_uint_field(out, &first, "verify_time_ns", result->verify_time_ns);
    json_uint_field(out, &first, "signature_size_bytes", result->signature_size_bytes);
    json_bool_field(out, &first, "verification_success", result->verification_success);
    json_bool_field(out, &first, "negative_self_test_passed", result->negative_self_test_passed);
    json_bool_field(out, &first, "success", result->success);
    json_int_field(out, &first, "error_code", result->error_code);
    json_end(out);
    json_flush_line(out);
}

int main(int argc, char **argv)
{
    mldsa_args_t args;
    if (!parse_args(argc, argv, &args)) {
        usage();
        return 2;
    }

    key_case_t keys[2] = {
        {"ML-DSA-65", args.mldsa65_private, args.mldsa65_public, NULL, NULL},
        {"ML-DSA-87", args.mldsa87_private, args.mldsa87_public, NULL, NULL},
    };
    for (int i = 0; i < 2; i++) {
        keys[i].private_key = load_key(keys[i].private_path, true);
        keys[i].public_key = load_key(keys[i].public_path, false);
        if (keys[i].private_key == NULL || keys[i].public_key == NULL) {
            pqtrust_print_openssl_errors();
            return 1;
        }
    }

    for (int key_index = 0; key_index < 2; key_index++) {
        for (int size_index = 0; size_index < args.message_size_count; size_index++) {
            for (int w = 0; w < args.warmups; w++) {
                mldsa_result_t warmup = run_case(
                    &keys[key_index],
                    args.message_sizes[size_index],
                    -1 - w
                );
                if (!warmup.success) {
                    return 1;
                }
            }
        }
    }

    FILE *out = fopen(args.output, "w");
    if (out == NULL) {
        return 1;
    }
    size_t case_count = (size_t)(2 * args.message_size_count);
    size_t *order = calloc(case_count, sizeof(size_t));
    if (order == NULL) {
        fclose(out);
        return 1;
    }

    uint64_t rng = args.seed == 0 ? 1 : args.seed;
    int sequence = 0;
    int exit_code = 0;
    for (int block = 0; block < args.repetitions; block++) {
        for (size_t i = 0; i < case_count; i++) {
            order[i] = i;
        }
        pqtrust_shuffle(order, case_count, &rng);
        for (size_t pos = 0; pos < case_count; pos++) {
            size_t case_id = order[pos];
            int key_index = (int)(case_id / (size_t)args.message_size_count);
            int size_index = (int)(case_id % (size_t)args.message_size_count);
            mldsa_result_t result = run_case(
                &keys[key_index],
                args.message_sizes[size_index],
                sequence
            );
            write_record(
                out,
                sequence,
                block,
                (int)pos,
                keys[key_index].algorithm,
                args.message_sizes[size_index],
                &result
            );
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
        .warmups = args.warmups * (int)case_count,
        .measured_count = args.repetitions * (int)case_count,
        .seed = args.seed,
    };
    if (pqtrust_write_batch_metadata(args.output, argv[0], &metadata) != 0) {
        exit_code = 1;
    }

    free(order);
    for (int i = 0; i < 2; i++) {
        EVP_PKEY_free(keys[i].private_key);
        EVP_PKEY_free(keys[i].public_key);
    }
    pqtrust_free_csv(args.message_sizes_raw, args.message_size_count);
    free(args.message_sizes);
    return exit_code;
}
