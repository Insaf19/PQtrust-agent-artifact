CC ?= gcc
OPENSSL_PREFIX ?=
BUILD_DIR ?= ../.build/native
SANITIZE_BUILD_DIR ?= ../.build/native-sanitize

CFLAGS := -std=c17 -D_GNU_SOURCE -O3 -Wall -Wextra -Werror -pedantic
SANITIZE_CFLAGS := -std=c17 -D_GNU_SOURCE -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wextra -Werror -pedantic
CPPFLAGS := -Iinclude -I$(OPENSSL_PREFIX)/include
LDFLAGS := -L$(OPENSSL_PREFIX)/lib -Wl,-rpath,$(OPENSSL_PREFIX)/lib
SANITIZE_LDFLAGS := $(LDFLAGS) -fsanitize=address,undefined
LDLIBS := -lssl -lcrypto

COMMON := src/bench_common.c src/json_output.c
TLS_SRC := src/tls_handshake_bench.c $(COMMON)
MLDSA_SRC := src/mldsa_bench.c $(COMMON)
GROUP_SELFTEST_SRC := src/group_name_selftest.c $(COMMON)

.PHONY: build clean check-prefix group-name-selftest sanitize

build: check-prefix $(BUILD_DIR)/tls_handshake_bench $(BUILD_DIR)/mldsa_bench

sanitize: check-prefix $(SANITIZE_BUILD_DIR)/tls_handshake_bench $(SANITIZE_BUILD_DIR)/mldsa_bench

group-name-selftest: $(BUILD_DIR)/group_name_selftest
	"$<"

check-prefix:
	@test -n "$(OPENSSL_PREFIX)" || { echo "OPENSSL_PREFIX is required"; exit 2; }
	@test -x "$(OPENSSL_PREFIX)/bin/openssl"
	@test -d "$(OPENSSL_PREFIX)/include"
	@test -d "$(OPENSSL_PREFIX)/lib"

$(BUILD_DIR):
	mkdir -p "$(BUILD_DIR)"

$(SANITIZE_BUILD_DIR):
	mkdir -p "$(SANITIZE_BUILD_DIR)"

$(BUILD_DIR)/tls_handshake_bench: $(TLS_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TLS_SRC) $(LDFLAGS) $(LDLIBS) -o "$@"

$(BUILD_DIR)/mldsa_bench: $(MLDSA_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(MLDSA_SRC) $(LDFLAGS) $(LDLIBS) -o "$@"

$(BUILD_DIR)/group_name_selftest: $(GROUP_SELFTEST_SRC) | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(GROUP_SELFTEST_SRC) $(LDFLAGS) $(LDLIBS) -o "$@"

$(SANITIZE_BUILD_DIR)/tls_handshake_bench: $(TLS_SRC) | $(SANITIZE_BUILD_DIR)
	$(CC) $(SANITIZE_CFLAGS) $(CPPFLAGS) $(TLS_SRC) $(SANITIZE_LDFLAGS) $(LDLIBS) -o "$@"

$(SANITIZE_BUILD_DIR)/mldsa_bench: $(MLDSA_SRC) | $(SANITIZE_BUILD_DIR)
	$(CC) $(SANITIZE_CFLAGS) $(CPPFLAGS) $(MLDSA_SRC) $(SANITIZE_LDFLAGS) $(LDLIBS) -o "$@"

clean:
	rm -rf "$(BUILD_DIR)" "$(SANITIZE_BUILD_DIR)"
