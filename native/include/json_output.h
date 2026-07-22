#ifndef PQTRUST_JSON_OUTPUT_H
#define PQTRUST_JSON_OUTPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

bool json_string_is_valid(const char *value);
void json_begin(FILE *out);
void json_end(FILE *out);
void json_comma(FILE *out, bool *first);
bool json_string_field(FILE *out, bool *first, const char *name, const char *value);
void json_int_field(FILE *out, bool *first, const char *name, long long value);
void json_uint_field(FILE *out, bool *first, const char *name, unsigned long long value);
void json_bool_field(FILE *out, bool *first, const char *name, bool value);
bool json_string_array_field(
    FILE *out,
    bool *first,
    const char *name,
    int argc,
    char **argv
);
void json_flush_line(FILE *out);

#endif
