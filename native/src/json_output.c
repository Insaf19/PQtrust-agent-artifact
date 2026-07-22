#include "json_output.h"

#include <stdio.h>

bool json_string_is_valid(const char *value)
{
    if (value == NULL) {
        return true;
    }
    const unsigned char *p = (const unsigned char *)value;
    while (*p != '\0') {
        if (*p < 0x20U) {
            return false;
        }
        if (*p < 0x80U) {
            p++;
        } else if ((*p & 0xE0U) == 0xC0U) {
            if (p[1] == '\0') {
                return false;
            }
            if ((p[1] & 0xC0U) != 0x80U || *p < 0xC2U) {
                return false;
            }
            p += 2;
        } else if ((*p & 0xF0U) == 0xE0U) {
            if (p[1] == '\0' || p[2] == '\0') {
                return false;
            }
            if ((p[1] & 0xC0U) != 0x80U || (p[2] & 0xC0U) != 0x80U) {
                return false;
            }
            if ((*p == 0xE0U && p[1] < 0xA0U) || (*p == 0xEDU && p[1] >= 0xA0U)) {
                return false;
            }
            p += 3;
        } else if ((*p & 0xF8U) == 0xF0U) {
            if (p[1] == '\0' || p[2] == '\0' || p[3] == '\0') {
                return false;
            }
            if ((p[1] & 0xC0U) != 0x80U || (p[2] & 0xC0U) != 0x80U
                || (p[3] & 0xC0U) != 0x80U) {
                return false;
            }
            if ((*p == 0xF0U && p[1] < 0x90U) || (*p == 0xF4U && p[1] >= 0x90U)
                || *p > 0xF4U) {
                return false;
            }
            p += 4;
        } else {
            return false;
        }
    }
    return true;
}

static void json_escaped(FILE *out, const char *value)
{
    fputc('"', out);
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", out);
            break;
        case '\\':
            fputs("\\\\", out);
            break;
        case '\b':
            fputs("\\b", out);
            break;
        case '\f':
            fputs("\\f", out);
            break;
        case '\n':
            fputs("\\n", out);
            break;
        case '\r':
            fputs("\\r", out);
            break;
        case '\t':
            fputs("\\t", out);
            break;
        default:
            if (*p < 0x20U) {
                fprintf(out, "\\u%04x", *p);
            } else {
                fputc((int)*p, out);
            }
            break;
        }
    }
    fputc('"', out);
}

void json_begin(FILE *out)
{
    fputc('{', out);
}

void json_end(FILE *out)
{
    fputc('}', out);
}

void json_comma(FILE *out, bool *first)
{
    if (*first) {
        *first = false;
    } else {
        fputc(',', out);
    }
}

bool json_string_field(FILE *out, bool *first, const char *name, const char *value)
{
    if (!json_string_is_valid(name) || !json_string_is_valid(value)) {
        return false;
    }
    json_comma(out, first);
    json_escaped(out, name);
    fputc(':', out);
    json_escaped(out, value == NULL ? "" : value);
    return true;
}

void json_int_field(FILE *out, bool *first, const char *name, long long value)
{
    json_comma(out, first);
    json_escaped(out, name);
    fprintf(out, ":%lld", value);
}

void json_uint_field(FILE *out, bool *first, const char *name, unsigned long long value)
{
    json_comma(out, first);
    json_escaped(out, name);
    fprintf(out, ":%llu", value);
}

void json_bool_field(FILE *out, bool *first, const char *name, bool value)
{
    json_comma(out, first);
    json_escaped(out, name);
    fputc(':', out);
    fputs(value ? "true" : "false", out);
}

bool json_string_array_field(
    FILE *out,
    bool *first,
    const char *name,
    int argc,
    char **argv
)
{
    if (!json_string_is_valid(name)) {
        return false;
    }
    for (int i = 0; i < argc; i++) {
        if (!json_string_is_valid(argv[i])) {
            return false;
        }
    }
    json_comma(out, first);
    json_escaped(out, name);
    fputs(":[", out);
    for (int i = 0; i < argc; i++) {
        if (i > 0) {
            fputc(',', out);
        }
        json_escaped(out, argv[i]);
    }
    fputc(']', out);
    return true;
}

void json_flush_line(FILE *out)
{
    fputc('\n', out);
    fflush(out);
}
