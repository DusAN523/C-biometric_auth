/* biometric_app.c
   Multifactor auth mock (C, OpenSSL)
   Compile:
     gcc -O2 biometric_app.c -o biometric_app -lcrypto

   Usage:
     ./biometric_app add <user> <vector_file> <password>
     ./biometric_app verify <user> <vector_file> <password>
     ./biometric_app bench <user> <vector_file> <password> <runs>
     ./biometric_app brute_password <user> <vector_file> <max_pin_length>
     ./biometric_app perf_vectors <user> <password> <runs>  # tests various vector sizes

   Notes:
    - DB file: biometric_db.json (created/updated)
    - Biometric hashing: SHA-256(vector || salt)
    - Password hashing: PBKDF2-HMAC-SHA256(password, salt, iterations)
    - This is an educational mock. For production use vetted libs & secure storage.
*/

#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define DB_FILE "biometric_db.json"
#define SALT_LEN 16
#define PBKDF2_ITERS_DEFAULT 10000
#define PASSWORD_HASH_LEN 32 /* SHA256 output length */

/* ---------- Helpers ---------- */

static void handle_openssl_err(const char *msg) {
    fprintf(stderr, "OpenSSL error: %s\n", msg);
    ERR_print_errors_fp(stderr);
}

static void bytes_to_hex(const unsigned char *in, size_t inlen, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < inlen; ++i) {
        out[i*2]   = hex[(in[i] >> 4) & 0xF];
        out[i*2+1] = hex[in[i] & 0xF];
    }
    out[inlen*2] = '\0';
}

static int hex_to_bytes(const char *hex, unsigned char *out, size_t outlen) {
    size_t hexlen = strlen(hex);
    if (hexlen != outlen*2) return -1;
    for (size_t i = 0; i < outlen; ++i) {
        char a = hex[i*2], b = hex[i*2+1];
        int va = (isdigit(a) ? a-'0' : tolower(a)-'a'+10);
        int vb = (isdigit(b) ? b-'0' : tolower(b)-'a'+10);
        if (va < 0 || va > 15 || vb < 0 || vb > 15) return -1;
        out[i] = (unsigned char)((va<<4) | vb);
    }
    return 0;
}

static int const_time_cmp(const unsigned char *a, const unsigned char *b, size_t n) {
    unsigned char diff = 0;
    for (size_t i = 0; i < n; ++i) diff |= a[i] ^ b[i];
    return diff == 0;
}

static char *read_file_all(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)sz, f);
    buf[r] = '\0';
    fclose(f);
    return buf;
}

static int create_empty_db() {
    FILE *f = fopen(DB_FILE, "w");
    if (!f) return -1;
    fprintf(f, "[]\n");
    fclose(f);
    return 0;
}

/* Append JSON object to DB file (simple string editing) */
static int json_append_object(const char *obj_text) {
    char *db = read_file_all(DB_FILE);
    if (!db) {
        if (create_empty_db() != 0) return -1;
        db = read_file_all(DB_FILE);
        if (!db) return -1;
    }
    size_t len = strlen(db);
    while (len > 0 && isspace((unsigned char)db[len-1])) { db[len-1] = '\0'; --len; }
    if (len < 1 || db[len-1] != ']') { free(db); return -1; }

    FILE *f = fopen(DB_FILE, "w");
    if (!f) { free(db); return -1; }

    if (len == 2) { // "[]"
        fprintf(f, "[\n%s\n]\n", obj_text);
    } else {
        db[len-1] = '\0'; // remove ]
        fprintf(f, "%s,\n%s\n]\n", db, obj_text);
    }
    fclose(f);
    free(db);
    return 0;
}

/* Build JSON object text */
static char *build_json_object(const char *user, const char *salt_hex, const char *bio_hash_hex, const char *pwd_salt_hex, const char *pwd_hash_hex, int iters) {
    size_t needed = strlen(user) + strlen(salt_hex) + strlen(bio_hash_hex) + strlen(pwd_salt_hex) + strlen(pwd_hash_hex) + 400;
    char *s = malloc(needed);
    if (!s) return NULL;
    snprintf(s, needed,
        "  {\n"
        "    \"user\": \"%s\",\n"
        "    \"bio_salt\": \"%s\",\n"
        "    \"biometric_hash\": \"%s\",\n"
        "    \"pwd_salt\": \"%s\",\n"
        "    \"pwd_hash\": \"%s\",\n"
        "    \"pwd_iters\": %d\n"
        "  }", user, salt_hex, bio_hash_hex, pwd_salt_hex, pwd_hash_hex, iters);
    return s;
}

/* compute SHA-256 of vector_text || salt */
static void compute_sha256_with_salt(const char *vector_text, const unsigned char *salt, size_t saltlen, unsigned char out[SHA256_DIGEST_LENGTH]) {
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, (const unsigned char*)vector_text, strlen(vector_text));
    SHA256_Update(&ctx, salt, saltlen);
    SHA256_Final(out, &ctx);
}

/* compute PBKDF2-HMAC-SHA256(password, salt, iters) -> out (len bytes) */
static int compute_pbkdf2(const char *password, const unsigned char *salt, size_t saltlen, int iterations, unsigned char *out, size_t outlen) {
    if (PKCS5_PBKDF2_HMAC(password, strlen(password), salt, (int)saltlen, iterations, EVP_sha256(), (int)outlen, out) != 1) {
        handle_openssl_err("PKCS5_PBKDF2_HMAC failed");
        return -1;
    }
    return 0;
}

/* crude find record by user (simple parsing) */
static int find_record_by_user(const char *user, char *out_bio_salt_hex, char *out_bio_hash_hex, char *out_pwd_salt_hex, char *out_pwd_hash_hex, int *out_iters) {
    char *db = read_file_all(DB_FILE);
    if (!db) return 1;
    char pat[256];
    snprintf(pat, sizeof(pat), "\"user\": \"%s\"", user);
    char *p = strstr(db, pat);
    if (!p) { free(db); return 2; }

    /* helper lambda-like macros to parse a string value for a given key */
#define FIND_STRING_VALUE(start_ptr, key_literal, out_buf, expected_len, errcode_missing, errcode_len) do { \
        char *k = strstr((start_ptr), (key_literal)); \
        if (!(k)) { free(db); return (errcode_missing); } \
        char *colon = strchr(k, ':'); \
        if (!(colon)) { free(db); return (errcode_missing); } \
        char *val_start_quote = strchr(colon, '"'); \
        if (!(val_start_quote)) { free(db); return (errcode_missing); } \
        val_start_quote++; \
        char *val_end_quote = strchr(val_start_quote, '"'); \
        if (!(val_end_quote)) { free(db); return (errcode_missing); } \
        size_t vlen = (size_t)(val_end_quote - val_start_quote); \
        if ((expected_len) > 0 && vlen != (size_t)(expected_len)) { free(db); return (errcode_len); } \
        memcpy((out_buf), val_start_quote, vlen); \
        (out_buf)[vlen] = '\0'; \
    } while (0)

    /* bio_salt */
    FIND_STRING_VALUE(p, "\"bio_salt\":", out_bio_salt_hex, SALT_LEN*2, 3, 4);

    /* biometric_hash */
    FIND_STRING_VALUE(p, "\"biometric_hash\":", out_bio_hash_hex, SHA256_DIGEST_LENGTH*2, 5, 6);

    /* pwd_salt */
    FIND_STRING_VALUE(p, "\"pwd_salt\":", out_pwd_salt_hex, SALT_LEN*2, 7, 8);

    /* pwd_hash */
    FIND_STRING_VALUE(p, "\"pwd_hash\":", out_pwd_hash_hex, PASSWORD_HASH_LEN*2, 9, 10);

#undef FIND_STRING_VALUE

    /* pwd_iters (number) */
    {
        char *k = strstr(p, "\"pwd_iters\":");
        if (!k) { free(db); return 11; }
        int iters = 0;
        if (sscanf(k, "\"pwd_iters\": %d", &iters) != 1) { free(db); return 12; }
        *out_iters = iters;
    }

    free(db);
    return 0;
}

/* generate salt */
static int gen_salt(unsigned char *salt, size_t len) {
    if (RAND_bytes(salt, (int)len) != 1) {
        handle_openssl_err("RAND_bytes failed");
        return -1;
    }
    return 0;
}

/* trim newline */
static void trim_nl(char *s) {
    size_t l = strlen(s);
    while (l>0 && (s[l-1]=='\n' || s[l-1]=='\r')) { s[l-1]='\0'; --l; }
}

/* time utilities */
static double timespec_diff_ms(const struct timespec *a, const struct timespec *b) {
    double sec = (double)(a->tv_sec - b->tv_sec);
    double nsec = (double)(a->tv_nsec - b->tv_nsec);
    return sec*1000.0 + nsec/1e6;
}

/* ---------- Commands: add / verify / bench / brute ---------- */

static int cmd_add(const char *user, const char *vector_file, const char *password) {
    char *vec = read_file_all(vector_file);
    if (!vec) { fprintf(stderr, "Cannot read vector file '%s'\n", vector_file); return 1; }
    trim_nl(vec);

    if (access(DB_FILE, F_OK) != 0) {
        if (create_empty_db() != 0) { fprintf(stderr, "Cannot create DB file\n"); free(vec); return 1; }
    }

    unsigned char bio_salt[SALT_LEN];
    if (gen_salt(bio_salt, SALT_LEN) != 0) { free(vec); return 1; }

    unsigned char bio_hash[SHA256_DIGEST_LENGTH];
    compute_sha256_with_salt(vec, bio_salt, SALT_LEN, bio_hash);

    /* password: generate salt and PBKDF2 */
    unsigned char pwd_salt[SALT_LEN];
    if (gen_salt(pwd_salt, SALT_LEN) != 0) { free(vec); return 1; }

    unsigned char pwd_hash[PASSWORD_HASH_LEN];
    int iters = PBKDF2_ITERS_DEFAULT;
    if (compute_pbkdf2(password, pwd_salt, SALT_LEN, iters, pwd_hash, PASSWORD_HASH_LEN) != 0) {
        free(vec); return 1;
    }

    char bio_salt_hex[SALT_LEN*2+1], bio_hash_hex[SHA256_DIGEST_LENGTH*2+1];
    char pwd_salt_hex[SALT_LEN*2+1], pwd_hash_hex[PASSWORD_HASH_LEN*2+1];
    bytes_to_hex(bio_salt, SALT_LEN, bio_salt_hex);
    bytes_to_hex(bio_hash, SHA256_DIGEST_LENGTH, bio_hash_hex);
    bytes_to_hex(pwd_salt, SALT_LEN, pwd_salt_hex);
    bytes_to_hex(pwd_hash, PASSWORD_HASH_LEN, pwd_hash_hex);

    char *obj = build_json_object(user, bio_salt_hex, bio_hash_hex, pwd_salt_hex, pwd_hash_hex, iters);
    if (!obj) { free(vec); fprintf(stderr, "malloc failed\n"); return 1; }
    if (json_append_object(obj) != 0) { free(obj); free(vec); fprintf(stderr, "Failed to append to DB\n"); return 1; }

    printf("Registered user '%s'. (bio_salt=%s)\n", user, bio_salt_hex);
    free(obj);
    free(vec);
    return 0;
}

static int cmd_verify(const char *user, const char *vector_file, const char *password) {
    char *vec = read_file_all(vector_file);
    if (!vec) { fprintf(stderr, "Cannot read vector file '%s'\n", vector_file); return 1; }
    trim_nl(vec);

    char bio_salt_hex[SALT_LEN*2+1], bio_hash_hex[SHA256_DIGEST_LENGTH*2+1];
    char pwd_salt_hex[SALT_LEN*2+1], pwd_hash_hex[PASSWORD_HASH_LEN*2+1];
    int iters = 0;
    int r = find_record_by_user(user, bio_salt_hex, bio_hash_hex, pwd_salt_hex, pwd_hash_hex, &iters);
    if (r == 2) { fprintf(stderr, "User not found\n"); free(vec); return 2; }
    if (r != 0) { fprintf(stderr, "DB parse error %d\n", r); free(vec); return 3; }

    unsigned char bio_salt[SALT_LEN], stored_bio_hash[SHA256_DIGEST_LENGTH];
    if (hex_to_bytes(bio_salt_hex, bio_salt, SALT_LEN) != 0) { fprintf(stderr, "Invalid bio salt hex\n"); free(vec); return 4; }
    if (hex_to_bytes(bio_hash_hex, stored_bio_hash, SHA256_DIGEST_LENGTH) != 0) { fprintf(stderr, "Invalid bio hash hex\n"); free(vec); return 4; }

    unsigned char pwd_salt[SALT_LEN], stored_pwd_hash[PASSWORD_HASH_LEN];
    if (hex_to_bytes(pwd_salt_hex, pwd_salt, SALT_LEN) != 0) { fprintf(stderr, "Invalid pwd salt hex\n"); free(vec); return 4; }
    if (hex_to_bytes(pwd_hash_hex, stored_pwd_hash, PASSWORD_HASH_LEN) != 0) { fprintf(stderr, "Invalid pwd hash hex\n"); free(vec); return 4; }

    /* check password */
    unsigned char pwd_hash[PASSWORD_HASH_LEN];
    if (compute_pbkdf2(password, pwd_salt, SALT_LEN, iters, pwd_hash, PASSWORD_HASH_LEN) != 0) { free(vec); return 4; }
    if (!const_time_cmp(pwd_hash, stored_pwd_hash, PASSWORD_HASH_LEN)) {
        printf("Password incorrect. Authentication failed.\n");
        free(vec); return 5;
    }

    /* check biometric */
    unsigned char calc_bio_hash[SHA256_DIGEST_LENGTH];
    compute_sha256_with_salt(vec, bio_salt, SALT_LEN, calc_bio_hash);
    if (!const_time_cmp(calc_bio_hash, stored_bio_hash, SHA256_DIGEST_LENGTH)) {
        printf("Biometric vector does not match. Authentication failed.\n");
        free(vec); return 6;
    }

    printf("Authentication SUCCESS for user '%s'\n", user);
    free(vec);
    return 0;
}

/* Bench: run verify N times and report average times (ms) for password PBKDF2 and bio SHA256 */
static int cmd_bench(const char *user, const char *vector_file, const char *password, int runs) {
    if (runs <= 0) runs = 10;
    struct timespec t0, t1;
    double total_ms = 0.0;
    for (int i = 0; i < runs; ++i) {
        clock_gettime(CLOCK_MONOTONIC, &t0);
        int r = cmd_verify(user, vector_file, password);
        clock_gettime(CLOCK_MONOTONIC, &t1);
        double ms = timespec_diff_ms(&t1, &t0);
        printf("Run %d: verify took %.3f ms (ret %d)\n", i+1, ms, r);
        total_ms += ms;
    }
    printf("Average verify time over %d runs: %.3f ms\n", runs, total_ms / runs);
    return 0;
}

/* Brute force password simulation: try numeric PINs up to length max_pin_length (e.g., 4 or 6).
   This demonstrates how many attempts would be needed; uses same PBKDF2 cost as stored.
   Note: only for demo, stops when found.
*/
static int cmd_brute_password(const char *user, const char *vector_file, int max_pin_len) {
    if (max_pin_len <= 0) max_pin_len = 4;
    char bio_salt_hex[SALT_LEN*2+1], bio_hash_hex[SHA256_DIGEST_LENGTH*2+1];
    char pwd_salt_hex[SALT_LEN*2+1], pwd_hash_hex[PASSWORD_HASH_LEN*2+1];
    int iters = 0;
    int r = find_record_by_user(user, bio_salt_hex, bio_hash_hex, pwd_salt_hex, pwd_hash_hex, &iters);
    if (r) { fprintf(stderr, "User not found or DB error\n"); return 1; }

    unsigned char pwd_salt[SALT_LEN], stored_pwd_hash[PASSWORD_HASH_LEN];
    if (hex_to_bytes(pwd_salt_hex, pwd_salt, SALT_LEN) != 0) { fprintf(stderr, "Invalid pwd salt hex\n"); return 1; }
    if (hex_to_bytes(pwd_hash_hex, stored_pwd_hash, PASSWORD_HASH_LEN) != 0) { fprintf(stderr, "Invalid pwd hash hex\n"); return 1; }

    /* brute force numeric PINs */
    long total_attempts = 0;
    struct timespec tstart, tend;
    clock_gettime(CLOCK_MONOTONIC, &tstart);

    for (int len = 1; len <= max_pin_len; ++len) {
        long limit = 1;
        for (int i = 0; i < len; ++i) limit *= 10;
        for (long n = 0; n < limit; ++n) {
            /* build zero-padded PIN string */
            char pin[32]; snprintf(pin, sizeof(pin), "%0*ld", len, n);
            unsigned char attempt_hash[PASSWORD_HASH_LEN];
            if (compute_pbkdf2(pin, pwd_salt, SALT_LEN, iters, attempt_hash, PASSWORD_HASH_LEN) != 0) {
                fprintf(stderr, "PBKDF2 failure\n"); return 1;
            }
            total_attempts++;
            if (const_time_cmp(attempt_hash, stored_pwd_hash, PASSWORD_HASH_LEN)) {
                clock_gettime(CLOCK_MONOTONIC, &tend);
                double ms = timespec_diff_ms(&tend, &tstart);
                printf("Found password (PIN) = '%s' after %ld attempts, time %.3f ms\n", pin, total_attempts, ms);
                return 0;
            }
        }
    }
    clock_gettime(CLOCK_MONOTONIC, &tend);
    double ms = timespec_diff_ms(&tend, &tstart);
    printf("Not found up to length %d after %ld attempts, time %.3f ms\n", max_pin_len, total_attempts, ms);
    return 0;
}

/* perf_vectors: generate vectors of increasing size and measure bio-hash time */
static int cmd_perf_vectors(const char *user, const char *password, int runs) {
    /* generate vectors of sizes: 10, 100, 1000, 5000 bytes */
    int sizes[] = {10, 100, 1000, 5000};
    for (size_t si = 0; si < sizeof(sizes)/sizeof(sizes[0]); ++si) {
        int s = sizes[si];
        /* build synthetic vector: comma-separated floats to approx s chars */
        char *vec = malloc((size_t)s + 50);
        if (!vec) return 1;
        vec[0] = '\0';
        while ((int)strlen(vec) < s) {
            strcat(vec, "0.1234,");
        }
        vec[s] = '\0';
        struct timespec t0, t1;
        double total_ms = 0.0;
        for (int r = 0; r < runs; ++r) {
            unsigned char salt[SALT_LEN];
            if (gen_salt(salt, SALT_LEN) != 0) { free(vec); return 1; }
            clock_gettime(CLOCK_MONOTONIC, &t0);
            unsigned char out_hash[SHA256_DIGEST_LENGTH];
            compute_sha256_with_salt(vec, salt, SALT_LEN, out_hash);
            clock_gettime(CLOCK_MONOTONIC, &t1);
            total_ms += timespec_diff_ms(&t1, &t0);
        }
        printf("Vector size %d bytes: avg SHA256 time over %d runs: %.3f ms\n", s, runs, total_ms / runs);
        free(vec);
    }
    return 0;
}

/* ---------- Main ---------- */

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage:\n  %s add <user> <vector_file> <password>\n  %s verify <user> <vector_file> <password>\n  %s bench <user> <vector_file> <password> <runs>\n  %s brute_password <user> <vector_file> <max_pin_len>\n  %s perf_vectors <user> <password> <runs>\n", argv[0], argv[0], argv[0], argv[0], argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    const char *cmd = argv[1];
    int ret = 0;
    if (strcmp(cmd, "add") == 0) {
        if (argc != 5) { fprintf(stderr, "add requires 3 args\n"); return 1; }
        ret = cmd_add(argv[2], argv[3], argv[4]);
    } else if (strcmp(cmd, "verify") == 0) {
        if (argc != 5) { fprintf(stderr, "verify requires 3 args\n"); return 1; }
        ret = cmd_verify(argv[2], argv[3], argv[4]);
    } else if (strcmp(cmd, "bench") == 0) {
        if (argc != 6) { fprintf(stderr, "bench requires 4 args\n"); return 1; }
        int runs = atoi(argv[5]);
        ret = cmd_bench(argv[2], argv[3], argv[4], runs);
    } else if (strcmp(cmd, "brute_password") == 0) {
        if (argc != 5) { fprintf(stderr, "brute_password requires 3 args\n"); return 1; }
        int maxlen = atoi(argv[4]);
        ret = cmd_brute_password(argv[2], argv[3], maxlen);
    } else if (strcmp(cmd, "perf_vectors") == 0) {
        if (argc != 4 && argc !=5) { fprintf(stderr, "perf_vectors requires 2 or 3 args\n"); return 1; }
        int runs = (argc==5) ? atoi(argv[4]) : 10;
        ret = cmd_perf_vectors(argv[2], argv[3], runs);
    } else {
        fprintf(stderr, "Unknown command '%s'\n", cmd);
        ret = 1;
    }

    EVP_cleanup();
    ERR_free_strings();
    return ret;
}
