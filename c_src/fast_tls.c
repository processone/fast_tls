/*
 * Copyright (C) 2002-2017 ProcessOne, SARL. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <string.h>
#include <erl_nif.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include "options.h"
#include "hashmap.h"

#define BUF_SIZE 1024

#define enif_alloc malloc
#define enif_free free
#define enif_realloc realloc

typedef struct {
    BIO *bio_read;
    BIO *bio_write;
    SSL *ssl;
    int handshakes;
    ErlNifMutex *mtx;
    int valid;
    char *send_buffer;
    int send_buffer_size;
    int send_buffer_len;
    char *send_buffer2;
    int send_buffer2_size;
    int send_buffer2_len;
} state_t;

static int ssl_index;

#ifdef _WIN32
typedef unsigned __int32 uint32_t;
#endif

#ifndef SSL_OP_NO_TICKET
#define SSL_OP_NO_TICKET 0
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define DH_set0_pqg(dh, dh_p, param, dh_g) (dh)->p = dh_p; (dh)->g = dh_g
#endif

#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define our_alloc enif_alloc
#define our_realloc enif_realloc
#define our_free enif_free
#else
static void *our_alloc(size_t size, const char *file, int line) {
    return enif_alloc(size);
}
static void * our_realloc(void *ptr, size_t size, const char *file, int line) {
    return enif_realloc(ptr, size);
}

static void our_free(void *ptr, const char *file, int line) {
    enif_free(ptr);
}
#endif


#define CIPHERS "DEFAULT:!EXPORT:!LOW:!RC4:!SSLv2"

static ErlNifResourceType *tls_state_t = NULL;
static ErlNifMutex **mtx_buf = NULL;

/**
 * Prepare the SSL options flag.
 **/
static int set_option_flag(const unsigned char *opt, size_t len, long *flag) {
    ssl_option_t *p;
    for (p = ssl_options; p->name; p++) {
        if (!memcmp(opt, p->name, len) && p->name[len] == '\0') {
            *flag |= p->code;
            return 1;
        }
    }
    return 0;
}

hashmap_t *certs_map;

typedef struct {
    char *key;
    time_t key_mtime;
    time_t dh_mtime;
    time_t ca_mtime;
    SSL_CTX *ssl_ctx;
} cert_info_t;

/*
 * str_hash is based on the public domain code from
 * http://www.burtleburtle.net/bob/hash/doobs.html
 */
static uint32_t cert_hash(const void *data) {
    unsigned char *key = (unsigned char *) ((cert_info_t *) data)->key;
    uint32_t hash = 0;
    size_t i;

    for (i = 0; key[i] != 0; i++) {
        hash += key[i];
        hash += (hash << 10);
        hash ^= (hash >> 6);
    }
    hash += (hash << 3);
    hash ^= (hash >> 11);
    hash += (hash << 15);

    return hash;
}

static int cert_cmp(const void *c1, const void *c2) {
    return strcmp(((cert_info_t *) c1)->key, ((cert_info_t *) c2)->key) == 0;
}

static state_t *init_tls_state() {
    state_t *state = enif_alloc_resource(tls_state_t, sizeof(state_t));
    if (!state) return NULL;
    memset(state, 0, sizeof(state_t));
    state->mtx = enif_mutex_create("");
    if (!state->mtx) return NULL;
    state->valid = 1;
    return state;
}

static void destroy_tls_state(ErlNifEnv *env, void *data) {
    state_t *state = (state_t *) data;
    if (state) {
        if (state->ssl)
            SSL_free(state->ssl);
        if (state->mtx)
            enif_mutex_destroy(state->mtx);
        if (state->send_buffer)
            enif_free(state->send_buffer);
        if (state->send_buffer2)
            enif_free(state->send_buffer2);
        memset(state, 0, sizeof(state_t));
    }
}

static void locking_callback(int mode, int n, const char *file, int line) {
    if (mode & CRYPTO_LOCK)
        enif_mutex_lock(mtx_buf[n]);
    else
        enif_mutex_unlock(mtx_buf[n]);
}

static void thread_id_callback(CRYPTO_THREADID *id) {
    CRYPTO_THREADID_set_pointer(id, enif_thread_self());
}

static int atomic_add_callback(int *pointer, int amount, int type, const char *file, int line) {
    return __sync_add_and_fetch(pointer, amount);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000L

static LHASH_OF(ERR_STRING_DATA) *cb_err_get(int create) {
    return NULL;
}

static void cb_err_del(void) {
}

static hashmap_t *err_string_map;

static uint32_t get_err_data_hash(const void *el) {
    return (uint32_t) (*(ERR_STRING_DATA **) el)->error;
}

static int get_err_data_cmp(const void *el1, const void *el2) {
    return (*(ERR_STRING_DATA **) el1)->error == (*(ERR_STRING_DATA **) el2)->error;
}

static ERR_STRING_DATA *cb_err_get_item(const ERR_STRING_DATA *d) {
    ERR_STRING_DATA **p = (ERR_STRING_DATA **) hashmap_lookup(err_string_map, &d);
    if (p)
        return *p;

    return NULL;
}

static ERR_STRING_DATA *cb_err_set_item(ERR_STRING_DATA *d) {
    ERR_STRING_DATA *old_data;
    int used = hashmap_insert(err_string_map, &d, &old_data);

    if (used == 1)
        return old_data;

    return NULL;
}

static ERR_STRING_DATA *cb_err_del_item(ERR_STRING_DATA *d) {
    ERR_STRING_DATA *old_data;
    int used = hashmap_remove(err_string_map, &d, &old_data);

    if (used == 1)
        return old_data;

    return NULL;
}

static LHASH_OF(ERR_STATE) *cb_thread_get(int create) {
    return NULL;
}

static void cb_thread_release(LHASH_OF(ERR_STATE) **hash) {
}

static ErlNifTSDKey err_funs_tls_key;

static ERR_STATE *cb_thread_get_item(const ERR_STATE *ARG) {
    return enif_tsd_get(err_funs_tls_key);
}

static ERR_STATE *cb_thread_set_item(ERR_STATE *ARG) {
    void *prev_val = enif_tsd_get(err_funs_tls_key);
    enif_tsd_set(err_funs_tls_key, ARG);

    return prev_val;
}

static void cb_thread_del_item(const ERR_STATE *ARG) {
    // Do nothing functions for freeing are not exported, we will leak
    // memory but only one struct per destroyed thread, and erlang don't do that much
}

static int cb_get_next_lib(void) {
    static int id = ERR_LIB_USER;
    return __sync_add_and_fetch(&id, 1);
}

void tls_item_delete(void *A) {
    // Do nothing, openssl don't export free function for those objects
}

struct priv_ERR_FNS {
    /* Works on the "error_hash" string table */
    LHASH_OF(ERR_STRING_DATA) *(*cb_err_get)(int create);

    void (*cb_err_del)(void);

    ERR_STRING_DATA *(*cb_err_get_item)(const ERR_STRING_DATA *);

    ERR_STRING_DATA *(*cb_err_set_item)(ERR_STRING_DATA *);

    ERR_STRING_DATA *(*cb_err_del_item)(ERR_STRING_DATA *);
    /* Works on the "thread_hash" error-state table */
    LHASH_OF(ERR_STATE) *(*cb_thread_get)(int create);

    void (*cb_thread_release)(LHASH_OF(ERR_STATE) **hash);

    ERR_STATE *(*cb_thread_get_item)(const ERR_STATE *);

    ERR_STATE *(*cb_thread_set_item)(ERR_STATE *);

    void (*cb_thread_del_item)(const ERR_STATE *);

    /* Returns the next available error "library" numbers */
    int (*cb_get_next_lib)(void);
};

static struct priv_ERR_FNS err_fns_impl = {
        cb_err_get,
        cb_err_del,
        cb_err_get_item,
        cb_err_set_item,
        cb_err_del_item,
        cb_thread_get,
        cb_thread_release,
        cb_thread_get_item,
        cb_thread_set_item,
        cb_thread_del_item,
        cb_get_next_lib
};
#endif

static int load(ErlNifEnv *env, void **priv, ERL_NIF_TERM load_info) {
    int i;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    err_string_map = hashmap_new(1024, sizeof(ERR_STRING_DATA *), get_err_data_hash, get_err_data_cmp);

    /* THIS MAY CRASH AFTER OPNESSL UPGRADE

       We are using somewhat private structures of openssl to do this, if our priv_ERR_FNS wouldn't match
       version included in openssl it will cause problem.
     */
    enif_tsd_key_create("openssl_err_funs_key", &err_funs_tls_key);
    ERR_set_implementation((const ERR_FNS *) &err_fns_impl);
#endif

    CRYPTO_set_mem_functions(our_alloc, our_realloc, our_free);
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    mtx_buf = enif_alloc(CRYPTO_num_locks() * sizeof(ErlNifMutex *));
    for (i = 0; i < CRYPTO_num_locks(); i++)
        mtx_buf[i] = enif_mutex_create("");

    CRYPTO_set_add_lock_callback(atomic_add_callback);
    CRYPTO_set_locking_callback(locking_callback);
    CRYPTO_THREADID_set_callback(thread_id_callback);

    certs_map = hashmap_new(16, sizeof(cert_info_t), cert_hash, cert_cmp);

    ssl_index = SSL_get_ex_new_index(0, "ssl index", NULL, NULL, NULL);
    ErlNifResourceFlags flags = ERL_NIF_RT_CREATE | ERL_NIF_RT_TAKEOVER;
    tls_state_t = enif_open_resource_type(env, NULL, "tls_state_t",
                                          destroy_tls_state,
                                          flags, NULL);
    return 0;
}

static void unload(ErlNifEnv *env, void *priv) {
    int i;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    hashmap_free(err_string_map);
#endif
    hashmap_free(certs_map);

    for (i = 0; i < CRYPTO_num_locks(); i++)
        enif_mutex_destroy(mtx_buf[i]);
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    OPENSSL_cleanup();
#endif
}

static int is_modified(char *file, time_t *known_mtime) {
    struct stat file_stat;

    if (file == NULL) {
        return 0;
    } else if (stat(file, &file_stat)) {
        *known_mtime = 0;
        return 1;
    } else {
        if (*known_mtime != file_stat.st_mtime) {
            *known_mtime = file_stat.st_mtime;
            return 1;
        } else
            return 0;
    }
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    return 1;
}

/*
 * ECDHE is enabled only on OpenSSL 1.0.0e and later.
 * See http://www.openssl.org/news/secadv_20110906.txt
 * for details.
 */
#ifndef OPENSSL_NO_ECDH

static void setup_ecdh(SSL_CTX *ctx) {
    EC_KEY *ecdh;

    if (SSLeay() < 0x1000005fL) {
        return;
    }

    ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_ECDH_USE);
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);

    EC_KEY_free(ecdh);
}

#endif

#ifndef OPENSSL_NO_DH
/*
1024-bit MODP Group with 160-bit prime order subgroup (RFC5114)
-----BEGIN DH PARAMETERS-----
MIIBDAKBgQCxC4+WoIDgHd6S3l6uXVTsUsmfvPsGo8aaap3KUtI7YWBz4oZ1oj0Y
mDjvHi7mUsAT7LSuqQYRIySXXDzUm4O/rMvdfZDEvXCYSI6cIZpzck7/1vrlZEc4
+qMaT/VbzMChUa9fDci0vUW/N982XBpl5oz9p21NpwjfH7K8LkpDcQKBgQCk0cvV
w/00EmdlpELvuZkF+BBN0lisUH/WQGz/FCZtMSZv6h5cQVZLd35pD1UE8hMWAhe0
sBuIal6RVH+eJ0n01/vX07mpLuGQnQ0iY/gKdqaiTAh6CR9THb8KAWm2oorWYqTR
jnOvoy13nVkY0IvIhY9Nzvl8KiSFXm7rIrOy5QICAKA=
-----END DH PARAMETERS-----
 */
static unsigned char dh1024_p[] = {
        0xB1, 0x0B, 0x8F, 0x96, 0xA0, 0x80, 0xE0, 0x1D, 0xDE, 0x92, 0xDE, 0x5E,
        0xAE, 0x5D, 0x54, 0xEC, 0x52, 0xC9, 0x9F, 0xBC, 0xFB, 0x06, 0xA3, 0xC6,
        0x9A, 0x6A, 0x9D, 0xCA, 0x52, 0xD2, 0x3B, 0x61, 0x60, 0x73, 0xE2, 0x86,
        0x75, 0xA2, 0x3D, 0x18, 0x98, 0x38, 0xEF, 0x1E, 0x2E, 0xE6, 0x52, 0xC0,
        0x13, 0xEC, 0xB4, 0xAE, 0xA9, 0x06, 0x11, 0x23, 0x24, 0x97, 0x5C, 0x3C,
        0xD4, 0x9B, 0x83, 0xBF, 0xAC, 0xCB, 0xDD, 0x7D, 0x90, 0xC4, 0xBD, 0x70,
        0x98, 0x48, 0x8E, 0x9C, 0x21, 0x9A, 0x73, 0x72, 0x4E, 0xFF, 0xD6, 0xFA,
        0xE5, 0x64, 0x47, 0x38, 0xFA, 0xA3, 0x1A, 0x4F, 0xF5, 0x5B, 0xCC, 0xC0,
        0xA1, 0x51, 0xAF, 0x5F, 0x0D, 0xC8, 0xB4, 0xBD, 0x45, 0xBF, 0x37, 0xDF,
        0x36, 0x5C, 0x1A, 0x65, 0xE6, 0x8C, 0xFD, 0xA7, 0x6D, 0x4D, 0xA7, 0x08,
        0xDF, 0x1F, 0xB2, 0xBC, 0x2E, 0x4A, 0x43, 0x71,
};
static unsigned char dh1024_g[] = {
        0xA4, 0xD1, 0xCB, 0xD5, 0xC3, 0xFD, 0x34, 0x12, 0x67, 0x65, 0xA4, 0x42,
        0xEF, 0xB9, 0x99, 0x05, 0xF8, 0x10, 0x4D, 0xD2, 0x58, 0xAC, 0x50, 0x7F,
        0xD6, 0x40, 0x6C, 0xFF, 0x14, 0x26, 0x6D, 0x31, 0x26, 0x6F, 0xEA, 0x1E,
        0x5C, 0x41, 0x56, 0x4B, 0x77, 0x7E, 0x69, 0x0F, 0x55, 0x04, 0xF2, 0x13,
        0x16, 0x02, 0x17, 0xB4, 0xB0, 0x1B, 0x88, 0x6A, 0x5E, 0x91, 0x54, 0x7F,
        0x9E, 0x27, 0x49, 0xF4, 0xD7, 0xFB, 0xD7, 0xD3, 0xB9, 0xA9, 0x2E, 0xE1,
        0x90, 0x9D, 0x0D, 0x22, 0x63, 0xF8, 0x0A, 0x76, 0xA6, 0xA2, 0x4C, 0x08,
        0x7A, 0x09, 0x1F, 0x53, 0x1D, 0xBF, 0x0A, 0x01, 0x69, 0xB6, 0xA2, 0x8A,
        0xD6, 0x62, 0xA4, 0xD1, 0x8E, 0x73, 0xAF, 0xA3, 0x2D, 0x77, 0x9D, 0x59,
        0x18, 0xD0, 0x8B, 0xC8, 0x85, 0x8F, 0x4D, 0xCE, 0xF9, 0x7C, 0x2A, 0x24,
        0x85, 0x5E, 0x6E, 0xEB, 0x22, 0xB3, 0xB2, 0xE5,
};

static int setup_dh(SSL_CTX *ctx, char *dh_file) {
    DH *dh;
    int res;

    if (dh_file != NULL) {
        BIO *bio = BIO_new_file(dh_file, "r");

        if (bio == NULL) {
            return 0;
        }
        dh = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
        BIO_free(bio);
        if (dh == NULL) {
            return 0;
        }
    } else {
        dh = DH_new();
        if (dh == NULL) {
            return 0;
        }
        BIGNUM *dh_p = BN_bin2bn(dh1024_p, sizeof(dh1024_p), NULL);
        BIGNUM *dh_g = BN_bin2bn(dh1024_g, sizeof(dh1024_g), NULL);
        if (dh_p == NULL || dh_g == NULL) {
            BN_free(dh_p);
            BN_free(dh_g);
            DH_free(dh);
            return 0;
        }

        DH_set0_pqg(dh, dh_p, NULL, dh_g);
    }

    SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
    res = (int) SSL_CTX_set_tmp_dh(ctx, dh);

    DH_free(dh);
    return res;
}

#endif

static void ssl_info_callback(const SSL *s, int where, int ret) {
    state_t *d = (state_t *) SSL_get_ex_data(s, ssl_index);
    if ((where & SSL_CB_HANDSHAKE_START) && d->handshakes) {
        d->handshakes++;
    } else if ((where & SSL_CB_HANDSHAKE_DONE) && !d->handshakes) {
        d->handshakes++;
    }
}

#define ERR_T(T) enif_make_tuple2(env, enif_make_atom(env, "error"), T)
#define OK_T(T) enif_make_tuple2(env, enif_make_atom(env, "ok"), T)
#define SEND_T(T) enif_make_tuple2(env, enif_make_atom(env, "send"), T)

#define SET_CERTIFICATE_FILE_ACCEPT 1
#define SET_CERTIFICATE_FILE_CONNECT 2
#define VERIFY_NONE 0x10000
#define COMPRESSION_NONE 0x100000

static ERL_NIF_TERM ssl_error(ErlNifEnv *env, const char *errstr) {
    size_t rlen;
    ErlNifBinary err;
    size_t errstrlen = strlen(errstr);
    unsigned long error_code = ERR_get_error();
    char *error_string = error_code ? ERR_error_string(error_code, NULL) : NULL;
    size_t error_string_length = error_string ? strlen(error_string) : 0;
    if (error_code)
        rlen = errstrlen + error_string_length + 2;
    else
        rlen = errstrlen;
    enif_alloc_binary(rlen, &err);
    memcpy(err.data, errstr, errstrlen);
    if (error_code) {
        memcpy(err.data + errstrlen, ": ", 2);
        memcpy(err.data + 2 + errstrlen, error_string, error_string_length);
    }
    return ERR_T(enif_make_binary(env, &err));
}

static char *create_ssl_for_cert(char *key_file, char *ciphers, char *dh_file,
                                 char *ca_file, char *key, SSL **retval) {
    hashmap_lock(certs_map, 0);

    cert_info_t info, old_info;
    info.key = key;

    cert_info_t *tmp = hashmap_lookup_no_lock(certs_map, &key);

    if (tmp)
        info = *tmp;
    else {
        info.ssl_ctx = NULL;
        info.key_mtime = 0;
        info.dh_mtime = 0;
        info.ca_mtime = 0;
    }

    time_t key_mtime = info.key_mtime;
    time_t dh_mtime = info.dh_mtime;
    time_t ca_mtime = info.ca_mtime;

    if (strlen(dh_file) == 0)
        dh_file = NULL;

    if (strlen(ca_file) == 0)
        ca_file = NULL;

    if (is_modified(key_file, &key_mtime) ||
        is_modified(dh_file, &dh_mtime) ||
        is_modified(ca_file, &ca_mtime) ||
        info.ssl_ctx == NULL) {
        hashmap_unlock(certs_map, 0);

        hashmap_lock(certs_map, 1);

        tmp = hashmap_lookup_no_lock(certs_map, &key);
        if (!tmp || (tmp->ssl_ctx == info.ssl_ctx &&
                     tmp->key_mtime == info.key_mtime &&
                     tmp->dh_mtime == info.dh_mtime &&
                     tmp->ca_mtime == info.ca_mtime)) {
            if (info.ssl_ctx)
                SSL_CTX_free(info.ssl_ctx);

            SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
            if (!ctx) {
                hashmap_unlock(certs_map, 1);
                return "SSL_CTX_new failed";
            }

            int res = SSL_CTX_use_certificate_chain_file(ctx, key_file);
            if (res <= 0) {
                hashmap_unlock(certs_map, 1);
                return "SSL_CTX_use_certificate_file failed";
            }

            res = SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM);
            if (res <= 0) {
                hashmap_unlock(certs_map, 1);
                return "SSL_CTX_use_PrivateKey_file failed";
            }

            res = SSL_CTX_check_private_key(ctx);
            if (res <= 0) {
                hashmap_unlock(certs_map, 1);
                return "SSL_CTX_check_private_key failed";
            }

            if (ciphers[0] == 0)
                SSL_CTX_set_cipher_list(ctx, CIPHERS);
            else
                SSL_CTX_set_cipher_list(ctx, ciphers);


#ifndef OPENSSL_NO_ECDH
            setup_ecdh(ctx);
#endif
#ifndef OPENSSL_NO_DH
            res = setup_dh(ctx, dh_file);
            if (res <= 0) {
                hashmap_unlock(certs_map, 1);
                return "Setting DH parameters failed";
            }
#endif

            SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);

            if (ca_file)
                SSL_CTX_load_verify_locations(ctx, ca_file, NULL);
            else
                SSL_CTX_set_default_verify_paths(ctx);

#ifdef SSL_MODE_RELEASE_BUFFERS
            SSL_CTX_set_mode(ctx, SSL_MODE_RELEASE_BUFFERS);
#endif
            /* SSL_CTX_load_verify_locations(ctx, "/etc/ejabberd/ca_certificates.pem", NULL); */
            /* SSL_CTX_load_verify_locations(ctx, NULL, "/etc/ejabberd/ca_certs/"); */

            /* This IF is commented to allow verification in all cases: */
            /* if (command == SET_CERTIFICATE_FILE_ACCEPT) */
            /* { */
            SSL_CTX_set_verify(ctx,
                               SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE,
                               verify_callback);
            /* } */

            SSL_CTX_set_info_callback(ctx, &ssl_info_callback);

            size_t len = strlen(key) + 1;

            info.key_mtime = key_mtime;
            info.dh_mtime = dh_mtime;
            info.ca_mtime = ca_mtime;
            info.ssl_ctx = ctx;
            info.key = enif_alloc(len);
            memcpy(info.key, key, len);

            if (hashmap_insert_no_lock(certs_map, &info, &old_info)) {
                enif_free(old_info.key);
            }
            *retval = SSL_new(ctx);
        } else {
            *retval = SSL_new(info.ssl_ctx);
        }

        hashmap_unlock(certs_map, 1);
    } else {
        *retval = SSL_new(info.ssl_ctx);
        hashmap_unlock(certs_map, 0);
    }
    return NULL;
}

static ERL_NIF_TERM open_nif(ErlNifEnv *env, int argc,
                             const ERL_NIF_TERM argv[]) {
    unsigned int command;
    unsigned int flags;
    char *cert_file = NULL, *ciphers = NULL;
    char *dh_file = NULL, *hash_key = NULL, *ca_file = NULL;
    ErlNifBinary ciphers_bin;
    ErlNifBinary certfile_bin;
    ErlNifBinary protocol_options_bin;
    ErlNifBinary dhfile_bin;
    ErlNifBinary cafile_bin;
    long options = 0L;
    state_t *state = NULL;

    ERR_clear_error();

    if (argc != 6)
        return enif_make_badarg(env);

    if (!enif_get_uint(env, argv[0], &flags))
        return enif_make_badarg(env);
    if (!enif_inspect_iolist_as_binary(env, argv[1], &certfile_bin))
        return enif_make_badarg(env);
    if (!enif_inspect_iolist_as_binary(env, argv[2], &ciphers_bin))
        return enif_make_badarg(env);
    if (!enif_inspect_iolist_as_binary(env, argv[2], &protocol_options_bin))
        return enif_make_badarg(env);
    if (!enif_inspect_iolist_as_binary(env, argv[4], &dhfile_bin))
        return enif_make_badarg(env);
    if (!enif_inspect_iolist_as_binary(env, argv[5], &cafile_bin))
        return enif_make_badarg(env);

    command = flags & 0xffff;
    size_t po_len_left = protocol_options_bin.size;
    unsigned char *po = protocol_options_bin.data;

    while (1) {
        unsigned char *pos = memchr(po, '|', po_len_left);

        if (!pos) {
            set_option_flag(po, po_len_left, &options);
            break;
        }
        set_option_flag(po, pos - po, &options);
        po_len_left -= pos - po + 1;
        po = pos + 1;
    }

    cert_file = enif_alloc(certfile_bin.size + 1);
    ciphers = enif_alloc(ciphers_bin.size + 1);
    dh_file = enif_alloc(dhfile_bin.size + 1);
    ca_file = enif_alloc(cafile_bin.size + 1);
    hash_key = enif_alloc(certfile_bin.size + ciphers_bin.size +
                          8 + dhfile_bin.size +
                          cafile_bin.size + 1);
    if (!cert_file || !ciphers || !dh_file || !hash_key || !ca_file) {
        enif_free(cert_file);
        enif_free(ciphers);
        enif_free(dh_file);
        enif_free(ca_file);
        enif_free(hash_key);
        return enif_make_badarg(env);
    }

    state = init_tls_state();
    if (!state) return ERR_T(enif_make_atom(env, "enomem"));

    memcpy(cert_file, certfile_bin.data, certfile_bin.size);
    cert_file[certfile_bin.size] = 0;
    memcpy(ciphers, ciphers_bin.data, ciphers_bin.size);
    ciphers[ciphers_bin.size] = 0;
    memcpy(dh_file, dhfile_bin.data, dhfile_bin.size);
    dh_file[dhfile_bin.size] = 0;
    memcpy(ca_file, cafile_bin.data, cafile_bin.size);
    ca_file[cafile_bin.size] = 0;

    sprintf(hash_key, "%s%s%08lx%s%s", cert_file, ciphers,
            options, dh_file, ca_file);

    char *err_str = create_ssl_for_cert(cert_file, ciphers, dh_file,
                                        ca_file, hash_key, &state->ssl);
    if (err_str)
        return ssl_error(env, err_str);

    if (!state->ssl) return ssl_error(env, "SSL_new failed");

    if (flags & VERIFY_NONE)
        SSL_set_verify(state->ssl, SSL_VERIFY_NONE, verify_callback);

#ifdef SSL_OP_NO_COMPRESSION
    if (flags & COMPRESSION_NONE)
        SSL_set_options(state->ssl, SSL_OP_NO_COMPRESSION);
#endif

    SSL_set_ex_data(state->ssl, ssl_index, state);

    state->bio_read = BIO_new(BIO_s_mem());
    state->bio_write = BIO_new(BIO_s_mem());

    SSL_set_bio(state->ssl, state->bio_read, state->bio_write);

    if (command == SET_CERTIFICATE_FILE_ACCEPT) {
        options |= (SSL_OP_NO_TICKET | SSL_OP_ALL | SSL_OP_NO_SSLv2);

        SSL_set_options(state->ssl, options);

        SSL_set_accept_state(state->ssl);
    } else {
        options |= (SSL_OP_NO_TICKET | SSL_OP_NO_SSLv2);

        SSL_set_options(state->ssl, options);

        SSL_set_connect_state(state->ssl);
    }

    enif_free(hash_key);
    enif_free(cert_file);
    enif_free(ciphers);
    enif_free(dh_file);
    ERL_NIF_TERM result = enif_make_resource(env, state);
    enif_release_resource(state);
    return OK_T(result);
}

static ERL_NIF_TERM set_encrypted_input_nif(ErlNifEnv *env, int argc,
                                            const ERL_NIF_TERM argv[]) {
    state_t *state = NULL;
    ErlNifBinary input;

    if (argc != 2)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!enif_inspect_iolist_as_binary(env, argv[1], &input))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);
    enif_mutex_lock(state->mtx);

    if (!state->valid) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "closed"));
    }

    BIO_write(state->bio_read, input.data, input.size);
    enif_mutex_unlock(state->mtx);

    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM set_decrypted_output_nif(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[]) {
    state_t *state = NULL;
    int res;
    ErlNifBinary input;

    if (argc != 2)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!enif_inspect_iolist_as_binary(env, argv[1], &input))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);
    enif_mutex_lock(state->mtx);

    if (!state->valid) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "closed"));
    }

    if (input.size > 0) {
        ERR_clear_error();

        if (state->send_buffer != NULL) {
            if (state->send_buffer2 == NULL) {
                state->send_buffer2_len = input.size;
                state->send_buffer2_size = input.size;
                state->send_buffer2 = enif_alloc(state->send_buffer2_size);
                memcpy(state->send_buffer2, input.data, input.size);
            } else {
                if (state->send_buffer2_size <
                    state->send_buffer2_len + input.size) {
                    while (state->send_buffer2_size <
                           state->send_buffer2_len + input.size) {
                        state->send_buffer2_size *= 2;
                    }
                    state->send_buffer2 = enif_realloc(state->send_buffer2, state->send_buffer2_size);
                }
                memcpy(state->send_buffer2 + state->send_buffer2_len, input.data, input.size);
                state->send_buffer2_len += input.size;
            }
        } else {
            res = SSL_write(state->ssl, input.data, input.size);
            if (res <= 0) {
                res = SSL_get_error(state->ssl, res);
                if (res == SSL_ERROR_WANT_READ || res == SSL_ERROR_WANT_WRITE) {
                    state->send_buffer_len = input.size;
                    state->send_buffer_size = input.size;
                    state->send_buffer = enif_alloc(state->send_buffer_size);
                    memcpy(state->send_buffer, input.data, input.size);
                } else {
                    enif_mutex_unlock(state->mtx);
                    return ssl_error(env, "SSL_write failed");
                }
            }
        }
    }

    enif_mutex_unlock(state->mtx);
    return enif_make_atom(env, "ok");
}

static ERL_NIF_TERM get_encrypted_output_nif(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[]) {
    state_t *state = NULL;
    size_t size;
    ErlNifBinary output;

    if (argc != 1)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);
    enif_mutex_lock(state->mtx);

    if (!state->valid) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "closed"));
    }

    ERR_clear_error();

    size = BIO_ctrl_pending(state->bio_write);
    if (!enif_alloc_binary(size, &output)) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "enomem"));
    }
    BIO_read(state->bio_write, output.data, size);
    enif_mutex_unlock(state->mtx);
    return OK_T(enif_make_binary(env, &output));
}

static ERL_NIF_TERM get_verify_result_nif(ErlNifEnv *env, int argc,
                                          const ERL_NIF_TERM argv[]) {
    long res;
    state_t *state = NULL;

    if (argc != 1)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);
    enif_mutex_lock(state->mtx);

    if (!state->valid) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "closed"));
    }

    ERR_clear_error();
    res = SSL_get_verify_result(state->ssl);
    enif_mutex_unlock(state->mtx);
    return OK_T(enif_make_long(env, res));
}

static ERL_NIF_TERM get_peer_certificate_nif(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[]) {
    X509 *cert = NULL;
    state_t *state = NULL;
    int rlen;
    ErlNifBinary output;

    if (argc != 1)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);
    enif_mutex_lock(state->mtx);

    if (!state->valid) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "closed"));
    }

    ERR_clear_error();

    cert = SSL_get_peer_certificate(state->ssl);
    if (!cert) {
        enif_mutex_unlock(state->mtx);
        return ssl_error(env, "SSL_get_peer_certificate failed");
    }
    rlen = i2d_X509(cert, NULL);
    if (rlen >= 0) {
        if (!enif_alloc_binary(rlen, &output)) {
            enif_mutex_unlock(state->mtx);
            return ERR_T(enif_make_atom(env, "enomem"));
        }
        i2d_X509(cert, &output.data);
        X509_free(cert);
        enif_mutex_unlock(state->mtx);
        return OK_T(enif_make_binary(env, &output));
    } else {
        X509_free(cert);
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "notfound"));
    }
}

static ERL_NIF_TERM get_decrypted_input_nif(ErlNifEnv *env, int argc,
                                            const ERL_NIF_TERM argv[]) {
    state_t *state = NULL;
    size_t rlen, size;
    int res;
    unsigned int req_size = 0;
    ErlNifBinary output;
    int retcode = 0;

    if (argc != 2)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!enif_get_uint(env, argv[1], &req_size))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);
    enif_mutex_lock(state->mtx);

    if (!state->valid) {
        enif_mutex_unlock(state->mtx);
        return ERR_T(enif_make_atom(env, "closed"));
    }

    ERR_clear_error();

    if (!SSL_is_init_finished(state->ssl)) {
        retcode = 2;
        res = SSL_do_handshake(state->ssl);
        if (res <= 0) {
            if (SSL_get_error(state->ssl, res) != SSL_ERROR_WANT_READ) {
                enif_mutex_unlock(state->mtx);
                return ssl_error(env, "SSL_do_handshake failed");
            }
        }
    }
    if (SSL_is_init_finished(state->ssl)) {
        int i;
        for (i = 0; i < 2; i++)
            if (state->send_buffer != NULL) {
                res = SSL_write(state->ssl, state->send_buffer, state->send_buffer_len);
                if (res <= 0) {
                    char *error = "SSL_write failed";
                    enif_mutex_unlock(state->mtx);
                    return ERR_T(enif_make_string(env, error, ERL_NIF_LATIN1));
                }
                retcode = 2;
                enif_free(state->send_buffer);
                state->send_buffer = state->send_buffer2;
                state->send_buffer_len = state->send_buffer2_len;
                state->send_buffer_size = state->send_buffer2_size;
                state->send_buffer2 = NULL;
                state->send_buffer2_len = 0;
                state->send_buffer2_size = 0;
            }
        size = BUF_SIZE;
        rlen = 0;
        enif_alloc_binary(size, &output);
        res = 0;
        while ((req_size == 0 || rlen < req_size) &&
               (res = SSL_read(state->ssl,
                               output.data + rlen,
                               (req_size == 0 || req_size >= size) ?
                               size - rlen : req_size - rlen)) > 0) {
            //printf("%d bytes of decrypted data read from state machine\r\n",res);
            rlen += res;
            if (size - rlen < BUF_SIZE) {
                size *= 2;
                enif_realloc_binary(&output, size);
            }
        }

        if (state->handshakes > 1) {
            enif_release_binary(&output);
            char *error = "client renegotiations forbidden";
            enif_mutex_unlock(state->mtx);
            return ERR_T(enif_make_string(env, error, ERL_NIF_LATIN1));
        }

        if (res < 0) {
            int error = SSL_get_error(state->ssl, res);

            if (error == SSL_ERROR_WANT_READ) {
                //printf("SSL_read wants more data\r\n");
                //return 0;
            }
            // TODO
        }
        enif_realloc_binary(&output, rlen);
    } else {
        retcode = 2;
        enif_alloc_binary(0, &output);
    }
    enif_mutex_unlock(state->mtx);
    return retcode == 0 ? OK_T(enif_make_binary(env, &output))
                        : SEND_T(enif_make_binary(env, &output));
}

static ERL_NIF_TERM invalidate_nif(ErlNifEnv *env, int argc,
                                   const ERL_NIF_TERM argv[]) {
    state_t *state = NULL;

    if (argc != 1)
        return enif_make_badarg(env);

    if (!enif_get_resource(env, argv[0], tls_state_t, (void *) &state))
        return enif_make_badarg(env);

    if (!state->mtx || !state->ssl) return enif_make_badarg(env);

    enif_mutex_lock(state->mtx);
    state->valid = 0;
    enif_mutex_unlock(state->mtx);

    return enif_make_atom(env, "ok");
}

static ErlNifFunc nif_funcs[] =
        {
                {"open_nif",                 6, open_nif},
                {"set_encrypted_input_nif",  2, set_encrypted_input_nif},
                {"set_decrypted_output_nif", 2, set_decrypted_output_nif},
                {"get_decrypted_input_nif",  2, get_decrypted_input_nif},
                {"get_encrypted_output_nif", 1, get_encrypted_output_nif},
                {"get_verify_result_nif",    1, get_verify_result_nif},
                {"get_peer_certificate_nif", 1, get_peer_certificate_nif},
                {"invalidate_nif",           1, invalidate_nif}
        };

ERL_NIF_INIT(fast_tls, nif_funcs, load, NULL, NULL, unload)
