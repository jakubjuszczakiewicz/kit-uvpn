/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

#include <stddef.h>

struct RSA;

struct RSA *rsa_new(unsigned int bits);
struct RSA *rsa_private(const char *n, const char *d, const char *e);
struct RSA *rsa_public(const char *n, const char *e);
void rsa_done(struct RSA *thiz);

char *rsa_get_n(const struct RSA *thiz);
char *rsa_get_d(const struct RSA *thiz);
char *rsa_get_e(const struct RSA *thiz);
size_t rsa_get_n_size(const struct RSA *thiz);
int rsa_is_public(const struct RSA *thiz);

size_t rsa_process_out(const struct RSA *thiz, int enc,
    const unsigned char *in, size_t len, unsigned char *out);
size_t rsa_process_in(const struct RSA *thiz, int enc,
    const unsigned char *in, size_t len, unsigned char *out);

size_t rsa_enc_pub(const struct RSA *thiz, const unsigned char *in,
    size_t len, unsigned char *out);
size_t rsa_dec_prv(const struct RSA *thiz, const unsigned char *in,
    size_t len, unsigned char *out);
