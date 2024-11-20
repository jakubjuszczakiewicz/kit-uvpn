/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "rsa.h"
#include <stdlib.h>
#include <string.h>
#include <gmp.h>
#include <time.h>

struct RSA
{
  mpz_t n;
  mpz_t d;
  mpz_t e;
};

struct RSA *rsa_new(unsigned int bits)
{
  struct RSA * result = malloc(sizeof(*result));
  mpz_t p, q, eu, t1, t2, m;
  gmp_randstate_t rnd;

  gmp_randinit_default(rnd);
  struct timespec tp;
  clock_gettime(CLOCK_REALTIME, &tp);
  gmp_randseed_ui(rnd, tp.tv_sec ^ tp.tv_nsec);

  mpz_init(p);
  mpz_init(q);
  mpz_init(result->n);
  mpz_init(result->e);
  mpz_init(eu);
  mpz_init(result->d);
  mpz_init(t1);
  mpz_init(t2);
  mpz_init(m);

  mpz_urandomb(p, rnd, (bits * 0.45));
  mpz_urandomb(q, rnd, (bits * 0.55));
  mpz_urandomb(m, rnd, bits);

  do
  {
    mpz_nextprime(p, p);
  } while(mpz_probab_prime_p(p, bits * 10) == 0);

  do
  {
    mpz_nextprime(q, q);
  } while(mpz_probab_prime_p(q, bits * 10) == 0);

  do
  {
    mpz_nextprime(m, m);
  } while(mpz_probab_prime_p(m, bits * 10) == 0);
  

  mpz_mul(result->n, p, q);
  mpz_sub_ui(p, p, 1);
  mpz_sub_ui(q, q, 1);
  mpz_sub_ui(m, m, 1);
  mpz_lcm(t2, p, q);
  mpz_lcm(eu, t2, m);

  do
  {
    mpz_urandomm(result->e, rnd, eu);
    mpz_gcd(t1, result->e, eu);
  } while((mpz_cmp_si(t1, 1) != 0) || (mpz_cmp(t2, result->e) > 0));
  gmp_randclear(rnd);

  mpz_gcdext(t1, t2, result->d, eu, result->e);

  while(mpz_cmp_si(result->d, 0) < 0)
  {
    mpz_add(result->d, result->d, eu);
  }

  mpz_clear(m);
  mpz_clear(p);
  mpz_clear(q);
  mpz_clear(eu);
  mpz_clear(t1);
  mpz_clear(t2);

  return result;
}

struct RSA *rsa_private(const char *n, const char *d, const char *e)
{
  struct RSA * result = malloc(sizeof(*result));

  mpz_init(result->n);
  mpz_init(result->e);
  mpz_init(result->d);

  mpz_set_str(result->n, n, 16);
  mpz_set_str(result->e, e, 16);
  mpz_set_str(result->d, d, 16);

  return result;
}

struct RSA *rsa_public(const char *n, const char *e)
{
  struct RSA * result = malloc(sizeof(*result));

  mpz_init(result->n);
  mpz_init(result->e);
  mpz_init(result->d);

  mpz_set_str(result->n, n, 16);
  mpz_set_str(result->e, e, 16);
  mpz_set_ui(result->d, 0);

  return result;
}

void rsa_done(struct RSA *thiz)
{
  if (!thiz)
  {
    return;
  }
  mpz_clear(thiz->e);
  mpz_clear(thiz->d);
  mpz_clear(thiz->n);

  free(thiz);
}

char *rsa_get_n(const struct RSA *thiz)
{
  return mpz_get_str(NULL, 16, thiz->n);
}

char *rsa_get_d(const struct RSA *thiz)
{
  return mpz_get_str(NULL, 16, thiz->d);
}

char *rsa_get_e(const struct RSA *thiz)
{
  return mpz_get_str(NULL, 16, thiz->e);
}

size_t rsa_get_n_size(const struct RSA *thiz)
{
  return sizeof(mp_limb_t) * mpz_size(thiz->n);
}

int rsa_is_public(const struct RSA *thiz)
{
  return mpz_cmp_ui(thiz->d, 0);
}

size_t rsa_process_out(const struct RSA *thiz, int enc,
    const unsigned char *in, size_t len, unsigned char *out)
{
  size_t (*func)(const struct RSA *, const unsigned char *,
    size_t, unsigned char *);

  if (enc)
    func = rsa_enc_pub;
  else
    func = rsa_dec_prv;

  size_t max = rsa_get_n_size(thiz) - 1;
  size_t in_pos = 0, out_pos = 0;

  unsigned char * buffer = malloc(max + 1);

  while (in_pos < len) {
    size_t next_part = (len - in_pos < max - 3)?(len - in_pos):(max - 3);
    buffer[0] = 0x80;
    buffer[1] = next_part >> 8;
    buffer[2] = next_part;
    memcpy(&buffer[3], &in[in_pos], next_part);
    in_pos += next_part;

    size_t tmp = func(thiz, buffer, next_part + 3, &out[out_pos + 2]);
    out[out_pos] = tmp >> 8;
    out[out_pos + 1] = tmp;
    out_pos += tmp + 2;
  }

  free(buffer);

  return out_pos;
}

size_t rsa_process_in(const struct RSA *thiz, int enc,
    const unsigned char *in, size_t len, unsigned char *out)
{
    size_t (*func)(const struct RSA *, const unsigned char *,
    size_t, unsigned char *);

  if (enc)
    func = rsa_enc_pub;
  else
    func = rsa_dec_prv;

  size_t max = rsa_get_n_size(thiz) - 1;
  size_t in_pos = 0, out_pos = 0;

  unsigned char * buffer = malloc(max + 1);

  while (in_pos < len) {
    size_t len2 = (in[in_pos] << 8) | in[in_pos + 1];

    if ((len2 > max + 1) || (in_pos + len2 + 2 > len)) {
      free(buffer);
      return 0;
    }
    size_t tmp2 = 2 + len2;
    size_t tmp = func(thiz, &in[in_pos + 2], len2, buffer);
    size_t len3 = (buffer[1] << 8) | buffer[2];

    if ((len3 + 3 < tmp) || (tmp < 3) || (buffer[0] != 0x80)) {
      free(buffer);
      return 0;
    }
    in_pos += tmp2;
    tmp -= 3;

    if (len3 > tmp) {
      memset(&out[out_pos], 0, len3 - tmp);
      memcpy(&out[out_pos + len3 - tmp], buffer + 3, tmp);
    } else
      memcpy(&out[out_pos], buffer + 3, len3);

    out_pos += len3;
  }

  free(buffer);

  return out_pos;
}

size_t rsa_enc_pub(const struct RSA *thiz, const unsigned char *in,
    size_t len, unsigned char *out)
{
  mpz_t m, c;
  mpz_init(m);
  mpz_init(c);

  mpz_import(m, len, 1, 1, 0, 0, in);
  mpz_powm(c, m, thiz->e, thiz->n);
  size_t result = 0;
  mpz_export(out, &result, 1, 1, 0, 0, c);

  mpz_clear(m);
  mpz_clear(c);

  return result;
}

size_t rsa_dec_prv(const struct RSA *thiz, const unsigned char *in,
    size_t len, unsigned char *out)
{
  mpz_t m, c;
  mpz_init(m);
  mpz_init(c);

  mpz_import(m, len, 1, 1, 0, 0, in);
  mpz_powm(c, m, thiz->d, thiz->n);
  size_t result;
  mpz_export(out, &result, 1, 1, 0, 0, c);

  mpz_clear(m);
  mpz_clear(c);
  
  return result;
}

