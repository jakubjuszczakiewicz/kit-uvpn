#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "memlog.h"

#include <rsa.h>

int main(int argc, char * argv[])
{
  unsigned int bits = 2048;
  if (argc == 2)
    bits = atoi(argv[1]);
  if (bits == 0)
    bits = 2048;

  struct RSA * rsa = rsa_new(bits);

  char * n = rsa_get_n(rsa);
  char * d = rsa_get_d(rsa);
  char * e = rsa_get_e(rsa);

  rsa_done(rsa);

  printf("n=[%s]\ne=[%s]\nd=[%s]\n", n, e, d);

  int_free(n);
  int_free(d);
  int_free(e);

  return 0;
}
