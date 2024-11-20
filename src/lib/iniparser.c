/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "iniparser.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "memlog.h"

static int parse(char * file, size_t length,
    iniparser_next_section section_callback,
    iniparser_next_value value_callback, void * data)
{
  char * ptr = file;

  while (ptr < file + length) {
    if (*ptr == '[')
      break;

    if (*ptr == ';')
      while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r'))
        ptr++;

    if (*ptr > ' ')
      break;

    ptr++;
  }

  if (ptr == file + length)
    return 0;

  while (ptr < file + length) {
    if (*ptr != '[')
      return 1;
    ptr++;
    const char * start = ptr;

    while ((ptr < file + length) && (*ptr != ']') && (*ptr != '\n') &&
        (*ptr != '\r'))
      ptr++;

    if ((ptr == file + length) || (*ptr != ']'))
      return 1;

    *ptr = 0;
    int r = section_callback(start, data);
    if (r)
      return r;

    do {
      while ((ptr < file + length) && (*ptr <= ' '))
        ptr++;

      if (ptr == file + length)
        return 0;

      if (*ptr == ';') {
        while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r'))
          ptr++;

        continue;
      }

      if (*ptr == '[')
        break;

      start = ptr;
      while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r') &&
          (*ptr != '=') && (*ptr != ';'))
        ptr++;

      if ((ptr == file + length) || (*ptr != '='))
        return 1;

      char * end = ptr - 1;
      while ((end > start) && (*end <= ' '))
        end--;

      end++;
      *end = 0;
      ptr++;

      while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r') &&
          (*ptr <= ' ') && (*ptr != ';'))
        ptr++;

      if (ptr == file + length)
        return value_callback(start, ptr, data);

      if ((*ptr == ';') || (*ptr == '\n') || (*ptr == '\r')) {
        ptr--;
        *ptr = 0;
        r = value_callback(start, ptr, data);
        if (r)
          return r;

        ptr++;
        while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r'))
          ptr++;

        continue;
      }

      const char * start2 = ptr;
  
      while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r') &&
          (*ptr != ';'))
        ptr++;

      if (ptr == file + length)
        return value_callback(start, start2, data);

      end = ptr - 1;
      if (*ptr == ';')
        while ((ptr < file + length) && (*ptr != '\n') && (*ptr != '\r'))
          ptr++;

      while ((end > start2) && (*end <= ' '))
        end--;
      end++;
      *end = 0;
      r = value_callback(start, start2, data);
      if (r)
        return r;
    } while (ptr < file + length);
  }

  return 1;
}

int iniparser(const char * path, iniparser_next_section section_callback,
    iniparser_next_value value_callback, void * data)
{
  FILE * f = fopen(path, "r");
  if (!f)
    return 1;

  fseek(f, 0, SEEK_END);
  size_t file_size = ftell(f);
  fseek(f, 0, SEEK_SET);

  char * fbody = int_malloc(file_size + 1);
  size_t fsize = fread(fbody, 1, file_size, f);
  fbody[fsize] = 0;

  fclose(f);

  int r = parse(fbody, fsize, section_callback, value_callback, data);

  int_free(fbody);

  return r;
}
