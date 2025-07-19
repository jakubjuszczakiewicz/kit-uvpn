/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "logger.h"

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <semaphore.h>
#include "threads.h"
#include "memlog.h"

#define STRTIME_SIZE 32
#define LOGGER_WRITE_BUFFER 102400

static atomic_int logfile;
static char * logfile_path = NULL;
static unsigned int logfile_level = 0;

static void * log_writter_thread = NULL;
static sem_t writer_semaphore, buffer_semaphore;
static char write_buffer_1[LOGGER_WRITE_BUFFER];
static char write_buffer_2[LOGGER_WRITE_BUFFER];
static volatile char * input = write_buffer_1;
static volatile size_t input_size = 0;

extern int end_now;

void logger_thread(void * arg)
{
  char * buffer;
  size_t buffer_size;

  while (!end_now) {
    sem_wait(&writer_semaphore);

    sem_wait(&buffer_semaphore);
    buffer_size = input_size;
    buffer = (char *)input;
    if (input == write_buffer_1) {
      input = write_buffer_2;
    } else {
      input = write_buffer_1;
    }
    input_size = 0;
    sem_post(&buffer_semaphore);

    size_t offs = 0;
    while (buffer_size > 0) {
      ssize_t w = write(atomic_load(&logfile), buffer + offs, buffer_size);
      if (w > 0) {
        buffer_size -= w;
        offs += w;
      } else if (w < 0)
        break;
    }
    fsync(atomic_load(&logfile));
  }
}

int logger_init(const char * path, unsigned int log_level)
{
  int f = open(path, O_APPEND | O_CREAT | O_RDWR,
      S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
  if (f < 0)
    return 1;

  atomic_store(&logfile, f);

  logfile_path = strdup(path);
  logfile_level = log_level;

  sem_init(&writer_semaphore, 0, 0);
  sem_init(&buffer_semaphore, 0, 1);
  log_writter_thread = thread_new(logger_thread, NULL);

  return 0;
}

int logger_reopen(void)
{
  if (!logfile_path)
    return 1;

  int old_logfile = atomic_load(&logfile);

  atomic_store(&logfile, open(logfile_path, O_APPEND | O_CREAT | O_RDWR,
      S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH));

  if (old_logfile)
    close(old_logfile);

  if (atomic_load(&logfile) >= 0)
    return 0;
  return 1;
}

void logger_close(void)
{
  sem_post(&writer_semaphore);
  thread_join(log_writter_thread);
  sem_destroy(&writer_semaphore);
  sem_destroy(&buffer_semaphore);

  close(atomic_load(&logfile));
  int_free(logfile_path);
  logfile_path = NULL;
  atomic_store(&logfile, 0);
}

void logger_printf(unsigned int log_level, const char * format, ...)
{
  if (log_level > logfile_level)
    return;

  char * log;
  char timestr[STRTIME_SIZE];
  va_list list;

  va_start(list, format);
  (void)vasprintf(&log, format, list);
  va_end(list);

  time_t now = time(NULL);
  struct tm now_tm;
  localtime_r(&now, &now_tm);
  strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S %z", &now_tm);

  size_t len1 = strlen(log);
  size_t len2 = strlen(timestr);
  size_t len = len1 + 3 + len2;

  sem_wait(&buffer_semaphore);

  while (input_size + len > LOGGER_WRITE_BUFFER) {
    sem_post(&buffer_semaphore);
    sem_wait(&buffer_semaphore);
  }

  memcpy((char *)&input[input_size], timestr, len2);
  memcpy((char *)&input[input_size + len2], "  ", 2);
  memcpy((char *)&input[input_size + len2 + 2], log, len1);
  memcpy((char *)&input[input_size + len2 + 2 + len1], "\n", 1);

  if (input_size == 0) {
    sem_post(&writer_semaphore);
  }

  input_size += len;

  sem_post(&buffer_semaphore);

  int_free(log);
}
