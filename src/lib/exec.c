/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "exec.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include "memlog.h"

#define READ_BUFFER_SIZE 1024

void exec_with_env(const char * path, size_t env_count, char * envs)
{
  if (!path)
    return;

  pid_t p = fork();
  if (p != 0) {
    if (p < 0)
      return;

    int status = -1;
    (void)waitpid(p, &status, 0);
    return;
  }

  fclose(stdin);
  fclose(stdout);
  fclose(stderr);

  size_t len = 0;

  char ** env_arg = malloc(sizeof(char *) * (env_count + 1));
  size_t pos = 0;

  for (size_t i = 0; i < env_count; i++) {
    env_arg[i] = &envs[pos];
    pos += strlen(&envs[pos]) + 1;
  }
  env_arg[env_count] = NULL;

  len = strlen(path);

  int count = 0;
  for (size_t i = 0; i < len; i++) {
    if (path[i] == '\\')
      i++;
    else if (path[i] == ' ') {
      count++;
      while (path[i + 1] == ' ')
        i++;
    }
  }
  char ** params = malloc(sizeof(char *) * (count + 2));
  char * args = malloc(len + 2);
  params[0] = args;

  count = 0;
  size_t j = 0;
  for (size_t i = 0; i < len; i++) {
    if (path[i] == '\\') {
      i++;
      args[j++] = path[i];
    } else if (path[i] == ' ') {
      args[j++] = 0;
      while ((i + 1 < len) && (path[i + 1] == ' '))
        i++;
      params[++count] = &args[j];
    } else {
      args[j++] = path[i];
    }
  }
  args[j] = 0;
  params[++count] = NULL;

  execve(params[0], &params[0], env_arg);

  free(params);
  free(args);
  free(env_arg);

  exit(-1);
}

int system_with_env(const char * path, size_t env_count, char * envs)
{
  if (!path)
    return -1;

  pid_t p = fork();
  if (p != 0) {
    if (p < 0)
      return -1;

    int status = -1;
    (void)waitpid(p, &status, 0);
    return WEXITSTATUS(status);
  }

  fclose(stdin);
  fclose(stdout);
  fclose(stderr);

  size_t len = 0;

  char ** env_arg = malloc(sizeof(char *) * (env_count + 1));
  size_t pos = 0;

  for (size_t i = 0; i < env_count; i++) {
    env_arg[i] = &envs[pos];
    pos += strlen(&envs[pos]) + 1;
  }
  env_arg[env_count] = NULL;

  len = strlen(path);

  int count = 0;
  for (size_t i = 0; i < len; i++) {
    if (path[i] == '\\')
      i++;
    else if (path[i] == ' ') {
      count++;
      while (path[i + 1] == ' ')
        i++;
    }
  }
  char ** params = malloc(sizeof(char *) * (count + 2));
  char * args = malloc(len + 2);
  params[0] = args;

  count = 0;
  size_t j = 0;
  for (size_t i = 0; i < len; i++) {
    if (path[i] == '\\') {
      i++;
      args[j++] = path[i];
    } else if (path[i] == ' ') {
      args[j++] = 0;
      while ((i + 1 < len) && (path[i + 1] == ' '))
        i++;
      params[++count] = &args[j];
    } else {
      args[j++] = path[i];
    }
  }
  args[j] = 0;
  params[++count] = NULL;

  execve(params[0], &params[0], env_arg);

  free(params);
  free(args);
  free(env_arg);

  exit(-1);
}

int proc_read_with_env(const char * path, size_t env_count, char * envs,
  char ** output_buffer, size_t * max_output_buffer_size,
  time_t max_exec_time_sec)
{
  if (!path)
    return -1;

  int stdio_out[2], stdio_err[2];
  pipe(stdio_out);
  pipe(stdio_err);

  pid_t child_pid = fork();
  if (child_pid == 0) {
    close(stdio_out[0]);
    close(stdio_err[0]);

    close(STDIN_FILENO);

    dup2(stdio_out[1], STDOUT_FILENO);
    close(stdio_out[1]);

    dup2(stdio_err[1], STDERR_FILENO);
    close(stdio_err[1]);

    size_t len = 0;

    char ** env_arg = malloc(sizeof(char *) * (env_count + 1));
    size_t pos = 0;

    for (size_t i = 0; i < env_count; i++) {
      env_arg[i] = &envs[pos];
      pos += strlen(&envs[pos]) + 1;
    }
    env_arg[env_count] = NULL;

    len = strlen(path);

    int count = 0;
    for (size_t i = 0; i < len; i++) {
      if (path[i] == '\\')
        i++;
      else if (path[i] == ' ') {
        count++;
        while (path[i + 1] == ' ')
          i++;
      }
    }
    char ** params = malloc(sizeof(char *) * (count + 2));
    char * args = malloc(len + 2);
    params[0] = args;

    count = 0;
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
      if (path[i] == '\\') {
        i++;
        args[j++] = path[i];
      } else if (path[i] == ' ') {
        args[j++] = 0;
        while ((i + 1 < len) && (path[i + 1] == ' '))
          i++;
        params[++count] = &args[j];
      } else {
        args[j++] = path[i];
      }
    }
    args[j] = 0;
    params[++count] = NULL;

    execve(params[0], &params[0], env_arg);

    free(params);
    free(args);
    free(env_arg);

    exit(-1);
  }
  if (child_pid < 0)
    return -1;

  close(stdio_out[1]);
  close(stdio_err[1]);

  char * read_buffer = int_malloc(READ_BUFFER_SIZE);

  int fd_max = stdio_out[0];
  if (stdio_err[0] > fd_max)
    fd_max = stdio_err[0];

  fd_max++;

  time_t start = time(NULL);

  *output_buffer = NULL;
  size_t output_buffer_size = 0;

  while (start + max_exec_time_sec > time(NULL)) {
    fd_set fd_read;
    FD_ZERO(&fd_read);
    FD_SET(stdio_out[0], &fd_read);
    FD_SET(stdio_err[0], &fd_read);

    struct timeval timeout = { 1, 0 };
    int n = select(fd_max, &fd_read, NULL, NULL, &timeout);

    if (n < 0) {
      break;
    }
    if (n == 0)
      continue;

    if (FD_ISSET(stdio_err[0], &fd_read)) {
      char tmpbuf[1024];
      read(stdio_err[0], tmpbuf, sizeof(tmpbuf));
    }
    if (FD_ISSET(stdio_out[0], &fd_read)) {
      ssize_t r = read(stdio_out[0], read_buffer, READ_BUFFER_SIZE);
      if (r <= 0)
        break;

      if (output_buffer_size + r > *max_output_buffer_size)
        r = *max_output_buffer_size - output_buffer_size;

      if (output_buffer_size) {
        *output_buffer = int_realloc(*output_buffer, output_buffer_size + r);
        memcpy(*output_buffer + output_buffer_size, read_buffer, r);
        output_buffer_size += r;
      } else {
        *output_buffer = int_malloc(r);
        memcpy(*output_buffer, read_buffer, r);
        output_buffer_size = r;
      }

      if (output_buffer_size == *max_output_buffer_size)
        break;
    }
  }

  int_free(read_buffer);

  kill(child_pid, SIGTERM);
  close(stdio_out[0]);
  close(stdio_err[0]);

  *max_output_buffer_size = output_buffer_size;

  int status = -1;
  (void)waitpid(child_pid, &status, 0);
  return WEXITSTATUS(status);
}
