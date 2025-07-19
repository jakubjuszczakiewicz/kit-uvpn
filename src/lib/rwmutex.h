/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */


#pragma once

#include <stdatomic.h>
#include <semaphore.h>

typedef atomic_uint rwmutex_t;

int sem_wait_int(sem_t * sem, volatile unsigned int * local_end_now);

#ifndef MUTEXLOG

void kit_rwlock_init(rwmutex_t * mtx);
void kit_rwlock_wrlock(rwmutex_t * mtx);
void kit_rwlock_rdlock(rwmutex_t * mtx);
void kit_rwlock_rdunlock(rwmutex_t * mtx);
void kit_rwlock_wrunlock(rwmutex_t * mtx);
void kit_rwlock_switch_rd_wr(rwmutex_t * mtx);
void kit_rwlock_switch_wr_rd(rwmutex_t * mtx);

#define i_rwlock_init(mtx) kit_rwlock_init(mtx) 
#define i_rwlock_wrlock(mtx) kit_rwlock_wrlock(mtx)
#define i_rwlock_rdlock(mtx) kit_rwlock_rdlock(mtx)
#define i_rwlock_rdunlock(mtx) kit_rwlock_rdunlock(mtx)
#define i_rwlock_wrunlock(mtx) kit_rwlock_wrunlock(mtx)
#define i_rwlock_switch_rd_wr(mtx) kit_rwlock_switch_rd_wr(mtx)
#define i_rwlock_switch_wr_rd(mtx) kit_rwlock_switch_wr_rd(mtx)

#else

void dbg_rwlock_init(rwmutex_t * mtx, int line, const char * file);
void dbg_rwlock_wrlock(rwmutex_t * mtx, int line, const char * file);
void dbg_rwlock_rdlock(rwmutex_t * mtx, int line, const char * file);
void dbg_rwlock_rdunlock(rwmutex_t * mtx, int line, const char * file);
void dbg_rwlock_wrunlock(rwmutex_t * mtx, int line, const char * file);
void dbg_rwlock_switch_rd_wr(rwmutex_t * mtx, int line, const char * file);
void dbg_rwlock_switch_wr_rd(rwmutex_t * mtx, int line, const char * file);

#define i_rwlock_init(mtx) dbg_rwlock_init(mtx, __LINE__, __FILE__) 
#define i_rwlock_wrlock(mtx) dbg_rwlock_wrlock(mtx, __LINE__, __FILE__)
#define i_rwlock_rdlock(mtx) dbg_rwlock_rdlock(mtx,  __LINE__, __FILE__)
#define i_rwlock_rdunlock(mtx) dbg_rwlock_rdunlock(mtx, __LINE__, __FILE__)
#define i_rwlock_wrunlock(mtx) dbg_rwlock_wrunlock(mtx, __LINE__, __FILE__)
#define i_rwlock_switch_rd_wr(mtx) dbg_rwlock_switch_rd_wr(mtx, __LINE__, __FILE__)
#define i_rwlock_switch_wr_rd(mtx) dbg_rwlock_switch_wr_rd(mtx, __LINE__, __FILE__)

#endif
