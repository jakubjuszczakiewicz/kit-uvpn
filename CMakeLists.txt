cmake_minimum_required(VERSION 3.1)
project(uVPN)
set(SOURCE_FILES
  src/lib/rsa.c
  src/lib/logger.c
  src/lib/random.c
  src/lib/thpool.c
  src/lib/iniparser.c
  src/lib/utils.c
  src/lib/threads.c
  src/lib/tcpc.c
  src/lib/allocator.c
  src/lib/avl.c
  src/lib/queue.c
  src/lib/exec.c
  src/lib/tabhash.c
  src/lib/hashdict.c
  src/lib/clock.c
  src/lib/dns.c
  src/lib/memlog.c
  src/lib/rwmutex.c
  src/core/main.c
  src/core/decrypt.c
  src/core/counter.c
  src/core/checksum.c
  src/core/checksum2.c
  src/core/encrypt.c
  src/core/l2_sw.c
  src/core/tap.c
  src/core/tcp.c
  src/core/config.c
  src/core/conststr.c
  src/core/perf.c
  src/core/workers.c
  src/core/connection.c
  src/core/version.c
)

set(SOURCE_FILES_RSAGEN
  src/lib/rsa.c
  src/tools/rsa_gen.c
  src/lib/memlog.c
)

if (UNIX)
  EXEC_PROGRAM(uname OUTPUT_VARIABLE SYSTEM_NAME)
  if(SYSTEM_NAME STREQUAL "Linux")
    list(APPEND SOURCE_FILES src/lib/linux/tap_int.c)
    set(OS_STR "Linux" CACHE STRING "OS Name String")

    EXEC_PROGRAM("date +'%Y-%m-%d %H:%M:%S'" OUTPUT_VARIABLE NOW_TIME)
    EXEC_PROGRAM("uname -n" OUTPUT_VARIABLE HOST_NAME)
    set(CT_TIME_STR "Configured @ ${NOW_TIME} ${HOST_NAME}" CACHE STRING "Comment added during compilation")
  elseif(SYSTEM_NAME STREQUAL "OpenBSD")
    list(APPEND SOURCE_FILES src/lib/bsd/tap_int.c)
    set(OS_STR "OpenBSD" CACHE STRING "OS Name String")

    EXEC_PROGRAM("date +'%Y-%m-%d %H:%M:%S'" OUTPUT_VARIABLE NOW_TIME)
    EXEC_PROGRAM("uname -n" OUTPUT_VARIABLE HOST_NAME)
    set(CT_TIME_STR "Configured @ ${NOW_TIME} ${HOST_NAME}" CACHE STRING "Comment added during compilation")
  elseif(SYSTEM_NAME STREQUAL "FreeBSD")
    list(APPEND SOURCE_FILES src/lib/bsd/tap_int.c)
    set(OS_STR "FreeBSD" CACHE STRING "OS Name String")
    add_definitions(-DSYS_ENDIAN)

    EXEC_PROGRAM("date +'%Y-%m-%d %H:%M:%S'" OUTPUT_VARIABLE NOW_TIME)
    EXEC_PROGRAM("uname -n" OUTPUT_VARIABLE HOST_NAME)
    set(CT_TIME_STR "Configured @ ${NOW_TIME} ${HOST_NAME}" CACHE STRING "Comment added during compilation")
  elseif(SYSTEM_NAME STREQUAL "NetBSD")
    list(APPEND SOURCE_FILES src/lib/bsd/tap_int.c)
    set(OS_STR "NetBSD" CACHE STRING "OS Name String")

    EXEC_PROGRAM("date +'%Y-%m-%d %H:%M:%S'" OUTPUT_VARIABLE NOW_TIME)
    EXEC_PROGRAM("uname -n" OUTPUT_VARIABLE HOST_NAME)
    set(CT_TIME_STR "Configured @ ${NOW_TIME} ${HOST_NAME}" CACHE STRING "Comment added during compilation")
  else()
    message(FATAL_ERROR "Unsupported system")
  endif()
elseif(WIN32)
  message(FATAL_ERROR "Windows is unsupported")
else()
  message(FATAL_ERROR "Unsupported system")
endif()

list(APPEND CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include_directories(${PROJECT_SOURCE_DIR}/src/lib ${GMP_INCLUDES})
find_package(GMP REQUIRED)
find_package(Threads REQUIRED)

add_definitions(-DOS_STR="${OS_STR}")

add_definitions(-DCT_TIME_STR="${CT_TIME_STR}")

set(MAX_CONNS "512" CACHE STRING "Max open connections")
add_definitions(-DMAX_CONNS=${MAX_CONNS})

set(MAX_BUFFER_SIZE "3072000" CACHE STRING "Max tcp buffer size")
add_definitions(-DMAX_BUFFER_SIZE=${MAX_BUFFER_SIZE})

set(AUTH_BUFFER_SIZE "65537" CACHE STRING "Max tcp auth buffer size")
add_definitions(-DAUTH_BUFFER_SIZE=${AUTH_BUFFER_SIZE})

set(MAX_MTU "1540" CACHE STRING "Max tap mtu")
add_definitions(-DMAX_MTU=${MAX_MTU})

set(MAX_CRYPTO_WORKERS "32" CACHE STRING "Max ecryption + decryption threads")
add_definitions(-DMAX_CRYPTO_WORKERS=${MAX_CRYPTO_WORKERS})

set(MAX_CHECKSUM_WORKERS "32" CACHE STRING "Max checksum check + calc threads")
add_definitions(-DMAX_CHECKSUM_WORKERS=${MAX_CHECKSUM_WORKERS})

set(QUEUE_DATA_SIZE "2048" CACHE STRING "Max packet queue entry size")
add_definitions(-DQUEUE_DATA_SIZE=${QUEUE_DATA_SIZE})

set(TAP_BUFFER_SIZE "64" CACHE STRING "Max packets count in TAP buffer")
add_definitions(-DTAP_BUFFER_SIZE=${TAP_BUFFER_SIZE})

set(TAP_QUEUES "1" CACHE STRING "TAP interface queues")
add_definitions(-DTAP_QUEUES=${TAP_QUEUES})

set(MAX_DROP_LIMIT "1" CACHE STRING "Drop limit for TCP connection")
add_definitions(-DMAX_DROP_LIMIT=${MAX_DROP_LIMIT})

set(PEFR_COUNTERS True CACHE BOOL "Add support for performance counters")
if (PEFR_COUNTERS)
  add_definitions(-DPERF_COUNTERS=${PERF_COUNTERS})
endif()

set(MEMLOG False CACHE BOOL "Add support for debugging dynamic memory allocation")
if (MEMLOG)
  add_definitions(-DMEMLOG=${PERF_COUNTERS})
endif()

set(MUTEXLOG False CACHE BOOL "Add support for debugging rw lock")
if (MUTEXLOG)
  add_definitions(-DMUTEXLOG=${MUTEXLOG})
endif()

set(ATOMIC_LIB False CACHE BOOL "Link atomic library")
if (ATOMIC_LIB)
  set(ATOMIC atomic)
else()
  set(ATOMIC)
endif()

add_executable(uVPN3 ${SOURCE_FILES})
target_link_libraries(uVPN3 ${GMP_LIBRARIES} ${KIT_CRYPTO_LIB} Threads::Threads ${ATOMIC})

include_directories(${PROJECT_SOURCE_DIR}/src/lib ${GMP_INCLUDES} ${KIT_CRYPTO_INCLUDES})
add_executable(uVPN_rsagen ${SOURCE_FILES_RSAGEN})
target_link_libraries(uVPN_rsagen ${GMP_LIBRARIES})

install(TARGETS uVPN3 uVPN_rsagen RUNTIME DESTINATION bin)
