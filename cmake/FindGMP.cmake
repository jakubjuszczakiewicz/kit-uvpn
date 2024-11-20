include(FindPackageHandleStandardArgs)

if (GMP_DIR)
  find_library(GMP_LIB
               NAMES gmp libgmp
               PATHS ${GMP_DIR}
               PATH_SUFFIXES ${lib_suffixes}
               NO_DEFAULT_PATH
               DOC "GMP library")
  find_path(GMP_HEADERS
            NAMES gmp.h
            PATHS ${GMP_DIR}
            PATH_SUFFIXES ${header_suffixes}
            NO_DEFAULT_PATH
            DOC "GMP headers")

else (GMP_DIR)
  find_library(GMP_LIB
               NAMES gmp libgmp
               PATH_SUFFIXES ${lib_suffixes}
               DOC "GMP library")
  find_path(GMP_HEADERS
            NAMES gmp.h
            PATH_SUFFIXES ${header_suffixes}
            DOC "GMP headers")
endif (GMP_DIR)

find_package_handle_standard_args(GMP REQUIRED_VARS GMP_LIB GMP_HEADERS)

if (GMP_FOUND)
  set(GMP_LIBRARIES "${GMP_LIB}")
  set(GMP_INCLUDES "${GMP_HEADERS}")
endif (GMP_FOUND)
