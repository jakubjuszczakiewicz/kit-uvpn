/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#include "version.h"
#include <string.h>

#define VERSION_MAJOR 3
#define VERSION_MINOR 5
#define VERSION_PATCH 2
#define VERSION_SUBSTR ""

#define STR(s) #s
#define MAKE_VER(ma, mi, pa, st) (STR(ma) "." STR(mi) "." STR(pa) st)

#define VERSION_STR MAKE_VER(VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_SUBSTR)

#define KIT_UVPN_NAME_STR "kit-uvpn"

uint16_t kit_uvpn_version[3] = { VERSION_MAJOR, VERSION_MINOR,
    VERSION_PATCH };
size_t kit_uvpn_version_str_len = strlen(VERSION_STR);
char kit_uvpn_version_str[] = VERSION_STR;

size_t kit_uvpn_name_len = strlen(KIT_UVPN_NAME_STR);
char kit_uvpn_name[] = KIT_UVPN_NAME_STR;
