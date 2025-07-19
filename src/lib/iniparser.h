/* Copyright (c) 2025 Jakub Juszczakiewicz
 * All rights reserved.
 */

#pragma once

typedef int (*iniparser_next_section)(const char * section_name, void * data);
typedef int (*iniparser_next_value)(const char * name, const char * value,
    void * data);

int iniparser(const char * path, iniparser_next_section section_callback,
    iniparser_next_value value_callback, void * data);
