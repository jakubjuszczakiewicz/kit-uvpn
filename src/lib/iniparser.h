/* Copyright (c) 2023 Krypto-IT Jakub Juszczakiewicz
 * All rights reserved.
 */

#ifndef __INI_PARSER_H__
#define __INI_PARSER_H__

typedef int (*iniparser_next_section)(const char * section_name, void * data);
typedef int (*iniparser_next_value)(const char * name, const char * value,
    void * data);

int iniparser(const char * path, iniparser_next_section section_callback,
    iniparser_next_value value_callback, void * data);

#endif
