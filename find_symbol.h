//
// Created by user on 04/07/2023.
//

#ifndef UNTITLED4_FIND_SYMBOL_H
#define UNTITLED4_FIND_SYMBOL_H

unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val);
bool comparing_name(FILE* file,Elf64_Off offset_to_name,const char* symbol_name_given);

#endif //UNTITLED4_FIND_SYMBOL_H
