#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include "find_symbol.h"
#include "elf64.h"

#define	ET_NONE	0	//No file type 
#define	ET_REL	1	//Relocatable file 
#define	ET_EXEC	2	//Executable file 
#define	ET_DYN	3	//Shared object file 
#define	ET_CORE	4	//Core file 

bool comparing_name(FILE* file,Elf64_Off offset_to_name,const char* symbol_name_given){
    fseek(file,offset_to_name,SEEK_SET);
    int sym_char_strtab =fgetc(file);
    int j=0;
    while(sym_char_strtab!= EOF && sym_char_strtab != '\0') {
        if(sym_char_strtab!=symbol_name_given[j]) {
            return false;
        }
        j++;
        sym_char_strtab=fgetc(file);
    }
    return true;
}

/* symbol_name		- The symbol (maybe function) we need to search for.
 * exe_file_name	- The file where we search the symbol in.
 * error_val		- If  1: A global symbol was found, and defined in the given executable.
 * 			- If -1: Symbol not found.
 *			- If -2: Only a local symbol was found.
 * 			- If -3: File is not an executable.
 * 			- If -4: The symbol was found, it is global, but it is not defined in the executable.
 * return value		- The address which the symbol_name will be loaded to, if the symbol was found and is global.
 */
unsigned long find_symbol(char* symbol_name, char* exe_file_name, int* error_val) {
    FILE *file = fopen(exe_file_name, "rb");
    if (file == NULL) {
        return -1;
    }

    Elf64_Ehdr elf_header;
    if(fread(&elf_header, sizeof(elf_header), 1, file)!=1){
        fclose(file);
        return -1;
    }
    Elf64_Half elf_type = elf_header.e_type;

    //check if the type is exe:
    if (elf_type != ET_EXEC) {
        *error_val = -3;
        fclose(file);
        return -1;
    }

    //else, the ELF file is an exe file:
    // find section table offset from beginning of file:
    Elf64_Off section_offset=elf_header.e_shoff;
    // size of entry in section table:
    Elf64_Half section_size=elf_header.e_shentsize; //not used
    //num of entries in section table:
    Elf64_Half section_num=elf_header.e_shnum;

    Elf64_Shdr* section_header_table=malloc(sizeof(Elf64_Shdr)*section_num);
    /**setting file to point at the start of section header table**/
    fseek(file,(long) section_offset, SEEK_SET);
    if(fread(section_header_table,sizeof(Elf64_Shdr),section_num,file)!=section_num){
        free(section_header_table);
        fclose(file);
        return -1;
    }

    //find SYMTAB index inside section header table:
    int symtab_index=-1;
    for(int i=0;i<section_num;++i){
        if(section_header_table[i].sh_type==2) {
            symtab_index=i;
        }
    }
    if (symtab_index==-1){
        free(section_header_table);
        fclose(file);
        return -1;
    }

    /**file curr at the start of section table**/

    //offset of symtable from beginning of file:
    Elf64_Off symtable_offset = section_header_table[symtab_index].sh_offset;
    // entry size of symbol in symbol table:
    Elf64_Xword entry_size_symtable = section_header_table[symtab_index].sh_entsize;
    // symbol table size:
    Elf64_Xword sym_table_size = section_header_table[symtab_index].sh_size;
    // num of section in section header table that is the string table belonging to symtable - strtable:
    Elf64_Word sym_table_link = section_header_table[symtab_index].sh_link;
    //saving the index of strtab (which is the link of symtab)
    int strtab_index=(int)sym_table_link;

    unsigned long num_symbols = sym_table_size/entry_size_symtable; //Elf64_Xword for num symbols

    //create sym_table:
    Elf64_Sym* symbol_table=malloc(sizeof(Elf64_Sym)*num_symbols);
    /**setting file to point at the start of symbol table**/
    fseek(file, (long)symtable_offset,SEEK_SET);

    //reading symbol table from file and saving it
    if(fread(symbol_table, sizeof(Elf64_Sym), num_symbols, file)!=num_symbols){
        fclose(file);
        free(section_header_table);
        free(symbol_table);
        return -1;
    }

    //iterate over sym_table:
    Elf64_Off strtab_offset=section_header_table[strtab_index].sh_offset;
    int flag = 0;
    unsigned long address=0;
    for(int i=0;i<num_symbols;++i){
        //comparing symbol name:
        if(comparing_name(file,strtab_offset+(symbol_table[i].st_name),symbol_name)==true){
            if(ELF64_ST_BIND(symbol_table[i].st_info)==1){ //GLOBAL
                if(symbol_table[i].st_shndx==0){ //NOT IN FILE
                    *error_val = -4;
                    free(symbol_table);
                    free(section_header_table);
                    fclose(file);
                    return -1;

                }
                else {
                    *error_val = 1;
                    address=symbol_table[i].st_value;
                    free(symbol_table);
                    free(section_header_table);
                    fclose(file);
                    return address;
                }
            }
            else if(ELF64_ST_BIND(symbol_table[i].st_info)==0 && symbol_table[i].st_value>0){ //LOCAL
                flag =1;
            }
        }
    }


    //if symbol is not found in sym_table:
    *error_val = -1;

    //if symbol is found but is a local symbol:
    if(flag==1){
        *error_val = -2;
    }


    free(symbol_table);
    free(section_header_table);
    fclose(file);
    return -1;
}



int main(int argc, char *const argv[]) {
	int err = 0;
	unsigned long addr = find_symbol(argv[1], argv[2], &err);

	if (err >= 0)
		printf("%s will be loaded to 0x%lx\n", argv[1], addr);
	else if (err == -2)
		printf("%s is not a global symbol! :(\n", argv[1]);
	else if (err == -1)
		printf("%s not found!\n", argv[1]);
	else if (err == -3)
		printf("%s not an executable! :(\n", argv[2]);
	else if (err == -4)
		printf("%s is a global symbol, but will come from a shared library\n", argv[1]);
	return 0;
}