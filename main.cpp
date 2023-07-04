#include <iostream>
#include "find_symbol.h"
#include "elf64.h"
#include <stdbool.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/mman.h>
#include <sys/ptrace.h>

void run_sys_debugger(pid_t child_pid, unsigned long func_addr, bool first_call) {
    int wait_status;
    struct user_regs_struct regs;
    unsigned long func_call_count = 0; // Counter for function calls

    wait(&wait_status);
    bool inside_func = false;

    while (WIFSTOPPED(wait_status)) {
        ptrace(PTRACE_GETREGS, child_pid, 0, &regs);

        if (regs.rip - 1 == func_addr) {
            inside_func = true;

            // Print the first parameter passed to the function
            if (first_call) {
                printf("PRF:: run %llu first parameter is %d\n", func_call_count, regs.rdi);
                first_call = false;
            }

            // Increment the function call count if it's not the first call
            if (!first_call) {
                func_call_count++;
            }

            // Set breakpoint at the caller to the debugged function
            unsigned long data = ptrace(PTRACE_PEEKTEXT, child_pid, (void*)func_addr, NULL);
            unsigned long data_trap = (data & 0xFFFFFFFFFFFFFF00) | 0xCC;
            ptrace(PTRACE_POKETEXT, child_pid, (void*)func_addr, (void*)data_trap);
        }

        ptrace(PTRACE_SYSCALL, child_pid, NULL, NULL);
        wait(&wait_status);

        if (inside_func && regs.rip == func_addr) {
            inside_func = false;
        }
    }

    printf("PRF:: run %llu returned with %d\n", func_call_count, regs.rax);
}


pid_t run_target(const char* func, char** argv) {
    pid_t pid = fork();

    if (pid > 0) {
        return pid;
    } else if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            perror("ptrace");
            exit(1);
        }
        execl(func, *(argv + 2), NULL);
    } else {
        perror("fork");
        exit(1);
    }
}





int main(int argc, char** argv) {
char* func_name = argv[0];
char* program_name = argv[1];
int *val = 0;
unsigned long res = find_symbol(func_name, program_name,val);

//check if the program is an exe:
if(*val == -3){
    printf("PRF:: %s not an executable!\n", program_name);
    return 0;
}

//check for the func_name in symtab:
    if(*val == -1){
        printf("PRF:: %s not found! :(\n", func_name);
        return 0;
    }

//check if func_name is global:
    if(*val == -2){
        printf("PRF:: %s is not a global symbol! :(\n", func_name);
        return 0;
    }

    Elf64_Addr real_func_address;
//check if func_name is an external func:
    if(*val == -4){
       // do step 5:
        FILE *file = fopen(program_name, "rb");
        if (file == NULL) {
            return -1;
        }

        Elf64_Ehdr elf_header;
        if(fread(&elf_header, sizeof(elf_header), 1, file)!=1){
            fclose(file);
            return -1;
        }

        // find section table offset from beginning of file:
        Elf64_Off section_offset=elf_header.e_shoff;
        // size of entry in section table:
        Elf64_Half section_size=elf_header.e_shentsize; //not used
        //num of entries in section table:
        Elf64_Half section_num=elf_header.e_shnum;

        Elf64_Shdr* section_header_table= (Elf64_Shdr*)(malloc(sizeof(Elf64_Shdr) * section_num));
        /**setting file to point at the start of section header table**/
        fseek(file,(long) section_offset, SEEK_SET);
        if(fread(section_header_table,sizeof(Elf64_Shdr),section_num,file)!=section_num){
            free(section_header_table);
            fclose(file);
            return -1;
        }

        //find all rela section index inside section header table:
        int index=0;
        for(int i=0;i<section_num;++i){
            if(section_header_table[i].sh_type==4) {
                index=i;
            }
            else{
                continue;
            }
            //go to the section and find the str table connected to it:

            unsigned long num_entries_rela = section_header_table[index].sh_size/section_header_table[index].sh_entsize;; //Elf64_Xword for num symbols
            int rela_dynsym_index = (int)section_header_table[index].sh_link;
            unsigned long dynsym_offset = section_header_table[rela_dynsym_index].sh_offset;
            int dynsym_entry_size = section_header_table[rela_dynsym_index].sh_entsize;
            int str_offset = (int)section_header_table[rela_dynsym_index].sh_link;

            //create table:
            Elf64_Rela* curr_rela_table=(Elf64_Rela*)malloc(sizeof(Elf64_Rela)*num_entries_rela);
            /**setting file to point at the start of curr table**/
            fseek(file, (long)section_header_table[index].sh_offset,SEEK_SET);

            //reading curr table from file and saving it
            if(fread(curr_rela_table, sizeof(Elf64_Rela), num_entries_rela, file)!=num_entries_rela){
                fclose(file);
                free(section_header_table);
                free(curr_rela_table);
                return -1;
            }
            //iterate over curr rela table entries:
            for(int i=0; i<num_entries_rela; i++){
                Elf64_Xword info = curr_rela_table[i].r_info;
                int index_in_dynsym = ELF64_R_SYM(info);

                //go to dynsym and find the symbol of this index:
                Elf64_Sym* dynsym_entry = (Elf64_Sym*)malloc(sizeof(Elf64_Sym));
                fseek(file,dynsym_offset+index_in_dynsym*(dynsym_entry_size),SEEK_SET);
                fread(dynsym_entry,sizeof(Elf64_Sym),1,file);
                unsigned long str_entry_offset = dynsym_entry->st_name;
                if(comparing_name(file, str_offset+str_entry_offset,func_name)==true){
                    //found the symbol!
                    Elf64_Addr address = curr_rela_table[i].r_offset;
                    Elf64_Addr* ptr = (Elf64_Addr*)address;
                    real_func_address = (*ptr)-6;
                }
            }
        }
    }
    else if(*val == 1) {
        real_func_address = res;
    }

    //step 6:
    pid_t child_pid = run_target(program_name, argv);
    run_sys_debugger(child_pid, real_func_address, true); // Initial call is the first call

    return 0;
}
