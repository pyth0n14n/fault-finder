#include <capstone/capstone.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "unicorn_engine.h"
#include "unicorn_consts.h"
#include "structs.h"
#include "fileio.h"
#include "utils.h"
#include "configuration.h"

void my_uc_context_save(uc_engine *uc,  uc_context* the_context)
{
    uc_err err=uc_context_save(uc, the_context);
    // printf_verbose("Save. Context pointer: %p. Size: %li\n",the_context,context_size(the_context));
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to save the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }

    // If you need to check the contexts are actually correct - they can be saved to file. See next line.
    // save_context_to_file(uc, the_context,"otter-saved.bin"); 
}

void my_uc_context_alloc(uc_engine *uc,  uc_context** the_context)
{
    uc_err err=uc_context_alloc(uc, the_context);
    // printf_verbose("Alloc. Context pointer: %p. Size: %li\n",*the_context,context_size(*the_context));
    // The line above does a malloc somewhere in there! ^^^

    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to alloc the context %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
}




void save_checkpoint(uc_engine *uc,   current_run_state_t* current_run_state, uint64_t address, uint64_t num)
{
    // alloc the space for the content

    my_uc_context_alloc(uc, &current_run_state->line_details_array[num].the_context);
    
    /// Save the context (registers) to the array
    my_uc_context_save(uc, current_run_state->line_details_array[num].the_context);


    current_run_state->line_details_array[num].stack=my_malloc(binary_file_details->stack.size,"line_details_array - stack");
    uc_err err=uc_mem_read(uc, binary_file_details->stack.address, current_run_state->line_details_array[num].stack, binary_file_details->stack.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to read and save the stack %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    current_run_state->line_details_array[num].memory_main=my_malloc(binary_file_details->memory_main.size,"line_details_array - memory main");
    err=uc_mem_read(uc, binary_file_details->memory_main.address, current_run_state->line_details_array[num].memory_main, binary_file_details->memory_main.size);
    if (err != UC_ERR_OK)
    {
        fprintf(stderr,"Unable to read and save main memory %u: %s\n", err, uc_strerror(err));
        my_exit(-1);
    }
    
    current_run_state->line_details_array[num].memory_other=my_malloc (sizeof(uint8_t*)*binary_file_details->memory_other_count,"line_details_array - memory other pointer");
    for (uint64_t i=0;i<binary_file_details->memory_other_count;i++)
    {
        //save the other memory bits
        current_run_state->line_details_array[num].memory_other[i]=my_malloc ( binary_file_details->memory_other[i].size, "line_details_array - memory other");
        err=uc_mem_read(uc, binary_file_details->memory_other[i].address, current_run_state->line_details_array[num].memory_other[i], binary_file_details->memory_other[i].size);
        if (err != UC_ERR_OK)
        {
            fprintf(stderr,"Unable to read and save other memory %u: %s\n", err, uc_strerror(err));
            my_exit(-1);
        }
    }

    printf_output("Saved a checkpoint: 0x%" PRIx64 ". Count: %lli\n",address,num);
}

void convertToUppercase(char *givenStr)
{
    int i;
    for (i = 0; givenStr[i] != '\0'; i++)
    {
        if (givenStr[i] >= 'a' && givenStr[i] <= 'z')
        {
            givenStr[i] = givenStr[i] - 32;
        }
    }
}


void hook_code_stats(uc_engine *uc, uint64_t address, uint64_t size, void *user_data)
{
    #ifdef DEBUG
        printf_debug("hook_code_stats. Address 0x%" PRIx64 "\n",address);
    #endif
    current_run_state_t* current_run_state=(current_run_state_t*)user_data; 
    uint64_t num=current_run_state->instruction_count;
    if (current_run_state->in_fault_range == 0)
    {
        return;
    }
    #ifdef DEBUG
        printf_debug("hook_code_stats - in faulting range. Address: 0x%" PRIx64 "\n",address);
    #endif
    line_details_t* line = &current_run_state->line_details_array[num];

    /// Save the address to the array 
    line->address=address;

    // TODO: should be judged with my_uc_mode
    if ((binary_file_details->my_uc_arch == UC_ARCH_ARM    || binary_file_details->my_uc_arch == UC_ARCH_ARM64)) 
    {
        // THIS IS SUCH A HACK! This is a thumb instruction so we need the first bit to be 1 if we restore the checkpoints.
        #ifdef DEBUG
            printf_debug("adding one to the address 0x%" PRIx64 "\n",address);
        #endif
        line->address=address+1;
    }

    line->hit_count=address_hit(current_run_state->address_hit_counter,address);
    line->size=size;
    // Only do this if we're going to use the checkpoints (it's very memory heavvvvy with lots of checkpoints)
    if (current_run_state->start_from_checkpoint == 1 &&  line->checkpoint == true)
    {
        save_checkpoint(uc,current_run_state, address, num);
    }

    if (binary_file_details->my_cs_arch != MY_CS_ARCH_NONE)
    {
        /******** USING CAPSTONE HERE START ************/
        csh handle;
        // Use capstone to dissemble the opcodes
        if (cs_open(binary_file_details->my_cs_arch, binary_file_details->my_cs_mode, &handle) != CS_ERR_OK)
        {   
            fprintf(current_run_state->file_fprintf,"Unable to open (initialise?) capstone.\n");
        }   
        else
        {
            // Enable "detail function"
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

            uint8_t* tmp=MY_STACK_ALLOC(size * sizeof(uint8_t));
            // Read the line of code (opcode)
            if (!uc_mem_read(uc, address, tmp, size))
            {
                cs_insn *insn;

                // Now disassemble this line using capstone and display the mnemonics
                size_t count=cs_disasm(handle, tmp, size,0x1000,0, &insn);
                if (count >0)
                {
                    // Judge src/dest regs
                    // cs_regs regs_read, regs_write;
                    uint16_t regs_read[12], regs_write[12];
                    uint8_t read_count, write_count;

                    if (cs_regs_access(handle, &insn[0],
                        regs_read, &read_count,
                        regs_write, &write_count) == 0)
                    {
                        for (int i = 0; i < read_count; i++) {
                            const char* regname = cs_reg_name(handle, regs_read[i]);
                            uint64_t reg_index = register_int_from_name(regname);
                            set_bit(&line->registers_src, reg_index);

                            #ifdef DEBUG
                            printf_debug("[READ reg] %s %lld\n", regname, reg_index);
                            #endif
                        }

                        for (int i = 0; i < write_count; i++) {
                            const char* regname = cs_reg_name(handle, regs_write[i]);
                            uint64_t reg_index = register_int_from_name(regname);
                            set_bit(&line->registers_dest, reg_index);

                            #ifdef DEBUG
                            printf_debug("[WRITE reg] %s %lld\n", regname, reg_index);
                            #endif
                        }
                    }
                    line->the_registers_used = line->registers_src | line->registers_dest;

                    #ifdef DEBUG
                    printf_debug("Instruction %llu uses:\n", num);
                    printf_debug("  %s\t%s\n", insn[0].mnemonic, insn[0].op_str);
                    printf_debug("  src  bitmap: 0x0" PRIx64 "%" PRIx64 "\n",
                        (uint64_t)((line->registers_src >> 64) & 0xFFFFFFFFFFFFFFFF),
                        (uint64_t)( line->registers_src & 0xFFFFFFFFFFFFFFFF));
                    printf_debug("  dest bitmap: 0x%" PRIx64 "%" PRIx64 "\n",
                        (uint64_t)((line->registers_dest >> 64) & 0xFFFFFFFFFFFFFFFF),
                        (uint64_t) (line->registers_dest & 0xFFFFFFFFFFFFFFFF));
                    #endif
                }
                else
                {
                    #ifdef DEBUG
                        printf_debug("Unable to disassemble.\n");
                    #endif 
                }
                cs_free (insn,count);
            } 
            else
            {
                fprintf(stderr, "Unable to read from address: 0x%" PRIx64 " size: 0x%" PRIx64 ". \n", address,size);
                my_exit(-1);
            }
        }
        cs_close(&handle);
        /******** USING CAPSTONE HERE END ************/
    }
    else
    {
            /******** Not using any disassembly START ************/
            line->the_registers_used=0xFFFFFFFFFFFFFFFF;
           /******** Not using any disassembly END ************/
    }
}
