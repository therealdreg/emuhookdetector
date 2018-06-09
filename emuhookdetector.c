/* Warning!!: the code is bullshit (is only a beta prototype).
-
Compile:
gcc -pthread -o emuhookdetector_dynamic emuhookdetector.c -lunicorn -lcapstone
gcc -static -pthread -o emuhookdetector_static emuhookdetector.c /usr/lib/libunicorn.a /usr/lib/libcapstone.a -lm
-
MIT LICENSE - Copyright (c) emuhookdetector 0.1Beta-crap - January 2016
by: David Reguera Garcia aka Dreg - dreg@fr33project.org
https://github.com/David-Reguera-Garcia-Dreg
http://www.fr33project.org
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include <unicorn/unicorn.h>
#include <capstone/capstone.h>
#include <string.h>
#include <dirent.h>

#define ADDRESS 0x1000000
#define SIZE_DSD 0x100
#define MIN(a,b) (((a)<(b))?(a):(b))

void* top_addr = NULL;
uint64_t next_rip = 0;

int main(int argc, char** argv, char** envp);
FILE* report = NULL;

static void hook_code64(uc_engine* uc, uint64_t address, uint32_t size, void* user_data)
{
    uint64_t rip = 0;
    uint8_t tmp[16];
    uint64_t rip_converted = 0;

    memset(tmp, 0, sizeof(tmp));

    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    rip_converted = (rip - ADDRESS) + ((uint64_t)top_addr);

    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
    printf(">>> RIP(converted) is 0x%"PRIx64 "\n", rip_converted);
    printf("*** RIP = 0x%x ***: ", rip);
    fprintf(report, "*** RIP = 0x%x (converted: 0x%"PRIx64 ") ***: \n\t", rip, rip_converted);

    size = MIN(sizeof(tmp), size);
    if (!uc_mem_read(uc, address, tmp, size))
    {
        uint32_t i;
        for (i = 0; i < size; i++)
        {
            printf("%02x ", tmp[i]);
            fprintf(report, "%02x ", tmp[i]);
        }
        printf("\n");
        fprintf(report, "\n");
    }

    csh handle;
    cs_insn* insn;
    size_t count;

    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK)
    {
        return;
    }

    count = cs_disasm(handle, tmp, size, rip_converted, 0, &insn);
    if (count > 0)
    {
        size_t j;
        for (j = 0; j < count; j++)
        {
            printf("0x%"PRIx64":\t%s\t\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            fprintf(report, "\t\t\t\t\t\t\t\t%s\t\t%s\n", insn[j].mnemonic, insn[j].op_str);
            if (strcmp(insn[j].mnemonic, "jmp") == 0)
            {
                puts("jmp detected");
                if (strstr(insn[j].op_str, "qword ptr [rip +") != NULL)
                {
                    unsigned int rel_jmp = 0;
                    uint64_t ptr_content = 0;
                    puts("relative to rip +");
                    sscanf(insn[j].op_str, "qword ptr [rip +%x]", &rel_jmp);
                    printf("readded ptr+: 0x%x\n", rel_jmp);
                    ptr_content = rip_converted + size + rel_jmp;
                    printf("readding ptr content (rip+sizeinst+relval) from: 0x%"PRIx64 "\n", ptr_content);
                    ptr_content = *((uint64_t*)ptr_content);
                    printf("content:  0x%"PRIx64 "\n", ptr_content);
                    printf("Stopping emulation and Changing rip to:  0x%"PRIx64 "\n", ptr_content);
                    next_rip = ptr_content;
                    uc_emu_stop(uc);
                }
            }
        }

        cs_free(insn, count);
    }
    else
    {
        printf("ERROR: Failed to disassemble given code!\n");
    }

    cs_close(&handle);
}

static void hook_mem64(uc_engine* uc, uc_mem_type type,
                       uint64_t address, int size, int64_t value, void* user_data)
{
    switch (type)
    {
    default:
        break;
    case UC_MEM_READ:
        printf(">>> Memory is being READ at 0x%"PRIx64 ", data size = %u\n",
               address, size);
        break;
    case UC_MEM_WRITE:
        printf(">>> Memory is being WRITE at 0x%"PRIx64 ", data size = %u, data value = 0x%"PRIx64 "\n",
               address, size, value);
        break;
    }
}

static void emuhookdetector(void)
{
    uc_engine* uc;
    uc_err err;
    uc_hook trace1, trace2, trace3, trace4;

    int64_t rax = 0;
    int64_t rbx = 0;
    int64_t rcx = 0;
    int64_t rdx = 0;
    int64_t rsi = 0;
    int64_t rdi = 0;
    int64_t r8 = 0;
    int64_t r9 = 0;
    int64_t r10 = 0;
    int64_t r11 = 0;
    int64_t r12 = 0;
    int64_t r13 = 0;
    int64_t r14 = 0;
    int64_t r15 = 0;
    int64_t rsp = ADDRESS + 0x200000;
    int i = 0;

    printf("Emulate x86_64 code\n");

    for (i = 0; i < 2; i++)
    {
        err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
        if (err)
        {
            printf("Failed on uc_open() with error returned: %u\n", err);
            return;
        }

        uc_mem_map(uc, (uint64_t)ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

        top_addr = readdir;
        if (next_rip != 0)
        {
            top_addr = next_rip;
        }
        printf("\ntop_addr: 0x%"PRIx64 "\n\n", (uint64_t)top_addr);
        printf("\nADDRESS: 0x%"PRIx64 "\n\n", (uint64_t)ADDRESS);

        if (uc_mem_write(uc, (uint64_t)ADDRESS, (uint64_t)top_addr, SIZE_DSD))
        {
            printf("Failed to write emulation code to memory, quit!\n");
            return;
        }

        uc_reg_write(uc, UC_X86_REG_RSP, &rsp);

        uc_reg_write(uc, UC_X86_REG_RAX, &rax);
        uc_reg_write(uc, UC_X86_REG_RBX, &rbx);
        uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
        uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
        uc_reg_write(uc, UC_X86_REG_RSI, &rsi);
        uc_reg_write(uc, UC_X86_REG_RDI, &rdi);
        uc_reg_write(uc, UC_X86_REG_R8, &r8);
        uc_reg_write(uc, UC_X86_REG_R9, &r9);
        uc_reg_write(uc, UC_X86_REG_R10, &r10);
        uc_reg_write(uc, UC_X86_REG_R11, &r11);
        uc_reg_write(uc, UC_X86_REG_R12, &r12);
        uc_reg_write(uc, UC_X86_REG_R13, &r13);
        uc_reg_write(uc, UC_X86_REG_R14, &r14);
        uc_reg_write(uc, UC_X86_REG_R15, &r15);

        uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code64, NULL, (uint64_t)ADDRESS, ((uint64_t)ADDRESS) + SIZE_DSD);
        uc_hook_add(uc, &trace3, UC_HOOK_MEM_WRITE, hook_mem64, NULL, 1, 0);
        uc_hook_add(uc, &trace4, UC_HOOK_MEM_READ, hook_mem64, NULL, 1, 0);

        err = uc_emu_start(uc, (uint64_t)ADDRESS, NULL, 0, 0);
        if (err)
        {
            printf("Failed on uc_emu_start() with error returned %u: %s\n",
                   err, uc_strerror(err));
        }

        printf(">>> Emulation done. Below is the CPU context\n");

        /*
        uc_reg_read(uc, UC_X86_REG_RAX, &rax);
        uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
        uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
        uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
        uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
        uc_reg_read(uc, UC_X86_REG_RDI, &rdi);
        uc_reg_read(uc, UC_X86_REG_R8, &r8);
        uc_reg_read(uc, UC_X86_REG_R9, &r9);
        uc_reg_read(uc, UC_X86_REG_R10, &r10);
        uc_reg_read(uc, UC_X86_REG_R11, &r11);
        uc_reg_read(uc, UC_X86_REG_R12, &r12);
        uc_reg_read(uc, UC_X86_REG_R13, &r13);
        uc_reg_read(uc, UC_X86_REG_R14, &r14);
        uc_reg_read(uc, UC_X86_REG_R15, &r15);

        printf(">>> RAX = 0x%" PRIx64 "\n", rax);
        printf(">>> RBX = 0x%" PRIx64 "\n", rbx);
        printf(">>> RCX = 0x%" PRIx64 "\n", rcx);
        printf(">>> RDX = 0x%" PRIx64 "\n", rdx);
        printf(">>> RSI = 0x%" PRIx64 "\n", rsi);
        printf(">>> RDI = 0x%" PRIx64 "\n", rdi);
        printf(">>> R8 = 0x%" PRIx64 "\n", r8);
        printf(">>> R9 = 0x%" PRIx64 "\n", r9);
        printf(">>> R10 = 0x%" PRIx64 "\n", r10);
        printf(">>> R11 = 0x%" PRIx64 "\n", r11);
        printf(">>> R12 = 0x%" PRIx64 "\n", r12);
        printf(">>> R13 = 0x%" PRIx64 "\n", r13);
        printf(">>> R14 = 0x%" PRIx64 "\n", r14);
        printf(">>> R15 = 0x%" PRIx64 "\n", r15);
        */
        uc_close(uc);

    }
}

int main(int argc, char** argv, char** envp)
{
    puts("\n\nMIT LICENSE - Copyright (c) emuhookdetector 0.1Beta-crap - January 2016\n"
         "by: David Reguera Garcia aka Dreg - dreg@fr33project.org\n"
         "https://github.com/David-Reguera-Garcia-Dreg\n"
         "http://www.fr33project.org\n\n"
         "Compile the static & dynamic exes:\n"
         "Instructions: check the ldd output of each executable, the static should be empty.\n"
         "\texecute the static compiled & dynamic compiled and compare each report.txt generated to find suspicious code flow\n\n");

    char* report_name = "./report.txt";
    report = fopen(report_name, "wb+");
    if (report == NULL)
    {
        perror("creating report.txt file");
        return -1;
    }
    printf("\nreport file created: %s\n\n", report_name);
    DIR* dir;
    struct dirent* ent;
    register char c;

    printf("\nreaddir: 0x%"PRIx64 "\n\n", (uint64_t)readdir);

    if ((dir = opendir("/proc")) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            c = ent->d_name[0];
        }
        closedir(dir);
    }
    if ((dir = opendir("/proc")) != NULL)
    {
        while ((ent = readdir(dir)) != NULL)
        {
            c = ent->d_name[0];
        }
        closedir(dir);
    }

    printf("\nplt init! readdir: 0x%"PRIx64 "\n\n", (uint64_t)readdir);

    emuhookdetector();

    fflush(report);
    fclose(report);
    return 0;
}
