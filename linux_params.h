/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#ifndef LINUX_PARAMS_H
#define LINUX_PARAMS_H

#include <asm/bootparam.h>

/*
 * A bzImage built from linux-6.66.66 seems to have cmdline_size 2047.
 * So let's set the buffer size to 2048.
 */
#define COMMANDLINE_SIZE 2048

/*
 * This is a wrapper struct over linux's struct boot_params with commandline
 * and gdt_table appended which we later need to put in memory and point to.
 *
 * 'struct boot_params' is defined in arch/x86/include/uapi/asm/bootparam.h
 * which maps to the initial bytes of the bzImage.
 *
 * ref: https://www.kernel.org/doc/html/latest/arch/x86/boot.html
 * ref: https://www.kernel.org/doc/html/latest/arch/x86/zero-page.html
 */
struct  __attribute__ ((packed)) linux_params {
    struct boot_params boot_params;
    uint8_t commandline[COMMANDLINE_SIZE];
    uint64_t gdt_table[4];
};

#endif /* LINUX_PARAMS_H */
