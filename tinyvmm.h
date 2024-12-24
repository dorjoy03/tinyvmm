/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#ifndef TINYVMM_H
#define TINYVMM_H

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

struct vm_info {
    char *kernel_path;
    char *initrd_path;
    char *cmdline;
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    int kvm_run_size;
    struct kvm_run *kvm_run;
    uint8_t *ram_ptr;
    size_t ram_size;
};

void tinyvmm_log(FILE *restrict stream, const char *restrict format, ...);

#endif /* TINYVMM_H */
