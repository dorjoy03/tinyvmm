/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

#include <linux/kvm.h>
#include <linux/kvm_para.h>

#include "linux_params.h"

struct vm_info {
    char *kernel_path;
    char *initrd_path;
    int kvm_fd;
    int vm_fd;
    int vcpu_fd;
    int kvm_run_size;
    struct kvm_run *kvm_run;
    uint8_t *ram_ptr;
    size_t ram_size;
};

/*
 * Logs from tinyvmm itself should be prefixed by "tinyvmm: "
 */
void tinyvmm_log(FILE *restrict stream, const char *restrict format, ...)
{
    fprintf(stream, "tinyvmm: ");

    va_list args;
    va_start(args, format);
    vfprintf(stream, format, args);
    va_end(args);

    fprintf(stream, "\n");
    return;
}

#define CPUID_APIC (1 <<  9)
#define CPUID_ACPI (1 << 22)

void kvm_set_cpuid(struct vm_info *vm)
{
    struct kvm_cpuid2 *kvm_cpuid;
    uint32_t nent = 128;
    size_t size;

    size = sizeof(struct kvm_cpuid2) + nent * sizeof(kvm_cpuid->entries[0]);
    kvm_cpuid = malloc(size);
    if (!kvm_cpuid) {
        tinyvmm_log(stderr, "malloc failed for kvm_cpuid: %s", strerror(errno));
        exit(1);
    }
    memset(kvm_cpuid, 0, size);

    kvm_cpuid->nent = nent;
    if (ioctl(vm->kvm_fd, KVM_GET_SUPPORTED_CPUID, kvm_cpuid) < 0) {
        tinyvmm_log(stderr, "KVM_GET_SUPPORTED_CPUID failed: %s", strerror(errno));
        exit(1);
    }

    for(uint32_t i = 0; i < kvm_cpuid->nent; i++) {
        /*
         * Disable APIC and ACPI for CPUID function 0x01 or 0x80000001
         * i.e., for general processor information or extended processor
         * features.
         */
        struct kvm_cpuid_entry2 *entry = &kvm_cpuid->entries[i];
        if (entry->function == 0x01 || entry->function == 0x80000001) {
            entry->edx &= ~(CPUID_APIC | CPUID_ACPI);
        }
    }

    if (ioctl(vm->vcpu_fd, KVM_SET_CPUID2, kvm_cpuid) < 0) {
        tinyvmm_log(stderr, "KVM_SET_CPUID2 failed: %s", strerror(errno));
        exit(1);
    }
    free(kvm_cpuid);
}

void kvm_init(struct vm_info *vm)
{
    uint64_t base_addr;

    vm->kvm_fd = open("/dev/kvm", O_RDWR);
    if (vm->kvm_fd < 0) {
        tinyvmm_log(stderr, "open /dev/kvm failed: %s", strerror(errno));
        exit(1);
    }

    if (ioctl(vm->kvm_fd, KVM_GET_API_VERSION, 0) != 12) {
        tinyvmm_log(stderr, "Expected KVM_GET_API_VERSION 12");
        exit(1);
    }

    vm->vm_fd = ioctl(vm->kvm_fd, KVM_CREATE_VM, 0);
    if (vm->vm_fd < 0) {
        tinyvmm_log(stderr, "KVM_CREATE_VM failed: %s", strerror(errno));
        exit(1);
    }

    /*
     * The following 2 ioctl calls are needed for intel hardware that don't
     * support unrestricted_guest mode i.e., running the guest in 16-bit
     * real-mode or in protected mode without paging enbaled. Otherwise,
     * for newer processors from "westmere" generation, they should not be
     * needed as they support unrestricted_guest mode.
     *
     * ref: https://lwn.net/Articles/658883/
     * ref: https://lwn.net/Articles/658511/
     */

    /*
     * ref: https://docs.kernel.org/virt/kvm/api.html#kvm-set-identity-map-addr
     * If set to 0, it is reset to 0xfffbc000.
     */
    base_addr = 0xfffbc000;
    if (ioctl(vm->vm_fd, KVM_SET_IDENTITY_MAP_ADDR, &base_addr) < 0) {
        tinyvmm_log(stderr, "KVM_SET_IDENTITY_MAP_ADDR failed: %s",
                    strerror(errno));
        exit(1);
    }

    /*
     * ref: https://docs.kernel.org/virt/kvm/api.html#kvm-set-tss-addr
     * Address set to after 4K of base_addr.
     */
    if (ioctl(vm->vm_fd, KVM_SET_TSS_ADDR, (long) (base_addr + 0x1000)) < 0) {
        tinyvmm_log(stderr, "KVM_SET_TSS_ADDR failed: %s", strerror(errno));
        exit(1);
    }

    if (ioctl(vm->vm_fd, KVM_CREATE_IRQCHIP, 0) < 0) {
        tinyvmm_log(stderr, "KVM_CREATE_IRQCHIP failed: %s", strerror(errno));
        exit(1);
    }

    struct kvm_pit_config pit = {
        .flags = 0,
    };
    if (ioctl(vm->vm_fd, KVM_CREATE_PIT2, &pit) < 0) {
        tinyvmm_log(stderr, "KVM_CREATE_PIT2 failed: %s", strerror(errno));
        exit(1);
    }

    vm->vcpu_fd = ioctl(vm->vm_fd, KVM_CREATE_VCPU, 0);
    if (vm->vcpu_fd < 0) {
        tinyvmm_log(stderr, "KVM_CREATE_VCPU failed: %s", strerror(errno));
        exit(1);
    }

    /* Set CPUID */
    kvm_set_cpuid(vm);

    vm->kvm_run_size = ioctl(vm->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);
    if (vm->kvm_run_size < 0) {
        tinyvmm_log(stderr, "KVM_GET_VCPU_MMAP_SIZE failed: %s", strerror(errno));
        exit(1);
    }

    vm->kvm_run = mmap(NULL, vm->kvm_run_size, PROT_READ | PROT_WRITE, MAP_SHARED,
                       vm->vcpu_fd, 0);
    if (!vm->kvm_run) {
        tinyvmm_log(stderr, "mmap for kvm_run struct failed: %s", strerror(errno));
        exit(1);
    }

    /* Set 512 MiB RAM */
    vm->ram_size = 512 * 1024 * 1024;
    vm->ram_ptr = mmap(NULL, vm->ram_size, PROT_READ | PROT_WRITE,
                   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (!vm->ram_ptr) {
        tinyvmm_log(stderr, "mmap failed to get ram: %s", strerror(errno));
        exit(1);
    }
    struct kvm_userspace_memory_region region = {
        .slot = 0,
        .guest_phys_addr = 0,
        .memory_size = vm->ram_size,
        .userspace_addr = (uint64_t) vm->ram_ptr,
    };
    if (ioctl(vm->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
        tinyvmm_log(stderr, "KVM_SET_USER_MEMORY_REGION failed: %s",
                    strerror(errno));
        exit(1);
    }
}

size_t load_file(const char *path, uint8_t **buf)
{
    FILE *f;
    int ret;
    long s;
    size_t size;
    uint8_t *file;

    f = fopen(path, "rb");
    if (!f) {
        tinyvmm_log(stderr, "fopen failed for path %s: %s", path, strerror(errno));
        exit(1);
    }

    ret = fseek(f, 0, SEEK_END);
    if (ret == -1) {
        tinyvmm_log(stderr, "fseek failed for path %s: %s", path, strerror(errno));
        exit(1);
    }

    s = ftell(f);
    if (s < 0) {
        tinyvmm_log(stderr, "ftell failed for path %s: %s", path, strerror(errno));
        exit(1);
    }
    size = (size_t) s;

    file = malloc(size);
    if (!file) {
        tinyvmm_log(stderr, "malloc failed: %s", strerror(errno));
        exit(1);
    }
    ret = fseek(f, 0, SEEK_SET);
    if (ret == -1) {
        tinyvmm_log(stderr, "fseek failed for path %s: %s", path, strerror(errno));
        exit(1);
    }

    if (fread(file, 1, size, f) != size) {
        tinyvmm_log(stderr, "fread failed for path %s", path);
        exit(1);
    }
    fclose(f);

    *buf = file;
    return size;
}

/*
 * Sets both sregs and regs
 */
void kvm_set_regs(struct vm_info *vm, uint64_t gdt_base, uint16_t gdt_limit,
                  uint16_t cs_gdt_ind, uint16_t ds_gdt_ind,
                  uint64_t kernel_load_addr, uint64_t kernel_params_addr)
{
    struct kvm_sregs sregs;
    struct kvm_segment seg;
    struct kvm_regs regs;

    /* Set flat protected mode (paging disabled) */
    if (ioctl(vm->vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        tinyvmm_log(stderr, "KVM_GET_SREGS failed: %s", strerror(errno));
        exit(1);
    }

    /* Set CR0 protected mode */
    sregs.cr0 |= (1 << 0);
    sregs.gdt.base = gdt_base;
    sregs.gdt.limit = gdt_limit;

    memset(&seg, 0, sizeof(seg));

    seg.limit = 0xffffffff;
    seg.present = 1;
    seg.db = 1;
    seg.s = 1; /* code/data */
    seg.g = 1; /* 4KB granularity */

    seg.type = 0xb; /* code */
    seg.selector = cs_gdt_ind << 3; // Each GDT entry is 8 bytes
    sregs.cs = seg;

    seg.type = 0x3; /* data */
    seg.selector = ds_gdt_ind << 3; // Each GDT entry is 8 bytes
    sregs.ds = seg;
    sregs.es = seg;
    sregs.ss = seg;
    sregs.fs = seg;
    sregs.gs = seg;

    if (ioctl(vm->vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        tinyvmm_log(stderr, "KVM_SET_SREGS failed: %s", strerror(errno));
        exit(1);
    }

    memset(&regs, 0, sizeof(regs));
    regs.rip = kernel_load_addr;
    regs.rsi = kernel_params_addr;
    regs.rflags = 0x2;
    if (ioctl(vm->vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        tinyvmm_log(stderr, "KVM_SET_REGS failed: %s", strerror(errno));
        exit(1);
    }
}

/* ref: https://www.kernel.org/doc/html/latest/arch/x86/boot.html#memory-layout */
#define KERNEL_PARAMS_ADDR 0x00090000 // 448 KiB below 1 MiB
#define KERNEL_LOAD_ADDR   0x00100000 // at 1 MiB
#define INITRD_LOAD_ADDR   0x02000000 // at 32 MiB

#define CS_GDT_INDEX       2
#define DS_GDT_INDEX       3

void load_kernel(struct vm_info *vm)
{
    uint8_t *buf;
    size_t buf_size;
    int setup_sects;
    int setup_hdr_start;
    int setup_hdr_end;
    size_t setup_code_size;
    size_t kernel_size;
    bool is_bzImage;
    struct linux_params *linux_params;

    buf_size = load_file(vm->kernel_path, &buf);

    if ((size_t) buf_size < sizeof(struct boot_params)) {
        tinyvmm_log(stderr, "Too small kernel");
        exit(1);
    }
    if (buf_size > 20 * 1024 * 1024) {
        tinyvmm_log(stderr, "Too big kernel");
        exit(1);
    }

    linux_params = (void *) (vm->ram_ptr + KERNEL_PARAMS_ADDR);
    memset(linux_params, 0, sizeof(struct linux_params));

    /* Copy setup header from bzImage */
    setup_hdr_start = 0x1f1;
    setup_hdr_end = 0x202 + buf[0x201];
    memcpy((uint8_t *) linux_params + setup_hdr_start, buf + setup_hdr_start,
           setup_hdr_end - setup_hdr_start);

    is_bzImage = linux_params->boot_params.hdr.version >= 0x0200 &&
        (linux_params->boot_params.hdr.loadflags & 0x01);
    if (!is_bzImage) {
        tinyvmm_log(stderr, "Expected kernel to be bzImage");
        exit(1);
    }

    if (linux_params->boot_params.hdr.boot_flag != 0xAA55) {
        tinyvmm_log(stderr, "Expected kernel magic 0xAA55");
        exit(1);
    }

    if (linux_params->boot_params.hdr.header != 0x53726448) {
        tinyvmm_log(stderr, "Expected kernel magic signature HdrS");
        exit(1);
    }

    setup_sects = linux_params->boot_params.hdr.setup_sects;
    if (setup_sects == 0) {
        setup_sects = 4;
    }

    setup_code_size = (setup_sects + 1) * 512;
    if (buf_size < setup_code_size) {
        tinyvmm_log(stderr, "Invalid bzImage setup_code size");
        exit(1);
    }

    kernel_size = buf_size - setup_code_size;
    if (kernel_size == 0) {
        tinyvmm_log(stderr, "Expected protected mode kernel to have non-zero size");
        exit(1);
    }

    /* Copy protected mode kernel at KERNEL_LOAD_ADDR */
    memcpy(vm->ram_ptr + KERNEL_LOAD_ADDR, buf + setup_code_size, kernel_size);
    free(buf);

    /* Set commandline console=ttyS0 */
    memcpy(linux_params->commandline, "console=ttyS0", 14);
    linux_params->boot_params.hdr.cmd_line_ptr = KERNEL_PARAMS_ADDR +
        offsetof(struct linux_params, commandline);

    linux_params->boot_params.hdr.type_of_loader = 0x01;
    /*
     * This must be set to memory size above 1MiB as we are not a proper
     * bootloader
     */
    linux_params->boot_params.alt_mem_k = (vm->ram_size / 1024) - 1024;

    /* CS */
    linux_params->gdt_table[CS_GDT_INDEX] = 0x00cf9b000000ffff;
    /* DS */
    linux_params->gdt_table[DS_GDT_INDEX] = 0x00cf93000000ffff;

    // Figure out why init scripts echo are not printed to ttyS0
    // what is going on
    if (vm->initrd_path) {
        uint8_t *initrd_buf;
        size_t initrd_size = load_file(vm->initrd_path, &initrd_buf);
        memcpy(vm->ram_ptr + INITRD_LOAD_ADDR, initrd_buf, initrd_size);
        linux_params->boot_params.hdr.ramdisk_image = INITRD_LOAD_ADDR;
        linux_params->boot_params.hdr.ramdisk_size = initrd_size;
        free(initrd_buf);
    }

    kvm_set_regs(vm,
                 KERNEL_PARAMS_ADDR + offsetof(struct linux_params, gdt_table),
                 sizeof(linux_params->gdt_table) - 1, CS_GDT_INDEX, DS_GDT_INDEX,
                 KERNEL_LOAD_ADDR, KERNEL_PARAMS_ADDR);
}

void vm_run(struct vm_info *vm)
{
    tinyvmm_log(stdout, "starting VM...");
    while (true) {
        if (ioctl(vm->vcpu_fd, KVM_RUN, 0) < 0) {
            tinyvmm_log(stderr, "KVM_RUN failed: %s", strerror(errno));
            exit(1);
        }
        switch (vm->kvm_run->exit_reason) {
        case KVM_EXIT_HLT:
            tinyvmm_log(stderr, "KVM_EXIT_HLT");
            exit(1);
        case KVM_EXIT_IO:
            if (vm->kvm_run->io.direction == KVM_EXIT_IO_OUT &&
                vm->kvm_run->io.port == 0x3f8) {
                uint32_t size = vm->kvm_run->io.size * vm->kvm_run->io.count;
                uint64_t offset = vm->kvm_run->io.data_offset;
                fprintf(stdout, "%.*s", size, (char *) vm->kvm_run + offset);
            } else if (vm->kvm_run->io.port == 0x3f8 + 5 &&
                       vm->kvm_run->io.direction == KVM_EXIT_IO_IN) {
                uint8_t *status = (uint8_t *)vm->kvm_run + vm->kvm_run->io.data_offset;
                *status = 0x20;
            } else {
                /*
                tinyvmm_log(stdout, "unknown IO: port = %d, direction = %d\n",
                            vm->kvm_run->io.port, vm->kvm_run->io.direction);
                */
            }
            break;
        case KVM_EXIT_FAIL_ENTRY:
            tinyvmm_log(stderr, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
                        (unsigned long long) vm->kvm_run->fail_entry.hardware_entry_failure_reason);
            exit(1);
        case KVM_EXIT_INTERNAL_ERROR:
            tinyvmm_log(stderr, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
                        vm->kvm_run->internal.suberror);
            exit(1);
        case KVM_EXIT_SHUTDOWN:
            tinyvmm_log(stdout, "KVM_EXIT_SHUTDOWN");
            exit(0);
        default:
            tinyvmm_log(stderr, "unhandled exit_reason = 0x%x",
                        vm->kvm_run->exit_reason);
            exit(1);
        }
    }
}

void usage()
{
    fprintf(stdout, "tinyvmm is a very tiny vmm to run a linux kernel bzImage\n"
            "and print the kernel logs to the terminal\n\n");
    fprintf(stdout, "Usage: tinyvmm --kernel=kernel_path [--intird=initrd_path]\n");
    fprintf(stdout, "    --kernel=kernel_path (Required) Path to linux kernel bzImage\n");
    fprintf(stdout, "    --initrd=initrd_path (Optional) Path to initramfs\n");
    fprintf(stdout, "    --help               (Optional) Print usage\n");

    exit(1);
}

int main(int argc, char *argv[])
{
    struct vm_info vm;
    int opt;

    memset(&vm, 0, sizeof(vm));

    struct option long_options[] = {
        { "kernel", required_argument, NULL, 'k' },
        { "initrd", required_argument, NULL, 'i' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 }
    };

    while ((opt = getopt_long(argc, argv, "", long_options, NULL)) != -1) {
        switch (opt) {
        case 'k':
            vm.kernel_path = optarg;
            break;
        case 'i':
            vm.initrd_path = optarg;
            break;
        case 'h':
            usage();
            break;
        default:
            usage();
            break;
        }
    }

    if (!vm.kernel_path) {
        usage();
    }

    if (optind < argc) {
        usage();
    }

    kvm_init(&vm);
    load_kernel(&vm);
    vm_run(&vm);

    return 0;
}
