/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#include <stdbool.h>

#include "ttyS0.h"
#include "uart.h"

#define likely(x)     __builtin_expect(!!(x), 1)
#define unlikely(x)   __builtin_expect(!!(x), 0)

#define TTYS0_PORT 0x3f8

struct ttyS0_state {
    struct uart_state uart;
    bool reset;
};

static struct ttyS0_state ttyS0;

bool is_ttyS0_io(int port)
{
    return port >= TTYS0_PORT && port <= TTYS0_PORT + 7;
}

void emulate_ttyS0(struct vm_info *vm)
{
    if (unlikely(!ttyS0.reset)) {
        uart_reset(&(ttyS0.uart), TTYS0_PORT);
        ttyS0.reset = true;
    }
    emulate_uart(vm->kvm_run, vm->vm_fd, &(ttyS0.uart));
}
