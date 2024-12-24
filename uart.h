/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#ifndef UART_H
#define UART_H

#include <stdint.h>
#include <stdbool.h>

#include <linux/kvm.h>

struct uart_state {
    /*
     * NS16450 registers
     *
     * We don't need Receive Buffer Register as we don't do any receive emulation.
     * We don't need Transmitter Holding Register as we write to stdout immediately
     * i.e., no need to store the byte.
     */
    uint8_t divisor_latch_ls;
    uint8_t divisor_latch_ms;
    uint8_t interrupt_enable;
    uint8_t interrupt_identification;
    uint8_t line_control;
    uint8_t modem_control;
    uint8_t line_status;
    uint8_t modem_status;
    uint8_t scratch;

    /* Internal state */
    bool interrupt_pending;
    /* Which port UART is bound to e.g., 0x3f8 */
    int root_port;
};

void uart_reset(struct uart_state *uart, int root_port);
void emulate_uart(struct kvm_run *kvm_run, int vm_fd, struct uart_state *uart);

#endif /* UART_H */

