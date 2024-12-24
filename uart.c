/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>

#include <linux/kvm.h>

#include "uart.h"
#include "tinyvmm.h"

/*
 * NS16450 UART emulation
 *
 * See National Semiconductor 16450 UART datasheet
 * or Texas Instruments 16550D UART datasheet and ignore the fifo stuff.
 */

#define UART_IER_THRE   (1 << 1)

#define UART_IIR_NO_INT (1 << 0)
#define UART_IIR_THRE   (1 << 1)

#define UART_LCR_DLAB   (1 << 7)

#define UART_LSR_THRE   (1 << 5)
#define UART_LSR_TEMT   (1 << 6)

static void uart_offset_0_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    if (uart->line_control & UART_LCR_DLAB) {
        *status = uart->divisor_latch_ls;
    }
    return;
}

static void uart_offset_0_write(struct kvm_run *kvm_run, struct uart_state *uart)
{
    if (uart->line_control & UART_LCR_DLAB) {
        uint8_t status = *((uint8_t *)kvm_run + kvm_run->io.data_offset);
        uart->divisor_latch_ls = status;
    } else {
        putchar(*((char *)kvm_run + kvm_run->io.data_offset));
    }
    return;
}

static void uart_offset_1_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    if (uart->line_control & UART_LCR_DLAB) {
        *status = uart->divisor_latch_ms;
    } else {
        *status = uart->interrupt_enable;
    }
    return;
}

static void uart_offset_1_write(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t status = *((uint8_t *)kvm_run + kvm_run->io.data_offset);
    if (uart->line_control & UART_LCR_DLAB) {
        uart->divisor_latch_ms = status;
    } else {
        uart->interrupt_enable = status;
        /* Bits 4 through 7: These four bits are always logic 0 */
        uart->interrupt_enable &= 0b00001111;
        if (uart->interrupt_enable & UART_IER_THRE) {
            /*
             * We can enable the Transmission Holding Register Empty interrupt
             * as we always write to stdout immediately so it's always empty.
             */
            uart->interrupt_identification = UART_IIR_THRE;
        } else {
            uart->interrupt_identification = UART_IIR_NO_INT;
        }
    }
    return;
}

static void uart_offset_2_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    *status = uart->interrupt_identification;
    return;
}

static void uart_offset_2_write(struct kvm_run __attribute__((unused)) *kvm_run,
                                struct uart_state __attribute__((unused)) *uart)
{
    // read-only
}

static void uart_offset_3_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    *status = uart->line_control;
    return;
}

static void uart_offset_3_write(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t status = *((uint8_t *)kvm_run + kvm_run->io.data_offset);
    uart->line_control = status;
    return;
}

static void uart_offset_4_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    *status = uart->modem_control;
    return;
}

static void uart_offset_4_write(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t status = *((uint8_t *)kvm_run + kvm_run->io.data_offset);
    // No emulation for loopback feature yet, seems like linux doesn't use it.
    uart->modem_control = status;
    /* Bits 5 through 7: These bits are permanently set to logic 0 */
    uart->modem_control &= 0b00011111;
    return;
}

static void uart_offset_5_read(struct kvm_run *kvm_run,
                               struct uart_state __attribute__((unused)) *uart)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    /*
     * We can advertise that Transmission Hodling Register and Transmitter is
     * always empty.
     */
    *status = UART_LSR_THRE | UART_LSR_TEMT;
    return;
}

static void uart_offset_5_write(struct kvm_run __attribute__((unused)) *kvm_run,
                                struct uart_state __attribute__((unused)) *uart)
{
    // read-only
}

static void uart_offset_6_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    *status = uart->modem_status;
    return;
}

static void uart_offset_6_write(struct kvm_run __attribute__((unused)) *kvm_run,
                                struct uart_state __attribute__((unused)) *uart)
{
    // read-only
}

static void uart_offset_7_read(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t *status = (uint8_t *)kvm_run + kvm_run->io.data_offset;
    *status = uart->scratch;
    return;
}

static void uart_offset_7_write(struct kvm_run *kvm_run, struct uart_state *uart)
{
    uint8_t status = *((uint8_t *)kvm_run + kvm_run->io.data_offset);
    uart->scratch = status;
    return;
}

static void (*uart_offset_handlers[8][2])(struct kvm_run *kvm_run, struct uart_state *uart) = {
    { uart_offset_0_read, uart_offset_0_write },
    { uart_offset_1_read, uart_offset_1_write },
    { uart_offset_2_read, uart_offset_2_write },
    { uart_offset_3_read, uart_offset_3_write },
    { uart_offset_4_read, uart_offset_4_write },
    { uart_offset_5_read, uart_offset_5_write },
    { uart_offset_6_read, uart_offset_6_write },
    { uart_offset_7_read, uart_offset_7_write },
};

static void kvm_set_irq_4(int vm_fd, uint32_t level)
{
    struct kvm_irq_level irq = {
        .irq = 4,
        .level = level
    };

    if (ioctl(vm_fd, KVM_IRQ_LINE, &irq) < 0) {
        tinyvmm_log(stdout, "warning: KVM_IRQ_LINE failed: %s", strerror(errno));
    }
}

void uart_reset(struct uart_state *uart, int root_port)
{
    memset(uart, 0, sizeof(*uart));
    uart->interrupt_identification = UART_IIR_NO_INT;
    uart->line_status = UART_LSR_THRE | UART_LSR_TEMT;
    uart->root_port = root_port;
}

void emulate_uart(struct kvm_run *kvm_run, int vm_fd, struct uart_state *uart)
{
    uint16_t port = kvm_run->io.port;

    assert(port >= uart->root_port && port <= uart->root_port + 7);
    assert(kvm_run->io.direction == 0 || kvm_run->io.direction == 1);

    uart_offset_handlers[port - uart->root_port][kvm_run->io.direction](kvm_run, uart);

    /*
     * We don't need to de-assert and then assert the irq again like real
     * hardware upon related state read/write. We can always keep the irq
     * asserted when enabled via Interrupt Enable Register because we can
     * afford to advertise Transmission Holding Register is always empty
     * and only de-assert when disabled. It minimizes ioctl calls and seems
     * to work.
     */
    if (uart->interrupt_pending == false &&
        uart->interrupt_identification & UART_IIR_THRE) {
        kvm_set_irq_4(vm_fd, 1);
        uart->interrupt_pending = true;
    } else if (uart->interrupt_pending == true &&
               uart->interrupt_identification & UART_IIR_NO_INT) {
        kvm_set_irq_4(vm_fd, 0);
        uart->interrupt_pending = false;
    }
}
