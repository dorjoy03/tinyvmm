/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <linux/kvm.h>

/*
 * ttyS0 emulation implemented according to https://wiki.osdev.org/Serial_Ports
 */

struct ttyS0_state {
    uint8_t baud_rate_high;
    uint8_t baud_rate_low;
    uint8_t interrupt_enable_register;
    uint8_t interrupt_identification;
    uint8_t fifo_control_register;
    uint8_t line_control_register;
    uint8_t modem_control_register;
    uint8_t line_status_register;
    uint8_t modem_status_register;
    uint8_t scratch_register;
};

static struct ttyS0_state ttyS0_state;

static void ttyS0_offset_0_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    if (ttyS0_state.line_control_register & 0x80) {
        *status = ttyS0_state.baud_rate_low;
    }
    return;
}

static void ttyS0_offset_0_write(struct kvm_run *kvm_run)
{
    uint8_t status = *(uint8_t *) kvm_run + kvm_run->io.data_offset;
    if (ttyS0_state.line_control_register & 0x80) {
        ttyS0_state.baud_rate_low = status;
    } else {
        uint32_t size = kvm_run->io.size * kvm_run->io.count;
        uint64_t offset = kvm_run->io.data_offset;
        fprintf(stdout, "%.*s", size, (char *) kvm_run + offset);
    }
    return;
}

static void ttyS0_offset_1_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    if (ttyS0_state.line_control_register & 0x80) {
        *status = ttyS0_state.baud_rate_high;
    } else {
        *status = ttyS0_state.interrupt_enable_register;
    }
    return;
}

static void ttyS0_offset_1_write(struct kvm_run *kvm_run)
{
    uint8_t status = *(uint8_t *) kvm_run + kvm_run->io.data_offset;
    if (ttyS0_state.line_control_register & 0x80) {
        ttyS0_state.baud_rate_high = status;
    } else {
        ttyS0_state.interrupt_enable_register = status;
    }
    return;
}

static void ttyS0_offset_2_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    *status = ttyS0_state.interrupt_identification;
    return;
}

static void ttyS0_offset_2_write(struct kvm_run *kvm_run)
{
    uint8_t status = *(uint8_t *) kvm_run + kvm_run->io.data_offset;
    ttyS0_state.fifo_control_register = status;
    return;
}

static void ttyS0_offset_3_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    *status = ttyS0_state.line_control_register;
    return;
}

static void ttyS0_offset_3_write(struct kvm_run *kvm_run)
{
    uint8_t status = *(uint8_t *) kvm_run + kvm_run->io.data_offset;
    ttyS0_state.line_control_register = status;
    return;
}

static void ttyS0_offset_4_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    *status = ttyS0_state.modem_control_register;
    return;
}

static void ttyS0_offset_4_write(struct kvm_run *kvm_run)
{
    uint8_t status = *(uint8_t *) kvm_run + kvm_run->io.data_offset;
    ttyS0_state.modem_control_register = status;
    return;
}

static void ttyS0_offset_5_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    *status = 0x20;
    return;
}

static void ttyS0_offset_5_write(struct kvm_run __attribute__((unused)) *kvm_run)
{
    // read-only
}

static void ttyS0_offset_6_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    *status = ttyS0_state.modem_status_register;
    return;
}

static void ttyS0_offset_6_write(struct kvm_run __attribute__((unused)) *kvm_run)
{
    // read-only
}

static void ttyS0_offset_7_read(struct kvm_run *kvm_run)
{
    uint8_t *status = (uint8_t *) kvm_run + kvm_run->io.data_offset;
    *status = ttyS0_state.scratch_register;
    return;
}

static void ttyS0_offset_7_write(struct kvm_run *kvm_run)
{
    uint8_t status = *(uint8_t *) kvm_run + kvm_run->io.data_offset;
    ttyS0_state.scratch_register = status;
    return;
}

static void (*ttyS0_offset_handlers[8][2])(struct kvm_run *kvm_run) = {
    { ttyS0_offset_0_read, ttyS0_offset_0_write },
    { ttyS0_offset_1_read, ttyS0_offset_1_write },
    { ttyS0_offset_2_read, ttyS0_offset_2_write },
    { ttyS0_offset_3_read, ttyS0_offset_3_write },
    { ttyS0_offset_4_read, ttyS0_offset_4_write },
    { ttyS0_offset_5_read, ttyS0_offset_5_write },
    { ttyS0_offset_6_read, ttyS0_offset_6_write },
    { ttyS0_offset_7_read, ttyS0_offset_7_write },
};

void emulate_ttyS0(struct kvm_run *kvm_run)
{
    uint16_t port = kvm_run->io.port;

    assert(port >= 0x3f8 && port <= 0x3f8 + 7);
    assert(kvm_run->io.direction == 0 || kvm_run->io.direction == 1);

    ttyS0_offset_handlers[port - 0x3f8][kvm_run->io.direction](kvm_run);
}
