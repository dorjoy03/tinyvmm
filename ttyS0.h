/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#ifndef TTYS0_H
#define TTYS0_H

#include <linux/kvm.h>

void emulate_ttyS0(struct kvm_run *kvm_run);

#endif /* TTYS0_H */
