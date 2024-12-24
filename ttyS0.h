/*
 * Copyright (c) 2024 Dorjoy Chowdhury
 * SPDX-License-Identifier: MIT
 */
#ifndef TTYS0_H
#define TTYS0_H

#include "tinyvmm.h"

bool is_ttyS0_io(int port);
void emulate_ttyS0(struct vm_info *vm);

#endif /* TTYS0_H */
