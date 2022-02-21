#pragma once

#include "dr_api.h"
#include "dr_defines.h"
#include "drmgr.h"
#include "drreg.h"

/* Allocated TLS slot offsets */
typedef enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, /* total number of TLS slots allocated */
} tls_slot_t;

void *get_tls_slot(void *tls_base, uint tls_offs, tls_slot_t slot);
void set_tls_slot(void *tls_base, uint tls_offs, tls_slot_t slot, void *value);

void *get_buf_ptr(void *tls_base, uint tls_offs);
void set_buf_ptr(void *tls_base, uint tls_offs, void *value);
