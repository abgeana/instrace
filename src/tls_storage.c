#include "tls_storage.h"

void *get_tls_slot(void *tls_base, uint tls_offs, tls_slot_t slot) {
    return (tls_base + tls_offs + slot);
}

void set_tls_slot(void *tls_base, uint tls_offs, tls_slot_t slot, void *value) {
    *((void **)(tls_base + tls_offs + slot)) = value;
}

void *get_buf_ptr(void *tls_base, uint tls_offs) {
    return get_tls_slot(tls_base, tls_offs, INSTRACE_TLS_OFFS_BUF_PTR);
}

void set_buf_ptr(void *tls_base, uint tls_offs, void *value) {
    set_tls_slot(tls_base, tls_offs, INSTRACE_TLS_OFFS_BUF_PTR, value);
}
