// vim: foldmethod=marker

/* Define DR_FAST_IR which disables ABI compatibility between releases but makes things faster.
 * See also https://dynamorio.org/API_BT.html
 */
#define DR_FAST_IR

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "utils.h"

#include <stddef.h>
#include <stdio.h>

// Defines {{{

/* Max number of log_entry_t objects a buffer can have.
 * It should be big enough to hold all entries in generated for any given basic block.
 */
#define MAX_NUM_LOG_ENTRIES 8192
// The maximum size of buffer for holding ins_refs.
#define LOG_BUFFER_SIZE (sizeof(log_entry_t) * MAX_NUM_LOG_ENTRIES)

// }}}

// Types {{{

// Each log_entry_t holds state after one instruction.
typedef struct _log_entry_t {
    app_pc pc;
    int opcode;
    reg_t rax;
} log_entry_t;

// Thread private data.
typedef struct {
    byte *seg_base;
    log_entry_t *log_buffer;
    file_t log;
    FILE *logf;
} per_thread_t;

// Allocated TLS slot offsets.
typedef enum {
    INSTRACE_TLS_OFFS_BUF_PTR,
    INSTRACE_TLS_COUNT, // Total number of TLS slots allocated.
} tls_slot_t;

// }}}

// Globals {{{

static client_id_t client_id;

static reg_id_t tls_register;
static uint tls_offs;

static int data_tls_idx;
static void *mutex; /* for multithread support */

// }}}

// TLS access functions {{{

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

// }}}

static void instrace(void *drcontext) {
    per_thread_t *data;
    log_entry_t *ins_ref, *buf_ptr;

    data = drmgr_get_tls_field(drcontext, data_tls_idx);
    buf_ptr = *((log_entry_t **)get_buf_ptr(data->seg_base, tls_offs));

    for (ins_ref = (log_entry_t *)data->log_buffer; ins_ref < buf_ptr; ins_ref++) {
        /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
         * for repeated printing that dominates performance, as the printing does here.
         */
        fprintf(
            data->logf,
            PIFX ",%s ," PIFX "\n",
            (ptr_uint_t)ins_ref->pc,
            decode_opcode_name(ins_ref->opcode),
            (ptr_uint_t)ins_ref->rax);
    }

    set_buf_ptr(data->seg_base, tls_offs, data->log_buffer);
}

/* clean_func dumps the memory reference info to the log file */
static void clean_func(void) {
    void *drcontext = dr_get_current_drcontext();
    instrace(drcontext);
}

static void insert_load_log_buffer(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_ptr) {
    // clang-format off
    dr_insert_read_raw_tls(
        drcontext,
        ilist,
        where,
        tls_register,
        tls_offs + INSTRACE_TLS_OFFS_BUF_PTR,
        reg_ptr
    );
    // clang-format on
}

static void insert_update_buf_ptr(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg_ptr, int adjust) {
    // clang-format off
    instrlist_meta_preinsert(
        ilist,
        where,
        XINST_CREATE_add(
            drcontext,
            opnd_create_reg(reg_ptr),
            OPND_CREATE_INT16(adjust)
        )
    );
    dr_insert_write_raw_tls(drcontext, ilist, where, tls_register, tls_offs + INSTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
    // clang-format on
}

static void
insert_save_opcode(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base, reg_id_t scratch, int opcode) {
    scratch = reg_resize_to_opsz(scratch, OPSZ_2);

    // clang-format off
    instrlist_meta_preinsert(
        ilist,
        where,
        XINST_CREATE_load_int(
            drcontext,
            opnd_create_reg(scratch),
            OPND_CREATE_INT16(opcode)
        )
    );
    instrlist_meta_preinsert(
        ilist,
        where,
        XINST_CREATE_store_2bytes(
            drcontext,
            OPND_CREATE_MEM16(base, offsetof(log_entry_t, opcode)),
            opnd_create_reg(scratch))
    );
    // clang-format on
}

static void
insert_save_pc(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t base, reg_id_t scratch, app_pc pc) {
    // clang-format off
    // Read pc into the scratch register.
    instrlist_insert_mov_immed_ptrsz(
        drcontext,
        (ptr_int_t)pc,
        opnd_create_reg(scratch),
        ilist,
        where,
        NULL, NULL
    );

    // Store the scratch register into the pc field of the struct.
    instrlist_meta_preinsert(
        ilist,
        where,
        XINST_CREATE_store(
            drcontext,
            OPND_CREATE_MEMPTR(base, offsetof(log_entry_t, pc)),
            opnd_create_reg(scratch)
        )
    );
    // clang-format on
}

static void grab_machine_registers_func() {
    per_thread_t *data;
    log_entry_t *buf_ptr;

    void *drcontext = dr_get_current_drcontext();
    dr_mcontext_t mc = {sizeof(dr_mcontext_t)};

    mc.flags = DR_MC_ALL;
    dr_get_mcontext(drcontext, &mc);

    data = drmgr_get_tls_field(drcontext, data_tls_idx);
    buf_ptr = *((log_entry_t **)get_buf_ptr(data->seg_base, tls_offs));

    buf_ptr->rax = mc.rax;
}

static void instrument_instruction(void *drcontext, instrlist_t *bb, instr_t *instr) {
    reg_id_t reg_ptr, reg_tmp;

    if (drreg_reserve_register(drcontext, bb, instr, NULL, &reg_ptr) != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, bb, instr, NULL, &reg_tmp) != DRREG_SUCCESS) {
        DR_ASSERT(false);
        return;
    }

    // clang-format off
    // reg_ptr = log_buffer entry (i.e. pointer to one log_entry_t object)
    insert_load_log_buffer  (drcontext, bb, instr, reg_ptr);
    // reg_ptr->pc = pc
    insert_save_pc          (drcontext, bb, instr, reg_ptr, reg_tmp, instr_get_app_pc(instr));
    // reg_ptr->opcode = opcode
    insert_save_opcode      (drcontext, bb, instr, reg_ptr, reg_tmp, instr_get_opcode(instr));
    // reg_ptr-><register> = <register value>
    dr_insert_clean_call    (drcontext, bb, instr, grab_machine_registers_func, false, 0);
    // log_buffer entry + sizeof(log_entry_t)
    insert_update_buf_ptr   (drcontext, bb, instr, reg_ptr, sizeof(log_entry_t));
    // clang-format on

    if (drreg_unreserve_register(drcontext, bb, instr, reg_ptr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, bb, instr, reg_tmp) != DRREG_SUCCESS) {
        DR_ASSERT(false);
    }
}

/* This function is registered as the callback for the "Instrumentation insertion" stage of drmgr.
 * The callback is executed for every instruction (argument instr) in a given basic block (argument bb).
 */
static dr_emit_flags_t instrumentation_insertion_func(
    void *drcontext, void *tag, instrlist_t *bb, instr_t *instr, bool for_trace, bool translating, void *user_data) {

    /* By default drmgr enables auto-predication, which predicates all instructions with the predicate of the current
     * instruction on ARM.
     * We disable it here because we want to unconditionally execute the following instrumentation.
     * It does not seem to do anything on intel though.
     */
    drmgr_disable_auto_predication(drcontext, bb);

    // We want to instrument only application instructions, not meta instructions.
    if (!instr_is_app(instr))
        return DR_EMIT_DEFAULT;

    // Insert code to add an entry to the buffer.
    instrument_instruction(drcontext, bb, instr);

    if (
        // Check if the current instruction is the first in the basic block.
        drmgr_is_first_instr(drcontext, instr)
        /* XXX i#1698: there are constraints for code between ldrex/strex pairs,
         * so we minimize the instrumentation in between by skipping the clean call.
         * We're relying a bit on the typical code sequence with either ldrex..strex
         * in the same bb, in which case our call at the start of the bb is fine,
         * or with a branch in between and the strex at the start of the next bb.
         * However, there is still a chance that the instrumentation code may clear the
         * exclusive monitor state.
         * Using a fault to handle a full buffer should be more robust, and the
         * forthcoming buffer filling API (i#513) will provide that.
         */
        IF_AARCHXX(&&!instr_is_exclusive_store(instr))) {

        // Add a call to our clean_func function at the beginning of every basic block.
        dr_insert_clean_call(drcontext, bb, instr, (void *)clean_func, false, 0);
    }

    return DR_EMIT_DEFAULT;
}

static void event_thread_init(void *drcontext) {
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    DR_ASSERT(data != NULL);
    drmgr_set_tls_field(drcontext, data_tls_idx, data);

    /* Keep seg_base in a per-thread data structure so we can get the TLS
     * slot and find where the pointer points to in the buffer.
     */
    data->seg_base = dr_get_dr_segment_base(tls_register);
    data->log_buffer = dr_raw_mem_alloc(LOG_BUFFER_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
    DR_ASSERT(data->seg_base != NULL && data->log_buffer != NULL);
    /* put log_buffer to TLS as starting buf_ptr */
    set_buf_ptr(data->seg_base, tls_offs, data->log_buffer);

    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    data->log = log_file_open(
        client_id,
        drcontext,
        NULL /* using client lib path */,
        "instrace",
#ifndef WINDOWS
        DR_FILE_CLOSE_ON_FORK |
#endif
            DR_FILE_ALLOW_LARGE);
    data->logf = log_stream_from_file(data->log);
}

static void event_thread_exit(void *drcontext) {
    per_thread_t *data;
    instrace(drcontext); /* dump any remaining log entries */
    data = drmgr_get_tls_field(drcontext, data_tls_idx);
    dr_mutex_lock(mutex);
    dr_mutex_unlock(mutex);
    log_stream_close(data->logf); /* closes fd too */
    dr_raw_mem_free(data->log_buffer, LOG_BUFFER_SIZE);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void event_exit(void) {
    if (!dr_raw_tls_cfree(tls_offs, INSTRACE_TLS_COUNT)) {
        DR_ASSERT(false);
    }

    if (!drmgr_unregister_tls_field(data_tls_idx)) {
        DR_ASSERT(false);
    }

    if (!drmgr_unregister_thread_init_event(event_thread_init) ||
        !drmgr_unregister_thread_exit_event(event_thread_exit)) {
        DR_ASSERT(false);
    }

    if (!drmgr_unregister_bb_insertion_event(instrumentation_insertion_func)) {
        DR_ASSERT(false);
    }

    if (drreg_exit() != DRREG_SUCCESS) {
        DR_ASSERT(false);
    }

    dr_mutex_destroy(mutex);
    drmgr_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    /* we need 2 reg slots beyond drreg's eflags slots => 3 slots */
    drreg_options_t ops = {sizeof(ops), 3, false};

    dr_set_client_name("instrace", "Alex Geana");

    if (!drmgr_init()) {
        dr_log(NULL, DR_LOG_ALL, 1, "drmgr could not be initialized\n");
        DR_ASSERT(false);
    }

    if (drreg_init(&ops) != DRREG_SUCCESS) {
        dr_log(NULL, DR_LOG_ALL, 1, "drreg could not be initialized\n");
        DR_ASSERT(false);
    }

    /* Register events of interest
     * See also https://dynamorio.org/using.html#sec_events
     */
    dr_register_exit_event(event_exit);

    if (!drmgr_register_thread_init_event(event_thread_init) || !drmgr_register_thread_exit_event(event_thread_exit)) {
        DR_ASSERT(false);
    }

    if (!drmgr_register_bb_instrumentation_event(
            NULL,                           // second instrumentation stage - Application code analysis
            instrumentation_insertion_func, // third instrumentation stage - Instrumentation insertion
            NULL)) {
        DR_ASSERT(false);
    }

    client_id = id;
    mutex = dr_mutex_create();

    // create a tls field used as a pointer to the data (also allocated in thread local storage)
    data_tls_idx = drmgr_register_tls_field();
    DR_ASSERT(data_tls_idx != -1);

    /* The TLS field provided by DR cannot be directly accessed from the code cache.
     * For better performance, we allocate raw TLS so that we can directly
     * access and update it with a single instruction.
     */
    if (!dr_raw_tls_calloc(&tls_register, &tls_offs, INSTRACE_TLS_COUNT, 0))
        DR_ASSERT(false);

    dr_log(NULL, DR_LOG_ALL, 1, "Client 'instrace' initializing\n");
}
