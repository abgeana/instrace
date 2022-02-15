#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "utils.h"
#include <stddef.h> /* for offsetof */
#include <stdio.h>



#include "dr_api.h"
#include "drmgr.h"
#include "syscall.h"


static void event_exit() {
    drmgr_exit();
}


static void event_post_syscall(void *drcontext, int sysnum) {
    reg_t result = dr_syscall_get_result(drcontext);
    dr_printf("syscall %d: %d\n", sysnum, result);
}


DR_EXPORT void dr_client_main(client_id_t id, int argc, const char *argv[]) {
    drmgr_init();
    dr_register_exit_event(event_exit);
    drmgr_register_post_syscall_event(event_post_syscall);
}
