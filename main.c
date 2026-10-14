#include <compiler.h>
#include <kpmodule.h>
#include <linux/printk.h>
#include <linux/string.h>
#include <kputils.h>
#include <hook.h>

KPM_NAME("realme8_zstd_pro");
KPM_VERSION("1.0.0-PRO");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("Custom Build");
KPM_DESCRIPTION("ZSTD engine for Realme 8 (Kernel 4.19.191+)");

extern unsigned long kallsyms_lookup_name(const char *name);

static void *(*kf_vzalloc)(unsigned long size) = 0;
static void (*kf_vfree)(const void *addr) = 0;
static void *addr_zcomp_create = 0;

static void hijack_zcomp_create(hook_fargs1_t *args, void *udata) {
    const char *requested_algorithm = (const char *)args->arg0;
    if (requested_algorithm) {
        args->arg0 = (uint64_t)"zstd"; 
    }
}

static long kpm_main_init(const char *args, const char *event, void *__user reserved) {
    pr_info("Realme8-PRO-ZSTD: Kernel module started...\n");

    kf_vzalloc = (typeof(kf_vzalloc))kallsyms_lookup_name("vzalloc");
    kf_vfree = (typeof(kf_vfree))kallsyms_lookup_name("vfree");
    addr_zcomp_create = (void *)kallsyms_lookup_name("zcomp_create");

    if (!kf_vzalloc || !kf_vfree) {
        pr_err("Realme8-PRO-ZSTD: Error! Kernel blocked memory subsystem.\n");
        return -1;
    }

    if (addr_zcomp_create) {
        hook_wrap1(addr_zcomp_create, hijack_zcomp_create, 0, 0);
        pr_info("Realme8-PRO-ZSTD: Module intercepted ZRAM control!\n");
    }

    return 0;
}

static long kpm_main_exit(void *__user reserved) {
    if (addr_zcomp_create) unhook(addr_zcomp_create);
    pr_info("Realme8-PRO-ZSTD: Module unloaded from kernel.\n");
    return 0;
}

KPM_INIT(kpm_main_init);
KPM_EXIT(kpm_main_exit);
