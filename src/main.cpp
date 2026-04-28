//
// Created by lidongyooo on 2026/2/5.
//


#include "GumTrace.h"
#include "Utils.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <atomic>
#include <fcntl.h>
#include <stdio.h>
#if PLATFORM_IOS
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/thread_act.h>
#endif

gboolean module_symbols_cb(const GumSymbolDetails * details, gpointer user_data) {
    auto *instance = GumTrace::get_instance();
    if (details && details->name && details->address && details->section != nullptr &&
        (details->section->protection & GUM_PAGE_READ)) {
        instance->func_maps[details->address] = details->name;
    }

    // if (details->is_global) {
    //     size_t global_addr = gum_module_find_global_export_by_name(details->name);
    //     if (global_addr > 0) {
    //         instance->func_maps[global_addr] = details->name;
    //     }
    // }

    return true;
}

gboolean module_dependency_cb (const GumDependencyDetails * details, gpointer user_data) {
    auto gum_module = gum_process_find_module_by_name(details->name);
    if (gum_module != nullptr) {
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
    }
    return true;
}

gboolean on_range_found(const GumRangeDetails *details, gpointer user_data) {
    auto instance = GumTrace::get_instance();

    RangeInfo info;
    info.base = (uintptr_t) details->range->base_address;
    info.size = (uintptr_t) details->range->size;
    info.end = info.base + info.size;

    if (details->file) {
        info.file_path = details->file->path;
    } else {
        info.file_path = "maybe heap";
    }

    instance->safa_ranges.push_back(info);
    return TRUE;
}

gboolean module_enumerate (GumModule * module, gpointer user_data) {
    auto instance = GumTrace::get_instance();
    const char *module_name = gum_module_get_name(module);

    if (instance->modules.count(module_name) > 0) {
        return true;
    }

#if PLATFORM_ANDROID
    auto module_path = gum_module_get_path(module);
    auto gum_module_range = gum_module_get_range(module);

    LOGE("module_enumerate %s %s %lx %lx", module_name, module_path, gum_module_range->base_address, gum_module_range->size);

    if (strncmp(module_path, "/system/", 8) == 0 || strncmp(module_path, "/system_ext/", 12) == 0  ||
        strncmp(module_path, "/apex/", 6) == 0 || strncmp(module_path, "/vendor/", 8) == 0 ||
        strstr(module_path, "libGumTrace.so") != nullptr || strstr(module_path, ".odex") != nullptr ||
        strstr(module_path, "memfd") != nullptr) {
        gum_stalker_exclude(instance->_stalker, gum_module_range);
    } else {
        if (instance->modules.count(module_name) == 0) {
            auto &module_map = instance->modules[module_name];
            module_map ["base"] = gum_module_range->base_address;
            module_map ["size"] = gum_module_range->size;
        }
    }

    return true;

#else

    if (instance->modules.count(module_name) == 0) {
        gum_stalker_exclude(instance->_stalker, gum_module_get_range(module));
    }
    return true;

#endif
}

// frida_entry 调用 init/run/unrun (它们在文件下方定义),需要前向声明
extern "C" void init(const char *module_names, char *trace_file_path, int thread_id, GUM_OPTIONS* options);
extern "C" void run();
extern "C" void unrun();

// === Snapchat iOS attestation anti-anti port (基于 snapchat_attestation_gumtrace.ts) ===
//
// 历史已经能过 anti-tamper 拿到 646MB trace 的配置 (memory: snapchat_ios_anti_anti_archive.md):
//
// 4 个外层 entry hook offset (任一 fire → start trace,depth=0 时 stop):
//   0x31e12f8  sub_1031E0FFC                                     registration zone
//   0x31e1e24  -[SCGrpcRegistrationService _registerWithUser:...] gRPC pipeline
//   0x4875648  -[SCPreLoginAttestationImpl generateAttestationPayloadForLoginOrRegistration:...]
//   0x6bdc20   sub_1006BDC20                                      narrow native attestation
//
// 必装 anti-anti patch (装在 entry hook 之前):
//   0x7B29FC sub_1007B29FC: a27 字段 onLeave 清 bit 63 (保 varint 9 字节,过 size assertion)
//   0x7B2C84 sub_1007B2C84: onEnter X1 == 0xa3 → 0xa2 (绕 fail-path signature)

enum HookKind : uintptr_t {
    HK_ENTRY = 1,
    HK_A27   = 2,
    HK_C84   = 3,
};

static GumInterceptor *g_interceptor = nullptr;
static std::atomic<bool> g_trace_active(false);
static std::atomic<unsigned int> g_trace_owner_tid(0);
static std::atomic<int> g_trace_depth(0);
static std::atomic<unsigned long> g_entry_fire_count(0);
static std::atomic<unsigned long> g_a27_fire_count(0);
static std::atomic<unsigned long> g_c84_patch_count(0);

typedef struct _HookListener { GObject parent; } HookListener;
typedef struct _HookListenerClass { GObjectClass parent_class; } HookListenerClass;
static void hook_listener_iface_init(gpointer g_iface, gpointer iface_data);
#define HOOK_TYPE_LISTENER (hook_listener_get_type())
G_DEFINE_TYPE_EXTENDED(HookListener, hook_listener, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, hook_listener_iface_init))
static void hook_listener_init(HookListener *self) {}
static void hook_listener_class_init(HookListenerClass *klass) {}

static void on_enter(GumInvocationListener *listener, GumInvocationContext *ctx) {
    HookKind kind = (HookKind)(uintptr_t)gum_invocation_context_get_listener_function_data(ctx);
    switch (kind) {
        case HK_ENTRY: {
            unsigned int tid = (unsigned int)mach_thread_self();
            mach_port_deallocate(mach_task_self(), tid);
            g_entry_fire_count.fetch_add(1, std::memory_order_relaxed);
            // 启 trace (一次性 init+run,后续 entry fire 只 ++depth)
            if (!g_trace_active.load()) {
                bool expected = false;
                if (g_trace_active.compare_exchange_strong(expected, true)) {
                    g_trace_owner_tid.store(tid);
                    g_trace_depth.store(0);
                    run();  // follow_me 当前线程
                }
            }
            if (g_trace_active.load() && g_trace_owner_tid.load() == tid) {
                int d = g_trace_depth.fetch_add(1, std::memory_order_relaxed) + 1;
                // 用 invocation data 标记 "本帧需要在 onLeave 减"
                int *track = (int *)gum_invocation_context_get_listener_invocation_data(ctx, sizeof(int));
                if (track) *track = 1;
            }
            break;
        }
        case HK_A27: {
            // 保存 X8 (out-ptr) 给 onLeave 用
            void **slot = (void **)gum_invocation_context_get_listener_invocation_data(ctx, sizeof(void *));
            if (slot) *slot = (void *)ctx->cpu_context->x[8];
            g_a27_fire_count.fetch_add(1, std::memory_order_relaxed);
            break;
        }
        case HK_C84: {
            // X1 == 0xa3 → 改成 0xa2,同时 [X22] 也改
            uint64_t x1 = ctx->cpu_context->x[1];
            if ((x1 & 0xFF) == 0xa3) {
                ctx->cpu_context->x[1] = 0xa2;
                uint64_t x22 = ctx->cpu_context->x[22];
                if (x22) *(uint64_t *)x22 = 0xa2;
                g_c84_patch_count.fetch_add(1, std::memory_order_relaxed);
            }
            break;
        }
    }
}

static void on_leave(GumInvocationListener *listener, GumInvocationContext *ctx) {
    HookKind kind = (HookKind)(uintptr_t)gum_invocation_context_get_listener_function_data(ctx);
    switch (kind) {
        case HK_ENTRY: {
            int *track = (int *)gum_invocation_context_get_listener_invocation_data(ctx, sizeof(int));
            if (!track || !*track) break;
            int d = g_trace_depth.fetch_sub(1, std::memory_order_relaxed) - 1;
            if (d <= 0 && g_trace_active.load()) {
                // unrun (unfollow + flush + close trace)
                unrun();
                g_trace_active.store(false);
            }
            break;
        }
        case HK_A27: {
            // 读 [X8] (a27 值),清 bit 63
            void **slot = (void **)gum_invocation_context_get_listener_invocation_data(ctx, sizeof(void *));
            if (!slot || !*slot) break;
            uint64_t *a27ptr = (uint64_t *)*slot;
            uint64_t v = *a27ptr;
            if (v >> 63) {
                *a27ptr = v & 0x7FFFFFFFFFFFFFFFULL;
            }
            break;
        }
        case HK_C84: break;
    }
}

static void hook_listener_iface_init(gpointer g_iface, gpointer iface_data) {
    GumInvocationListenerInterface *iface = (GumInvocationListenerInterface *) g_iface;
    iface->on_enter = on_enter;
    iface->on_leave = on_leave;
}

// data 格式: "module_name|trace_path|wait_seconds"
// 例: "Snapchat||60"  → 60s 等用户走完 注册→密码→确认
extern "C" __attribute__((visibility("default")))
void frida_entry(const char *data) {
    char module_name[256] = "Snapchat";
    char trace_path[1024];
    int wait_seconds = 60;

    const char *home = getenv("HOME");
    snprintf(trace_path, sizeof(trace_path), "%s/Documents/Snapchat_full.log",
             home ? home : "/tmp");

    if (data && *data) {
        char buf[2048];
        snprintf(buf, sizeof(buf), "%s", data);
        char *parts[3] = {nullptr, nullptr, nullptr};
        int idx = 0;
        char *tok = buf;
        char *p = buf;
        while (*p && idx < 3) {
            if (*p == '|') { *p = 0; parts[idx++] = tok; tok = p + 1; }
            p++;
        }
        if (idx < 3) parts[idx++] = tok;
        if (parts[0] && *parts[0]) snprintf(module_name, sizeof(module_name), "%s", parts[0]);
        if (parts[1] && *parts[1]) snprintf(trace_path, sizeof(trace_path), "%s", parts[1]);
        if (parts[2] && *parts[2]) wait_seconds = atoi(parts[2]);
    }
    if (wait_seconds < 1) wait_seconds = 60;

    // init 准备 trace state (但不 run 不 unfollow,等 entry hook fire 才启)
    GUM_OPTIONS opts; memset(&opts, 0, sizeof(opts));
    opts.mode = 1;  // DEBUG 模式高频 flush,trace 中途崩也保有数据
    init(module_name, trace_path, 0, &opts);  // thread_id=0 → run() 内 follow_me 当前线程 (entry fire 时 = Snap 线程)

    auto inst = GumTrace::get_instance();
    auto it = inst->modules.find(module_name);
    if (it == inst->modules.end()) {
        return;
    }
    size_t base = it->second.at("base");
    g_interceptor = gum_interceptor_obtain();

    // 1. 装 anti-anti patch (BEFORE entry hooks,确保任何路径都先经 patch)
    HookListener *a27_listener = (HookListener *)g_object_new(HOOK_TYPE_LISTENER, NULL);
    HookListener *c84_listener = (HookListener *)g_object_new(HOOK_TYPE_LISTENER, NULL);
    gum_interceptor_begin_transaction(g_interceptor);
    GumAttachReturn ar_a27 = gum_interceptor_attach(g_interceptor,
        (void *)(base + 0x7B29FC), GUM_INVOCATION_LISTENER(a27_listener),
        (gpointer)(uintptr_t)HK_A27, GUM_ATTACH_FLAGS_NONE);
    GumAttachReturn ar_c84 = gum_interceptor_attach(g_interceptor,
        (void *)(base + 0x7B2C84), GUM_INVOCATION_LISTENER(c84_listener),
        (gpointer)(uintptr_t)HK_C84, GUM_ATTACH_FLAGS_NONE);

    // 2. 装 4 个外层 entry hook
    static const size_t ENTRY_OFFS[] = {0x31e12f8, 0x31e1e24, 0x4875648, 0x6bdc20};
    HookListener *entry_listeners[4] = {nullptr};
    GumAttachReturn ar_entries[4] = {(GumAttachReturn)-1,(GumAttachReturn)-1,
                                     (GumAttachReturn)-1,(GumAttachReturn)-1};
    for (int i = 0; i < 4; i++) {
        entry_listeners[i] = (HookListener *)g_object_new(HOOK_TYPE_LISTENER, NULL);
        ar_entries[i] = gum_interceptor_attach(g_interceptor,
            (void *)(base + ENTRY_OFFS[i]), GUM_INVOCATION_LISTENER(entry_listeners[i]),
            (gpointer)(uintptr_t)HK_ENTRY, GUM_ATTACH_FLAGS_NONE);
    }
    gum_interceptor_end_transaction(g_interceptor);

    // marker: 确认所有 hook attach 成功
    if (home) {
        char p[1024]; snprintf(p, sizeof(p), "%s/tmp/gumtrace_hook_status", home);
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd >= 0) {
            char b[1024];
            int n = snprintf(b, sizeof(b),
                "module=%s base=0x%lx wait=%ds\n"
                "patch a27 (0x7B29FC) attach=%d\n"
                "patch c84 (0x7B2C84) attach=%d\n"
                "entry 0x31e12f8 attach=%d\n"
                "entry 0x31e1e24 attach=%d\n"
                "entry 0x4875648 attach=%d\n"
                "entry 0x6bdc20  attach=%d\n",
                module_name, (unsigned long)base, wait_seconds,
                ar_a27, ar_c84,
                ar_entries[0], ar_entries[1], ar_entries[2], ar_entries[3]);
            write(fd, b, n); close(fd);
        }
    }

    sleep(wait_seconds);

    // detach 全部
    gum_interceptor_detach(g_interceptor, GUM_INVOCATION_LISTENER(a27_listener));
    gum_interceptor_detach(g_interceptor, GUM_INVOCATION_LISTENER(c84_listener));
    for (int i = 0; i < 4; i++) {
        if (entry_listeners[i])
            gum_interceptor_detach(g_interceptor, GUM_INVOCATION_LISTENER(entry_listeners[i]));
    }
    g_object_unref(a27_listener);
    g_object_unref(c84_listener);
    for (int i = 0; i < 4; i++) if (entry_listeners[i]) g_object_unref(entry_listeners[i]);
    g_object_unref(g_interceptor);

    // 如果还在 trace,强制收
    if (g_trace_active.load()) {
        unrun();
        g_trace_active.store(false);
    }

    // close trace file 兜底
    if (inst->trace_file.is_open()) {
        inst->trace_file.write(inst->buffer, inst->buffer_offset);
        inst->buffer_offset = 0;
        inst->trace_file.flush();
        inst->trace_file.close();
    }

    // dump 计数器
    if (home) {
        char p[1024]; snprintf(p, sizeof(p), "%s/tmp/gumtrace_hook_status", home);
        int fd = open(p, O_WRONLY | O_APPEND, 0644);
        if (fd >= 0) {
            char b[256];
            int n = snprintf(b, sizeof(b),
                "entry_fire=%lu a27_fire=%lu c84_patch=%lu\n",
                g_entry_fire_count.load(), g_a27_fire_count.load(), g_c84_patch_count.load());
            write(fd, b, n); close(fd);
        }
    }
}

extern "C" __attribute__((visibility("default")))
void init(const char *module_names, char *trace_file_path, int thread_id, GUM_OPTIONS* options) {

    gum_init();
    auto code_signing_policy = gum_process_get_code_signing_policy();
    LOGE("Gum code signing policy before init: %s",
         gum_code_signing_policy_to_string(code_signing_policy));
#if PLATFORM_IOS
    if (code_signing_policy != GUM_CODE_SIGNING_OPTIONAL) {
        gum_process_set_code_signing_policy(GUM_CODE_SIGNING_OPTIONAL);
        LOGE("Gum code signing policy forced to: %s",
             gum_code_signing_policy_to_string(gum_process_get_code_signing_policy()));
    }
#endif

    GumTrace *instance = GumTrace::get_instance();
    memcpy(&instance->options, options, sizeof(GUM_OPTIONS));

    instance->_stalker = gum_stalker_new();
    gum_stalker_set_trust_threshold(instance->_stalker, 0);
    gum_stalker_set_ratio(instance->_stalker, 2);
    if (instance->options.mode == GUM_OPTIONS_MODE_STABLE) {
        gum_process_enumerate_ranges(GUM_PAGE_RW, on_range_found, nullptr);

        std::sort(instance->safa_ranges.begin(), instance->safa_ranges.end(),
          [](const RangeInfo &a, const RangeInfo &b) { return a.base < b.base; });
        gum_stalker_set_trust_threshold(instance->_stalker, 2);
        gum_stalker_set_ratio(instance->_stalker, 5);
    }

    auto module_names_vector = Utils::str_split(module_names, ',');
    for (const auto &module_name: module_names_vector) {
        auto *gum_module = gum_process_find_module_by_name(module_name.c_str());
        if (gum_module == nullptr) {
            LOGE("module not found: %s", module_name.c_str());
            continue;
        }
        auto &module_map = instance->modules[module_name];
        gum_module_enumerate_symbols(gum_module, module_symbols_cb, nullptr);
        gum_module_enumerate_dependencies(gum_module, module_dependency_cb, nullptr);
        auto *gum_module_range = gum_module_get_range(gum_module);
        module_map["base"] = gum_module_range->base_address;
        module_map["size"] = gum_module_range->size;
    }

    gum_process_enumerate_modules(module_enumerate, nullptr);

    size_t path_len = strlen(trace_file_path);
    if (path_len >= sizeof(instance->trace_file_path)) {
        path_len = sizeof(instance->trace_file_path) - 1;
    }
    memcpy(instance->trace_file_path, trace_file_path, path_len);
    instance->trace_file_path[path_len] = '\0';
    instance->trace_thread_id = thread_id;
    instance->trace_file = std::ofstream(instance->trace_file_path, std::ios::out | std::ios::trunc);

    for (const auto& svc_name : svc_names) {
        auto svc_name_vector = Utils::str_split(svc_name, ' ');
        instance->svc_func_maps[std::stoi(svc_name_vector.at(1))] = svc_name_vector.at(0);
    }

#if PLATFORM_ANDROID
    auto libart_module = gum_process_find_module_by_name("libart.so");
    GumAddress JNI_GetCreatedJavaVMs_addr = gum_module_find_symbol_by_name(libart_module, "JNI_GetCreatedJavaVMs");
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_export_by_name(libart_module, "JNI_GetCreatedJavaVMs");
    }
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        JNI_GetCreatedJavaVMs_addr = gum_module_find_global_export_by_name("JNI_GetCreatedJavaVMs");
    }
    if (JNI_GetCreatedJavaVMs_addr == 0) {
        LOGE("未找到JNI_GetCreatedJavaVMs符号");
    } else {
        typedef jint (*JNI_GetCreatedJavaVMs_t)(JavaVM**, jsize, jsize*);
        auto *jni_get_created_vms = reinterpret_cast<JNI_GetCreatedJavaVMs_t>(JNI_GetCreatedJavaVMs_addr);
        jsize vm_count = 1;
        auto **vms = new JavaVM*[vm_count];
        jint result = jni_get_created_vms(vms, vm_count, &vm_count);
        if (result == JNI_OK && vm_count > 0) {
            instance->java_vm = vms[0];
            LOGE("成功获取JavaVM: %p", instance->java_vm);
        } else {
            LOGE("获取JavaVM失败，错误码: %d", result);
        }

        delete[] vms;
    }
#    endif

}

void* thread_function(void* arg) {
    GumTrace *instance = GumTrace::get_instance();
    size_t last_size = 0;

    while (true) {
        if (instance->trace_file.is_open()) {
            if (!(instance->options.mode == GUM_OPTIONS_MODE_DEBUG)) {
                struct stat stat_buf;
                int ret = stat(instance->trace_file_path, &stat_buf);

                if (ret == 0) {
                    off_t growth = stat_buf.st_size - last_size;
                    off_t growth_mb = growth / (1024 * 1024);
                    off_t size_gb = stat_buf.st_size / (1024 * 1024 * 1024);

                    LOGE("每20秒新增：%ldMB 当前文件大小：%ldGB",
                         growth_mb, size_gb);
                    last_size = stat_buf.st_size;
                } else {
                    LOGE("stat 失败，错误码：%d，错误信息：%s",
                         errno, strerror(errno));
                    LOGE("文件路径：%s", instance->trace_file_path);
                }
            }

            instance->trace_file.flush();
        } else {
            LOGE("trace_file 未打开");
            break;
        }

        if (instance->options.mode == GUM_OPTIONS_MODE_DEBUG) {
            usleep(1000);
        } else {
            usleep(1000 * 1000 * 20);
        }
    }

    return nullptr;
}


extern "C" __attribute__((visibility("default")))
void run() {

    pthread_t thread1;
    pthread_create(&thread1, NULL, thread_function, nullptr);

    GumTrace *instance = GumTrace::get_instance();
    instance->follow();
}

extern "C" __attribute__((visibility("default")))
void unrun() {
    GumTrace *instance = GumTrace::get_instance();
    instance->unfollow();
}

int main() {
    printf("xxx %p", main);
}
