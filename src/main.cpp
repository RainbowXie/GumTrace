//
// Created by lidongyooo on 2026/2/5.
//


#include "GumTrace.h"
#include "Utils.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
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

// hook-driven trace: 只在 target 函数被命中时启 trace,onLeave 收 trace
// 这样 trace 范围聚焦在 target 函数执行期间,匹配 example_ios.js 的标准用法。

static GumInterceptor *g_interceptor = nullptr;

typedef struct _HookListener {
    GObject parent;
} HookListener;

typedef struct _HookListenerClass {
    GObjectClass parent_class;
} HookListenerClass;

static void hook_listener_iface_init(gpointer g_iface, gpointer iface_data);

#define HOOK_TYPE_LISTENER (hook_listener_get_type())
G_DEFINE_TYPE_EXTENDED(HookListener, hook_listener, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE(GUM_TYPE_INVOCATION_LISTENER, hook_listener_iface_init))

static void hook_listener_init(HookListener *self) {}
static void hook_listener_class_init(HookListenerClass *klass) {}

static void on_enter(GumInvocationListener *listener, GumInvocationContext *ctx) {
    // Snapchat 命中 target 函数 → 启 trace (follow_me = 当前线程)
    run();
}
static void on_leave(GumInvocationListener *listener, GumInvocationContext *ctx) {
    // 函数返回 → 停 trace
    // 但 unrun 会 close 文件,多次进出会重新打开 truncate。
    // 改为只 unfollow_me,文件保留累积 trace,frida_entry 退出时统一 close。
    auto inst = GumTrace::get_instance();
    if (inst->trace_thread_id > 0) gum_stalker_unfollow(inst->_stalker, inst->trace_thread_id);
    else gum_stalker_unfollow_me(inst->_stalker);
    if (inst->trace_file.is_open()) {
        inst->trace_file.write(inst->buffer, inst->buffer_offset);
        inst->buffer_offset = 0;
        inst->trace_file.flush();
    }
}

static void hook_listener_iface_init(gpointer g_iface, gpointer iface_data) {
    GumInvocationListenerInterface *iface = (GumInvocationListenerInterface *) g_iface;
    iface->on_enter = on_enter;
    iface->on_leave = on_leave;
}

// data 格式: "module_name|trace_path|target_offset_hex|wait_seconds"
// 例:
//   "Snapchat||7DC1F0|30"   trace 文件默认 sandbox/Documents,hook Snapchat+0x7DC1F0,等 30s
extern "C" __attribute__((visibility("default")))
void frida_entry(const char *data) {
    char module_name[256] = "Snapchat";
    char trace_path[1024];
    char target_offset_hex[32] = "7DC1F0";  // sub_1007DC1F0 prebuf_v2_encrypt (anti-tamper immune)
    int wait_seconds = 30;

    const char *home = getenv("HOME");
    snprintf(trace_path, sizeof(trace_path), "%s/Documents/gumtrace_inject.log",
             home ? home : "/tmp");

    if (data && *data) {
        char buf[2048];
        snprintf(buf, sizeof(buf), "%s", data);
        char *parts[4] = {nullptr, nullptr, nullptr, nullptr};
        int idx = 0;
        char *tok = buf;
        char *p = buf;
        while (*p && idx < 4) {
            if (*p == '|') { *p = 0; parts[idx++] = tok; tok = p + 1; }
            p++;
        }
        if (idx < 4) parts[idx++] = tok;
        if (parts[0] && *parts[0]) snprintf(module_name, sizeof(module_name), "%s", parts[0]);
        if (parts[1] && *parts[1]) snprintf(trace_path, sizeof(trace_path), "%s", parts[1]);
        if (parts[2] && *parts[2]) snprintf(target_offset_hex, sizeof(target_offset_hex), "%s", parts[2]);
        if (parts[3] && *parts[3]) wait_seconds = atoi(parts[3]);
    }
    if (wait_seconds < 1) wait_seconds = 30;

    // init: 准备 trace state,thread_id=0 → follow_me 模式 (hook 触发线程被 follow)
    GUM_OPTIONS opts; memset(&opts, 0, sizeof(opts));
    init(module_name, trace_path, 0, &opts);

    // 计算 target 地址 = module base + offset
    auto inst = GumTrace::get_instance();
    auto it = inst->modules.find(module_name);
    if (it == inst->modules.end()) {
        // module 没 init 上 (找不到),啥都做不了
        unrun();
        return;
    }
    size_t base = it->second.at("base");
    size_t offset = strtoul(target_offset_hex, nullptr, 16);
    void *target = (void *)(base + offset);

    // gum_interceptor_attach
    g_interceptor = gum_interceptor_obtain();
    HookListener *listener = (HookListener *)g_object_new(HOOK_TYPE_LISTENER, NULL);
    gum_interceptor_begin_transaction(g_interceptor);
    gum_interceptor_attach(g_interceptor, target,
                           GUM_INVOCATION_LISTENER(listener), nullptr,
                           GUM_ATTACH_FLAGS_NONE);
    gum_interceptor_end_transaction(g_interceptor);

    // 等待 hook 触发 (用户在屏幕上走流程触发 attestation)
    sleep(wait_seconds);

    // detach + cleanup
    gum_interceptor_detach(g_interceptor, GUM_INVOCATION_LISTENER(listener));
    g_object_unref(listener);
    g_object_unref(g_interceptor);

    // close trace file (write final buffer + flush)
    if (inst->trace_file.is_open()) {
        inst->trace_file.write(inst->buffer, inst->buffer_offset);
        inst->buffer_offset = 0;
        inst->trace_file.flush();
        inst->trace_file.close();
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
