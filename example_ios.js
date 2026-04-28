let traceSoName = 'libGumTrace.dylib'
let targetSo = 'libtarget.dylib'

let gumtrace_init = null
let gumtrace_run = null
let gumtrace_unrun = null

function getSandboxPath(filename) {
    try {
        const homePath = ObjC.classes.NSString.stringWithString_("~").stringByExpandingTildeInPath().toString();
        return homePath + '/Documents/' + filename;
    } catch (e) {
        console.log('获取沙盒路径失败:', e);
        return '/tmp/' + filename
    }
}

function loadGumTrace() {
    let dlopen = new NativeFunction(Module.findGlobalExportByName('dlopen'), 'pointer', ['pointer', 'int'])
    let dlsym = new NativeFunction(Module.findGlobalExportByName('dlsym'), 'pointer', ['pointer', 'pointer'])

    // hide-jb ON 时 /var/jb 前缀对 app 进程隐形,sandbox Documents 是两种模式下都可见的稳定路径
    // hide-jb ON 场景: 提前把 libGumTrace.dylib 推到 app sandbox 的 Documents 目录
    let candidates = [
        getSandboxPath(traceSoName),
        '/var/jb/var/root/' + traceSoName,
    ]

    let soHandle = null
    let loadedFrom = null
    for (let path of candidates) {
        let h = dlopen(Memory.allocUtf8String(path), 2)
        if (!h.isNull()) {
            soHandle = h
            loadedFrom = path
            break
        }
        console.log('  dlopen miss:', path)
    }

    if (!soHandle || soHandle.isNull()) {
        throw new Error(
            'GumTrace dlopen failed. Push libGumTrace.dylib to ' +
            getSandboxPath(traceSoName) + ' (hide-jb OFF) or use Frida session.inject_library_file ' +
            '(hide-jb ON, since iOS sandbox blocks mmap-exec from app Documents).'
        )
    }
    console.log('GumTrace loaded from:', loadedFrom)

    gumtrace_init = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('init')), 'void', ['pointer', 'pointer', 'int', 'pointer'])
    gumtrace_run = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('run')), 'void', [])
    gumtrace_unrun = new NativeFunction(dlsym(soHandle, Memory.allocUtf8String('unrun')), 'void', [])
}

function startTrace() {
    loadGumTrace()

    let moduleNames = Memory.allocUtf8String(targetSo)
    let outputPath = Memory.allocUtf8String(getSandboxPath('trace.log'))
    let threadId = 0   // 0 = 当前线程
    let options = Memory.alloc(8)

    // 0 = Stand 模式
    // 1 = DEBUG 模式
    // 2 = Stable 模式
    options.writeU64(0)

    console.log('start trace')

    gumtrace_init(moduleNames, outputPath, threadId, options)
    gumtrace_run()
}

function stopTrace() {
    console.log('stop trace')
    gumtrace_unrun()
}

// Warning: All apis from Frida 17

let isTrace = false
function hook() {


    // 示例：hook 目标函数，在其执行期间进行追踪
    let targetModule = Process.findModuleByName(targetSo)
    Interceptor.attach(targetModule.base.add(0x1234), {
        onEnter() {
            if (isTrace === false) {
                isTrace = true
                startTrace()
                this.tracing = true
            }
        },
        onLeave() {
            if (this.tracing) {
                stopTrace()
            }
        }
    })


}

setImmediate(hook)
