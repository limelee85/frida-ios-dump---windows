import ObjC from "frida-objc-bridge";

declare const Module: any;
declare const Memory: {
    allocUtf8String(str: string): NativePointer;
    alloc(size: number): NativePointer;
    readByteArray(ptr: NativePointer, length: number): ArrayBuffer | null;
    readU8(ptr: NativePointer): number;
    writeU8(ptr: NativePointer, value: number): void;
    readU16(ptr: NativePointer): number;
    writeU16(ptr: NativePointer, value: number): void;
    readU32(ptr: NativePointer): number;
    writeU32(ptr: NativePointer, value: number): void;
    readU64(ptr: NativePointer): UInt64;
    writeU64(ptr: NativePointer, value: UInt64 | number): void;
    readPointer(ptr: NativePointer): NativePointer;
    writePointer(ptr: NativePointer, value: NativePointer): void;
};
declare const Process: {
    getModuleByName(name: string): Module;
    enumerateModules(): ModuleDetails[];
};
declare const NativeFunction: any;
declare const ptr: (address: number | string) => NativePointer;
declare const send: (msg: any) => void;
declare function recv(callback: (message: any) => void): void;

type NativePointer = any; // Frida NativePointer 객체 타입 대체
type UInt64 = any; // 64비트 정수 타입 대체


interface Module {
  name: string;
  path: string;
  base: NativePointer;
  size: number;
  getExportByName(name: string): NativePointer;
}

interface ModuleDetails {
    base: NativePointer;
    size: number;
    name: string;
    path: string;
}

const O_RDONLY = 0;
const O_WRONLY = 1;
const O_RDWR = 2;
const O_CREAT = 512;

const SEEK_SET = 0;
const SEEK_CUR = 1;
const SEEK_END = 2;

function allocStr(str: string): NativePointer {
    return Memory.allocUtf8String(str);
}

function putStr(addr: NativePointer | number, str: string): NativePointer {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.writeUtf8String(str);
}

function getByteArr(addr: NativePointer | number, length: number): ArrayBuffer | null {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return Memory.readByteArray(addr, length);
}

function getU8(addr: NativePointer | number): number {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.readU8();
}

function putU8(addr: NativePointer | number, n: number): number {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.writeU8(n);
}

function getU16(addr: NativePointer | number): number {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.readU16();
}

function putU16(addr: NativePointer | number, n: number): number {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.writeU16(n);
}

function getU32(addr: NativePointer | number): number {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.readU32();
}

function putU32(addr: NativePointer | number, n: number): number {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.writeU32(n);
}

function getU64(addr: NativePointer | number): UInt64 {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.readU64();
}

function putU64(addr: NativePointer | number, n: UInt64 | number): UInt64 {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.writeU64(n);
}

function getPt(addr: NativePointer | number): NativePointer {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    return addr.readPointer();
}

function putPt(addr: NativePointer | number, n: NativePointer | number): NativePointer {
    if (typeof addr === "number") {
        addr = ptr(addr);
    }
    if (typeof n === "number") {
        n = ptr(n);
    }
    return addr.writePointer(n);
}

function malloc(size: number): NativePointer {
    return Memory.alloc(size);
}

function getExportFunction(type: "f" | "d", name: string, ret?: string, args?: string[]) {
    const mod = Process.getModuleByName("Foundation");
    if (!mod) {
        console.log("Cannot find Foundation module");
        return null;
    }
    const nptr = mod.getExportByName(name);
    if (!nptr) {
        console.log("Cannot find export " + name);
        return null;
    }

    if (type === "f" && ret && args) {
        return new NativeFunction(nptr, ret, args);
    } else if (type === "d") {
        return Memory.readPointer(nptr);
    }
    return null;
}

const NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
const wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
const read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
const write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
const lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
const close = getExportFunction("f", "close", "int", ["int"]);
const remove = getExportFunction("f", "remove", "int", ["pointer"]);
const access = getExportFunction("f", "access", "int", ["pointer", "int"]);
const dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);

function getDocumentDir(): string {
    const NSDocumentDirectory = 9;
    const NSUserDomainMask = 1;
    const npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    return (new (ObjC.Object as any)(npdirs)).objectAtIndex_(0).toString();
}

function open(pathname: string | NativePointer, flags: number, mode: number): number {
    if (typeof pathname === "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

let modules: ModuleDetails[] | null = null;

function getAllAppModules(): ModuleDetails[] {
    modules = [];
    const tmpmods = Process.enumerateModules();
    for (let i = 0; i < tmpmods.length; i++) {
        if (tmpmods[i].path.indexOf(".app") !== -1) {
            modules.push(tmpmods[i]);
        }
    }
    return modules;
}

const FAT_MAGIC = 0xcafebabe;
const FAT_CIGAM = 0xbebafeca;
const MH_MAGIC = 0xfeedface;
const MH_CIGAM = 0xcefaedfe;
const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const LC_SEGMENT = 0x1;
const LC_SEGMENT_64 = 0x19;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str: string, n: number): string {
    return Array(n - str.length + 1).join("0") + str;
}

function swap32(value: number): number {
    const hex = pad(value.toString(16), 8);
    let result = "";
    for (let i = 0; i < hex.length; i += 2) {
        result += hex.charAt(hex.length - i - 2);
        result += hex.charAt(hex.length - i - 1);
    }
    return parseInt(result, 16);
}

function dumpModule(name: string): string | void {
    if (modules === null) {
        modules = getAllAppModules();
    }

    let targetmod: ModuleDetails | null = null;
    for (let i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) !== -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (!targetmod) {
        console.log("Cannot find module");
        return;
    }

    const modbase = targetmod.base;
    const modsize = targetmod.size;
    const newmodname = targetmod.name;
    const newmodpath = getDocumentDir() + "/" + newmodname + ".fid";
    const oldmodpath = targetmod.path;

    if (access(allocStr(newmodpath), 0) === 0) {
        remove(allocStr(newmodpath));
    }

    const fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
    const foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule === -1 || foldmodule === -1) {
        console.log("Cannot open file " + newmodpath);
        return;
    }

    let is64bit = false;
    let size_of_mach_header = 0;
    const magic = getU32(modbase);
    const cur_cpu_type = getU32(modbase.add(4));
    const cur_cpu_subtype = getU32(modbase.add(8));

    if (magic === MH_MAGIC || magic === MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    } else if (magic === MH_MAGIC_64 || magic === MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    const BUFSIZE = 4096;
    const buffer = malloc(BUFSIZE);

    read(foldmodule, buffer, BUFSIZE);

    let fileoffset = 0;
    let filesize = 0;
    const magic2 = getU32(buffer);
    if (magic2 === FAT_CIGAM || magic2 === FAT_MAGIC) {
        let off = 4;
        const archs = swap32(getU32(buffer.add(off)));
        for (let i = 0; i < archs; i++) {
            const cputype = swap32(getU32(buffer.add(off + 4)));
            const cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if (cur_cpu_type === cputype && cur_cpu_subtype === cpusubtype) {
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if (fileoffset === 0 || filesize === 0) return;

        lseek(fmodule, 0, SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);

        for (let i = 0; i < Math.floor(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            write(fmodule, buffer, BUFSIZE);
        }
        if (filesize % BUFSIZE) {
            read(foldmodule, buffer, filesize % BUFSIZE);
            write(fmodule, buffer, filesize % BUFSIZE);
        }
    } else {
        let readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule, 0, SEEK_SET);
        while ((readLen = read(foldmodule, buffer, BUFSIZE)) > 0) {
            write(fmodule, buffer, readLen);
        }
    }

    const ncmds = getU32(modbase.add(16));
    let off = size_of_mach_header;
    let offset_cryptid = -1;
    let crypt_off = 0;
    let crypt_size = 0;

    for (let i = 0; i < ncmds; i++) {
        const cmd = getU32(modbase.add(off));
        const cmdsize = getU32(modbase.add(off + 4));
        if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid !== -1) {
        const tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, offset_cryptid, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, crypt_off, SEEK_SET);
        write(fmodule, modbase.add(crypt_off), crypt_size);
    }

    close(fmodule);
    close(foldmodule);

    return newmodpath;
}

function loadAllDynamicLibrary(app_path: any): void {
    const defaultManager = ObjC.classes.NSFileManager.defaultManager();
    const errorPtr = Memory.alloc((Process as any).pointerSize);
    errorPtr.writePointer(ptr(0));
    const filenames = defaultManager.contentsOfDirectoryAtPath_error_(app_path, errorPtr);
    for (let i = 0, l = filenames.count(); i < l; i++) {
        const file_name = filenames.objectAtIndex_(i);
        const file_path = app_path.stringByAppendingPathComponent_(file_name);
        if (file_name.hasSuffix_(".framework")) {
            const bundle = ObjC.classes.NSBundle.bundleWithPath_(file_path);
            if (bundle.isLoaded()) {
                console.log("[frida-ios-dump]: " + file_name + " has been loaded.");
            } else {
                if (bundle.load()) {
                    console.log("[frida-ios-dump]: Load " + file_name + " success.");
                } else {
                    console.log("[frida-ios-dump]: Load " + file_name + " failed.");
                }
            }
        } else if (file_name.hasSuffix_(".bundle") || 
                   file_name.hasSuffix_(".momd") ||
                   file_name.hasSuffix_(".strings") ||
                   file_name.hasSuffix_(".appex") ||
                   file_name.hasSuffix_(".app") ||
                   file_name.hasSuffix_(".lproj") ||
                   file_name.hasSuffix_(".storyboardc")) {
            continue;
        } else {
            var isDirPtr = Memory.alloc((Process as any).pointerSize);
            //Memory.writePointer(isDirPtr,NULL);
            isDirPtr.writePointer(ptr(0));
            defaultManager.fileExistsAtPath_isDirectory_(file_path, isDirPtr);
            if (isDirPtr.readPointer() == 1) {
                loadAllDynamicLibrary(file_path);
            } else {
                if (file_name.hasSuffix_(".dylib")) {
                    var is_loaded = 0;
                    if (modules !== null) {
	                    for (var j = 0; j < modules.length; j++) {
	                        if (modules[j].path.indexOf(file_name) != -1) {
	                            is_loaded = 1;
	                            console.log("[frida-ios-dump]: " + file_name + " has been dlopen.");
	                            break;
	                        }
	                    } 
	                }

                    if (!is_loaded) {
                        if (dlopen(allocStr(file_path.UTF8String()), 9)) {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " success. ");
                        } else {
                            console.log("[frida-ios-dump]: dlopen " + file_name + " failed. ");
                        }
                    }
                }
            }
        }
    }
}

function main(): void {
    const app_path = ObjC.classes.NSBundle.mainBundle().executablePath().stringByDeletingLastPathComponent();
    loadAllDynamicLibrary(app_path);

    let err = 0;
    if ((err = access(allocStr(getDocumentDir() + "/load_all"), 0)) === 0) {
        loadAllDynamicLibrary(app_path);
    }

    console.log("[frida-ios-dump]: Start dump all app modules.");
    const mod_arr = getAllAppModules();
    for (let i = 0; i < mod_arr.length; i++) {
        const module = mod_arr[i];

        console.log("[frida-ios-dump]: Dumping " + module.name);
        var result = dumpModule(module.name);
        send({ dump: result, path: module.path});
        
    }
    send({app: app_path.toString()});
    send({done: "ok"});
    console.log("[frida-ios-dump]: Done dumping all app modules.");
}

main();
