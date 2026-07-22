"use strict";

const kernel32 = "kernel32.dll";
const ntdll = "ntdll.dll";
const advapi32 = "advapi32.dll";
const shell32 = "shell32.dll";
const user32 = "user32.dll";

const hookedAddresses = new Set();

const CONFIG =
  typeof globalThis.__NOIRLYCAN_CONFIG__ !== "undefined"
    ? globalThis.__NOIRLYCAN_CONFIG__
    : null;

const ENABLED_EXPORTS = (function () {
  if (!CONFIG || !CONFIG.hooks) {
    return null;
  }
  const enabled = new Set();
  CONFIG.hooks.forEach(function (spec) {
    enabled.add(spec.export);
  });
  return enabled;
})();

const DYNAMIC_INJECTION_APIS = (function () {
  if (CONFIG && CONFIG.dynamic_nt && CONFIG.dynamic_nt.length) {
    return new Set(CONFIG.dynamic_nt);
  }
  return new Set([
    "NtAllocateVirtualMemory", "NtCreateSection", "NtMapViewOfSection",
    "NtWriteVirtualMemory", "NtReadVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateThread", "NtCreateThreadEx", "NtSetContextThread", "NtGetContextThread",
    "NtResumeThread", "NtAlertResumeThread", "NtSuspendThread", "NtSuspendProcess",
    "NtResumeProcess", "NtQueueApcThread", "NtQueueApcThreadEx", "NtUnmapViewOfSection",
    "NtCreateProcess", "NtCreateProcessEx", "NtCreateUserProcess", "NtOpenProcess",
    "NtOpenThread", "NtAddAtom", "NtTestAlert", "RtlCreateProcessReflection",
    "RtlCreateUserThread", "RtlCreateUserProcess", "LdrLoadDll",
  ]);
})();

function normalizeNtName(name) {
  if (!name) {
    return null;
  }
  if (name.indexOf("Zw") === 0) {
    return "Nt" + name.substring(2);
  }
  return name;
}

function isApiEnabled(apiName) {
  if (!ENABLED_EXPORTS) {
    return true;
  }
  const normalized = normalizeNtName(apiName);
  if (ENABLED_EXPORTS.has(apiName)) {
    return true;
  }
  return normalized !== null && ENABLED_EXPORTS.has(normalized);
}

function ptrToString(value) {
  if (value === null || value === undefined) {
    return null;
  }
  try {
    return value.toString();
  } catch (_) {
    return null;
  }
}

function ptrToNumber(value) {
  if (value === null || value === undefined) {
    return null;
  }
  try {
    return value.toUInt32();
  } catch (_) {
    try {
      return parseInt(value.toString(), 16);
    } catch (_) {
      return null;
    }
  }
}

function boolSuccess(retval) {
  try {
    return retval.toInt32() !== 0;
  } catch (_) {
    return !retval.isNull();
  }
}

function ntSuccess(retval) {
  try {
    const status = retval.toInt32();
    return status >= 0;
  } catch (_) {
    return false;
  }
}

function readPointerSafe(address) {
  try {
    return Memory.readPointer(address);
  } catch (_) {
    return ptr("0");
  }
}

function readSizeSafe(address) {
  try {
    return Memory.readPointer(address).toString();
  } catch (_) {
    return "0";
  }
}

// Offsets into the Windows CONTEXT structure (winnt.h) for the instruction
// pointer. ContextFlags lives at offset 0x00. We use it as a sanity check.
// AMD64: Rip @ 0xF8, ContextFlags @ 0x30 (paragraph-aligned record).
// x86:   Eip @ 0xB8.
function readInstructionPointerFromContext(contextPtr) {
  if (contextPtr === null || contextPtr === undefined || contextPtr.isNull()) {
    return null;
  }
  try {
    if (Process.pointerSize === 8) {
      const rip = Memory.readU64(contextPtr.add(0xF8));
      const value = rip.toString();
      return value === "0" ? null : value;
    }
    const eip = Memory.readU32(contextPtr.add(0xB8));
    return eip === 0 ? null : eip.toString();
  } catch (_) {
    return null;
  }
}

function getModuleByName(moduleName) {
  try {
    return Process.getModuleByName(moduleName);
  } catch (_) {
    try {
      return Process.findModuleByName(moduleName);
    } catch (_2) {
      return null;
    }
  }
}

function getExport(moduleName, exportName) {
  const module = getModuleByName(moduleName);
  if (!module) {
    return null;
  }
  try {
    if (typeof module.findExportByName === "function") {
      const address = module.findExportByName(exportName);
      if (address) {
        return address;
      }
    }
    if (typeof module.getExportByName === "function") {
      return module.getExportByName(exportName);
    }
  } catch (_) {}
  return null;
}

const GetCurrentProcessIdPtr = getExport(kernel32, "GetCurrentProcessId");
const GetCurrentProcessId = GetCurrentProcessIdPtr
  ? new NativeFunction(GetCurrentProcessIdPtr, "uint32", [])
  : null;

const GetProcessIdPtr = getExport(kernel32, "GetProcessId");
const GetProcessId = GetProcessIdPtr
  ? new NativeFunction(GetProcessIdPtr, "uint32", ["pointer"])
  : null;

const GetProcessIdOfThreadPtr = getExport(kernel32, "GetProcessIdOfThread");
const GetProcessIdOfThread = GetProcessIdOfThreadPtr
  ? new NativeFunction(GetProcessIdOfThreadPtr, "uint32", ["pointer"])
  : null;

const OpenProcessPtr = getExport(kernel32, "OpenProcess");
const OpenProcess = OpenProcessPtr
  ? new NativeFunction(OpenProcessPtr, "pointer", ["uint32", "int", "uint32"])
  : null;

const CloseHandlePtr = getExport(kernel32, "CloseHandle");
const CloseHandle = CloseHandlePtr ? new NativeFunction(CloseHandlePtr, "int", ["pointer"]) : null;

const QueryFullProcessImageNameWPtr = getExport(kernel32, "QueryFullProcessImageNameW");
const QueryFullProcessImageNameW = QueryFullProcessImageNameWPtr
  ? new NativeFunction(QueryFullProcessImageNameWPtr, "int", ["pointer", "uint32", "pointer", "pointer"])
  : null;

const PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
const pidImageCache = {};

function currentPid() {
  if (GetCurrentProcessId) {
    return GetCurrentProcessId();
  }
  return Process.id;
}

function actorImage() {
  try {
    const modules = Process.enumerateModules();
    if (modules.length > 0) {
      return modules[0].path;
    }
  } catch (_) {}
  return null;
}

function rememberProcessImage(pid, image) {
  if (!pid || !image) {
    return;
  }
  pidImageCache[pid] = image;
}

function processImageFromPid(pid) {
  if (!pid) {
    return null;
  }
  if (pidImageCache[pid]) {
    return pidImageCache[pid];
  }
  if (pid === currentPid()) {
    const image = actorImage();
    if (image) {
      pidImageCache[pid] = image;
    }
    return image;
  }
  if (!OpenProcess || !QueryFullProcessImageNameW || !CloseHandle) {
    return null;
  }
  const handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
  if (!handle || handle.isNull()) {
    return null;
  }
  let image = null;
  try {
    const sizePtr = Memory.alloc(4);
    Memory.writeU32(sizePtr, 32768);
    const buffer = Memory.alloc(32768 * 2);
    const ok = QueryFullProcessImageNameW(handle, 0, buffer, sizePtr);
    if (ok) {
      image = Memory.readUtf16String(buffer);
      if (image) {
        pidImageCache[pid] = image;
      }
    }
  } catch (_) {
    image = null;
  } finally {
    CloseHandle(handle);
  }
  return image;
}

function processIdFromHandle(handle) {
  if (!handle || handle.isNull()) {
    return null;
  }
  if (handle.equals(ptr("-1"))) {
    return currentPid();
  }
  if (!GetProcessId) {
    return null;
  }
  try {
    const pid = GetProcessId(handle);
    return pid === 0 ? null : pid;
  } catch (_) {
    return null;
  }
}

function processIdFromThreadHandle(handle) {
  if (!GetProcessIdOfThread || !handle || handle.isNull()) {
    return null;
  }
  try {
    const pid = GetProcessIdOfThread(handle);
    return pid === 0 ? null : pid;
  } catch (_) {
    return null;
  }
}

function emit(primitive, api, fields) {
  if (fields.target_pid && !fields.target_image) {
    fields.target_image = processImageFromPid(fields.target_pid);
  }
  const payload = Object.assign(
    {
      type: "memory_primitive",
      primitive: primitive,
      api: api,
      timestamp: new Date().toISOString(),
      actor_pid: currentPid(),
      actor_image: actorImage(),
    },
    fields
  );
  send(payload);
}

function emitProcessCreate(api, fields) {
  if (fields.pid && fields.image) {
    rememberProcessImage(fields.pid, fields.image);
  }
  const payload = Object.assign(
    {
      type: "process_create",
      api: api,
      timestamp: new Date().toISOString(),
      parent_pid: currentPid(),
      parent_image: actorImage(),
    },
    fields
  );
  send(payload);
}

function emitApiResolve(apiName, address, sourceApi) {
  send({
    type: "api_resolve",
    api: apiName,
    address: ptrToString(address),
    resolve_via: sourceApi,
    timestamp: new Date().toISOString(),
    actor_pid: currentPid(),
    actor_image: actorImage(),
  });
}

function emitObservation(category, api, fields) {
  send(
    Object.assign(
      {
        type: "api_observation",
        category: category,
        api: api,
        timestamp: new Date().toISOString(),
        actor_pid: currentPid(),
        actor_image: actorImage(),
      },
      fields
    )
  );
}

function readUtf16Safe(value) {
  if (!value || value.isNull()) {
    return null;
  }
  try {
    return Memory.readUtf16String(value);
  } catch (_) {
    return null;
  }
}

function readAnsiSafe(value) {
  if (!value || value.isNull()) {
    return null;
  }
  try {
    return Memory.readAnsiString(value);
  } catch (_) {
    return null;
  }
}

function readAnsiStringStruct(value) {
  if (!value || value.isNull()) {
    return null;
  }
  try {
    const length = Memory.readU16(value.add(0));
    const buffer = Memory.readPointer(value.add(Process.pointerSize));
    if (buffer.isNull() || length === 0) {
      return null;
    }
    return Memory.readUtf8String(buffer, length);
  } catch (_) {
    return null;
  }
}

function creationFlags(value) {
  const flags = ptrToNumber(value) || 0;
  const names = [];
  if (flags & 0x00000004) names.push("CREATE_SUSPENDED");
  if (flags & 0x08000000) names.push("CREATE_NO_WINDOW");
  if (flags & 0x00000010) names.push("CREATE_NEW_CONSOLE");
  if (flags & 0x00000200) names.push("CREATE_NEW_PROCESS_GROUP");
  if (flags & 0x00000400) names.push("CREATE_UNICODE_ENVIRONMENT");
  return names;
}

function protectionToString(value) {
  const flags = ptrToNumber(value) || 0;
  const names = [];
  if (flags & 0x10) names.push("EXECUTE");
  if (flags & 0x20) names.push("EXECUTE_READ");
  if (flags & 0x40) names.push("EXECUTE_READWRITE");
  if (flags & 0x80) names.push("EXECUTE_WRITECOPY");
  if (flags & 0x04) names.push("READWRITE");
  if (flags & 0x02) names.push("READONLY");
  return names.length ? names.join("|") : "0x" + flags.toString(16);
}

function processInformationPid(processInformation) {
  if (!processInformation || processInformation.isNull()) {
    return null;
  }
  try {
    return Memory.readU32(processInformation.add(Process.pointerSize * 2));
  } catch (_) {
    return null;
  }
}

function hookAtAddress(apiName, address, handlers) {
  if (!address || address.isNull()) {
    return false;
  }
  const key = address.toString();
  if (hookedAddresses.has(key)) {
    return false;
  }
  try {
    Interceptor.attach(address, handlers);
    hookedAddresses.add(key);
    return true;
  } catch (_) {
    return false;
  }
}

function hook(moduleName, exportName, handlers) {
  if (!isApiEnabled(exportName)) {
    return false;
  }
  const address = getExport(moduleName, exportName);
  if (!address) {
    return false;
  }
  return hookAtAddress(exportName, address, handlers);
}

function resolveApiName(name) {
  const normalized = normalizeNtName(name);
  if (!normalized || !DYNAMIC_INJECTION_APIS.has(normalized)) {
    if (name && DYNAMIC_INJECTION_APIS.has(name)) {
      return name;
    }
    return null;
  }
  return normalized;
}

function attachHandlersForApi(apiName) {
  if (!isApiEnabled(apiName)) {
    return false;
  }
  const handlers = API_HANDLERS[apiName];
  if (!handlers) {
    return false;
  }
  const address = getExport(ntdll, apiName);
  if (!address) {
    return false;
  }
  return hookAtAddress(apiName, address, handlers);
}

function trackResolvedApi(name, address, sourceApi) {
  const apiName = resolveApiName(name);
  if (!apiName || !address || address.isNull()) {
    return;
  }
  emitApiResolve(apiName, address, sourceApi);
  attachHandlersForApi(apiName);
  if (address.toString() !== getExport(ntdll, apiName)?.toString()) {
    hookAtAddress(apiName + "(dynamic)", address, API_HANDLERS[apiName]);
  }
}

