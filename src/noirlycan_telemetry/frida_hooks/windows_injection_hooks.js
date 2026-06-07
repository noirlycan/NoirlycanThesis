"use strict";

const kernel32 = "kernel32.dll";
const ntdll = "ntdll.dll";
const advapi32 = "advapi32.dll";
const shell32 = "shell32.dll";
const user32 = "user32.dll";

const hookedAddresses = new Set();

const DYNAMIC_INJECTION_APIS = new Set([
  "NtAllocateVirtualMemory",
  "NtCreateSection",
  "NtMapViewOfSection",
  "NtWriteVirtualMemory",
  "NtReadVirtualMemory",
  "NtProtectVirtualMemory",
  "NtCreateThread",
  "NtCreateThreadEx",
  "NtSetContextThread",
  "NtGetContextThread",
  "NtResumeThread",
  "NtAlertResumeThread",
  "NtSuspendThread",
  "NtSuspendProcess",
  "NtResumeProcess",
  "NtQueueApcThread",
  "NtQueueApcThreadEx",
  "NtUnmapViewOfSection",
  "NtCreateProcess",
  "NtCreateProcessEx",
  "NtCreateUserProcess",
  "NtOpenProcess",
  "NtOpenThread",
  "NtAddAtom",
  "NtTestAlert",
  "RtlCreateProcessReflection",
  "RtlCreateUserThread",
  "RtlCreateUserProcess",
  "LdrLoadDll",
  "ZwAllocateVirtualMemory",
  "ZwCreateSection",
  "ZwMapViewOfSection",
  "ZwWriteVirtualMemory",
  "ZwProtectVirtualMemory",
  "ZwCreateThreadEx",
  "ZwSetContextThread",
  "ZwResumeThread",
]);

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
  const address = getExport(moduleName, exportName);
  if (!address) {
    return false;
  }
  return hookAtAddress(exportName, address, handlers);
}

function normalizeNtName(name) {
  if (!name) {
    return null;
  }
  if (name.indexOf("Zw") === 0) {
    return "Nt" + name.substring(2);
  }
  return name;
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

const API_HANDLERS = {
  NtAllocateVirtualMemory: {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.baseAddressPointer = args[1];
      this.sizePointer = args[3];
      this.protection = protectionToString(args[5]);
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("allocate", "NtAllocateVirtualMemory", {
          target_pid: this.targetPid,
          address: readPointerSafe(this.baseAddressPointer).toString(),
          size: readSizeSafe(this.sizePointer),
          protection: this.protection,
        });
      }
    },
  },
  NtCreateSection: {
    onEnter(args) {
      this.sectionHandlePointer = args[0];
      this.sizePointer = args[3];
      this.protection = protectionToString(args[4]);
      this.attributes = args[5].toString();
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("allocate", "NtCreateSection", {
          target_pid: currentPid(),
          address: null,
          size: this.sizePointer.isNull() ? null : readSizeSafe(this.sizePointer),
          section_handle: readPointerSafe(this.sectionHandlePointer).toString(),
          protection: this.protection,
          allocation_attributes: this.attributes,
        });
      }
    },
  },
  NtMapViewOfSection: {
    onEnter(args) {
      this.sectionHandle = args[0].toString();
      this.targetPid = processIdFromHandle(args[1]);
      this.baseAddressPointer = args[2];
      this.viewSizePointer = args[6];
      this.protection = protectionToString(args[9]);
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("write", "NtMapViewOfSection", {
          target_pid: this.targetPid,
          address: readPointerSafe(this.baseAddressPointer).toString(),
          size: readSizeSafe(this.viewSizePointer),
          section_handle: this.sectionHandle,
          protection: this.protection,
          cross_process: this.targetPid !== currentPid(),
        });
      }
    },
  },
  NtWriteVirtualMemory: {
    onEnter(args) {
      emit("write", "NtWriteVirtualMemory", {
        target_pid: processIdFromHandle(args[0]),
        address: args[1].toString(),
        size: args[3].toString(),
      });
    },
  },
  NtProtectVirtualMemory: {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.baseAddressPointer = args[1];
      this.sizePointer = args[2];
      this.protection = protectionToString(args[3]);
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("allocate", "NtProtectVirtualMemory", {
          target_pid: this.targetPid,
          address: readPointerSafe(this.baseAddressPointer).toString(),
          size: readSizeSafe(this.sizePointer),
          protection: this.protection,
        });
      }
    },
  },
  NtCreateThreadEx: {
    onEnter(args) {
      emit("execute", "NtCreateThreadEx", {
        target_pid: processIdFromHandle(args[3]),
        address: args[4].toString(),
        size: "1",
        thread_parameter: args[5].toString(),
        create_flags: args[6].toString(),
      });
    },
  },
  RtlCreateUserThread: {
    onEnter(args) {
      emit("execute", "RtlCreateUserThread", {
        target_pid: processIdFromHandle(args[0]),
        address: args[4].toString(),
        size: "1",
        thread_parameter: args[5].toString(),
        create_flags: args[6].toString(),
      });
    },
  },
  NtQueueApcThread: {
    onEnter(args) {
      emit("execute", "NtQueueApcThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: args[1].toString(),
        size: "1",
        thread_handle: args[0].toString(),
      });
    },
  },
  NtQueueApcThreadEx: {
    onEnter(args) {
      emit("execute", "NtQueueApcThreadEx", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: args[2].toString(),
        size: "1",
        thread_handle: args[0].toString(),
      });
    },
  },
  NtSetContextThread: {
    onEnter(args) {
      emit("execute", "NtSetContextThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
        context_pointer: args[1].toString(),
      });
    },
  },
  NtGetContextThread: {
    onEnter(args) {
      emit("context_read", "NtGetContextThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
        context_pointer: args[1].toString(),
        note: "context_read",
      });
    },
  },
  NtResumeThread: {
    onEnter(args) {
      emit("execute", "NtResumeThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
      });
    },
  },
  NtAlertResumeThread: {
    onEnter(args) {
      emit("execute", "NtAlertResumeThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
      });
    },
  },
  NtUnmapViewOfSection: {
    onEnter(args) {
      emit("write", "NtUnmapViewOfSection", {
        target_pid: processIdFromHandle(args[0]),
        address: args[1].toString(),
        size: null,
        note: "unmap_view",
      });
    },
  },
  NtReadVirtualMemory: {
    onEnter(args) {
      emit("write", "NtReadVirtualMemory", {
        target_pid: processIdFromHandle(args[0]),
        address: args[1].toString(),
        size: args[3].toString(),
        note: "read_remote",
      });
    },
  },
  NtCreateThread: {
    onEnter(args) {
      emit("execute", "NtCreateThread", {
        target_pid: processIdFromHandle(args[2]),
        address: args[3].toString(),
        size: "1",
        thread_parameter: args[4].toString(),
      });
    },
  },
  NtSuspendThread: {
    onEnter(args) {
      emitObservation("execute", "NtSuspendThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        thread_handle: args[0].toString(),
      });
    },
  },
  NtSuspendProcess: {
    onEnter(args) {
      emitObservation("execute", "NtSuspendProcess", {
        target_pid: processIdFromHandle(args[0]),
      });
    },
  },
  NtResumeProcess: {
    onEnter(args) {
      emitObservation("execute", "NtResumeProcess", {
        target_pid: processIdFromHandle(args[0]),
      });
    },
  },
  NtOpenProcess: {
    onEnter(args) {
      this.desiredAccess = args[1].toString();
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitObservation("access", "NtOpenProcess", {
          desired_access: this.desiredAccess,
        });
      }
    },
  },
  NtOpenThread: {
    onEnter(args) {
      this.desiredAccess = args[1].toString();
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitObservation("access", "NtOpenThread", {
          desired_access: this.desiredAccess,
        });
      }
    },
  },
  NtAddAtom: {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitObservation("execute", "NtAddAtom", {});
      }
    },
  },
  NtTestAlert: {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("execute", "NtTestAlert", {
          target_pid: currentPid(),
          address: null,
          size: "1",
          note: "alertable_wake",
        });
      }
    },
  },
};

[
  "ZwAllocateVirtualMemory",
  "ZwCreateSection",
  "ZwMapViewOfSection",
  "ZwWriteVirtualMemory",
  "ZwProtectVirtualMemory",
  "ZwCreateThreadEx",
  "ZwSetContextThread",
  "ZwResumeThread",
].forEach(function (zwApi) {
  const ntApi = "Nt" + zwApi.substring(2);
  if (API_HANDLERS[ntApi]) {
    API_HANDLERS[zwApi] = API_HANDLERS[ntApi];
  }
});

function installStaticHooks() {
  hook(kernel32, "CreateProcessW", {
    onEnter(args) {
      this.image = readUtf16Safe(args[0]);
      this.commandLine = readUtf16Safe(args[1]);
      this.flags = creationFlags(args[5]);
      this.processInformation = args[9];
    },
    onLeave(retval) {
      if (!boolSuccess(retval)) {
        return;
      }
      const pid = processInformationPid(this.processInformation);
      const image = this.image || this.commandLine;
      emitProcessCreate("CreateProcessW", {
        pid: pid,
        image: image,
        command_line: this.commandLine,
        flags: this.flags,
      });
      if (pid && image) {
        rememberProcessImage(pid, image);
      }
    },
  });

  hook(kernel32, "CreateProcessA", {
    onEnter(args) {
      this.image = readAnsiSafe(args[0]);
      this.commandLine = readAnsiSafe(args[1]);
      this.flags = creationFlags(args[5]);
      this.processInformation = args[9];
    },
    onLeave(retval) {
      if (!boolSuccess(retval)) {
        return;
      }
      const pid = processInformationPid(this.processInformation);
      const image = this.image || this.commandLine;
      emitProcessCreate("CreateProcessA", {
        pid: pid,
        image: image,
        command_line: this.commandLine,
        flags: this.flags,
      });
      if (pid && image) {
        rememberProcessImage(pid, image);
      }
    },
  });

  hook(kernel32, "VirtualAllocEx", {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.size = args[2].toString();
      this.protection = protectionToString(args[4]);
    },
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("allocate", "VirtualAllocEx", {
          target_pid: this.targetPid,
          address: retval.toString(),
          size: this.size,
          protection: this.protection,
        });
      }
    },
  });

  hook(kernel32, "VirtualAllocExNuma", {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.size = args[2].toString();
      this.protection = protectionToString(args[4]);
    },
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("allocate", "VirtualAllocExNuma", {
          target_pid: this.targetPid,
          address: retval.toString(),
          size: this.size,
          protection: this.protection,
        });
      }
    },
  });

  hook(kernel32, "VirtualProtectEx", {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.address = args[1].toString();
      this.size = args[2].toString();
      this.protection = protectionToString(args[3]);
    },
    onLeave(retval) {
      if (boolSuccess(retval)) {
        emit("allocate", "VirtualProtectEx", {
          target_pid: this.targetPid,
          address: this.address,
          size: this.size,
          protection: this.protection,
        });
      }
    },
  });

  hook(kernel32, "WriteProcessMemory", {
    onEnter(args) {
      emit("write", "WriteProcessMemory", {
        target_pid: processIdFromHandle(args[0]),
        address: args[1].toString(),
        size: args[3].toString(),
      });
    },
  });

  hook(kernel32, "CreateRemoteThread", {
    onEnter(args) {
      emit("execute", "CreateRemoteThread", {
        target_pid: processIdFromHandle(args[0]),
        address: args[3].toString(),
        size: "1",
        thread_parameter: args[4].toString(),
        create_flags: args[5].toString(),
      });
    },
  });

  hook(kernel32, "CreateRemoteThreadEx", {
    onEnter(args) {
      emit("execute", "CreateRemoteThreadEx", {
        target_pid: processIdFromHandle(args[0]),
        address: args[3].toString(),
        size: "1",
        thread_parameter: args[4].toString(),
        create_flags: args[6].toString(),
      });
    },
  });

  hook(kernel32, "QueueUserAPC", {
    onEnter(args) {
      emit("execute", "QueueUserAPC", {
        target_pid: processIdFromThreadHandle(args[1]),
        address: args[0].toString(),
        size: "1",
        thread_handle: args[1].toString(),
      });
    },
  });

  hook(kernel32, "SetThreadContext", {
    onEnter(args) {
      emit("execute", "SetThreadContext", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
        context_pointer: args[1].toString(),
      });
    },
  });

  hook(kernel32, "GetThreadContext", {
    onEnter(args) {
      emit("context_read", "GetThreadContext", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
        context_pointer: args[1].toString(),
      });
    },
  });

  hook(kernel32, "ResumeThread", {
    onEnter(args) {
      emit("execute", "ResumeThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: null,
        size: null,
        thread_handle: args[0].toString(),
      });
    },
  });

  hook(ntdll, "RtlCopyMemory", {
    onEnter(args) {
      this.size = args[2].toString();
      if (parseInt(this.size, 10) >= 0x1000) {
        emit("write", "RtlCopyMemory", {
          target_pid: currentPid(),
          address: args[0].toString(),
          size: this.size,
          source: args[1].toString(),
        });
      }
    },
  });

  hook(kernel32, "CopyMemory", {
    onEnter(args) {
      this.size = args[2].toString();
      if (parseInt(this.size, 10) >= 0x1000) {
        emit("write", "CopyMemory", {
          target_pid: currentPid(),
          address: args[0].toString(),
          size: this.size,
          source: args[1].toString(),
        });
      }
    },
  });

  Object.keys(API_HANDLERS).forEach(function (apiName) {
    attachHandlersForApi(apiName);
  });
}

function installPaperExtendedHooks() {
  hook(kernel32, "ReadProcessMemory", {
    onEnter(args) {
      emit("write", "ReadProcessMemory", {
        target_pid: processIdFromHandle(args[0]),
        address: args[1].toString(),
        size: args[3].toString(),
        note: "read_remote",
      });
    },
  });

  hook(kernel32, "OpenProcess", {
    onEnter(args) {
      emitObservation("access", "OpenProcess", {
        desired_access: args[0].toString(),
      });
    },
  });

  hook(kernel32, "OpenThread", {
    onEnter(args) {
      emitObservation("access", "OpenThread", {
        desired_access: args[0].toString(),
      });
    },
  });

  hook(kernel32, "CreateThread", {
    onEnter(args) {
      emit("execute", "CreateThread", {
        target_pid: currentPid(),
        address: args[2].toString(),
        size: "1",
        thread_parameter: args[3].toString(),
      });
    },
  });

  hook(kernel32, "SuspendThread", {
    onEnter(args) {
      emitObservation("execute", "SuspendThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        thread_handle: args[0].toString(),
      });
    },
  });

  hook(kernel32, "CreateFileMappingA", {
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("allocate", "CreateFileMappingA", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: null,
        });
      }
    },
  });

  hook(kernel32, "CreateFileMappingW", {
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("allocate", "CreateFileMappingW", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: null,
        });
      }
    },
  });

  hook(kernel32, "MapViewOfFile", {
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("write", "MapViewOfFile", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: null,
        });
      }
    },
  });

  hook(kernel32, "MapViewOfFileEx", {
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("write", "MapViewOfFileEx", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: null,
        });
      }
    },
  });

  hook(kernel32, "VirtualAlloc", {
    onEnter(args) {
      this.size = args[1].toString();
      this.protection = protectionToString(args[3]);
    },
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("allocate", "VirtualAlloc", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: this.size,
          protection: this.protection,
        });
      }
    },
  });

  hook(kernel32, "LoadLibraryA", {
    onEnter(args) {
      emit("execute", "LoadLibraryA", {
        target_pid: currentPid(),
        address: null,
        size: null,
        module: readAnsiSafe(args[0]),
      });
    },
  });

  hook(kernel32, "LoadLibraryW", {
    onEnter(args) {
      emit("execute", "LoadLibraryW", {
        target_pid: currentPid(),
        address: null,
        size: null,
        module: readUtf16Safe(args[0]),
      });
    },
  });

  hook(kernel32, "LoadLibraryExA", {
    onEnter(args) {
      emit("execute", "LoadLibraryExA", {
        target_pid: currentPid(),
        address: null,
        size: null,
        module: readAnsiSafe(args[0]),
      });
    },
  });

  hook(kernel32, "LoadLibraryExW", {
    onEnter(args) {
      emit("execute", "LoadLibraryExW", {
        target_pid: currentPid(),
        address: null,
        size: null,
        module: readUtf16Safe(args[0]),
      });
    },
  });

  hook(kernel32, "WinExec", {
    onEnter(args) {
      emitProcessCreate("WinExec", {
        pid: null,
        image: readAnsiSafe(args[0]),
        command_line: readAnsiSafe(args[0]),
        flags: creationFlags(args[1]),
      });
    },
  });

  hook(ntdll, "LdrLoadDll", {
    onEnter(args) {
      this.modulePointer = args[2];
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("execute", "LdrLoadDll", {
          target_pid: currentPid(),
          address: null,
          size: null,
          module: readUtf16Safe(Memory.readPointer(this.modulePointer)),
        });
      }
    },
  });

  hook(ntdll, "RtlCreateUserProcess", {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitProcessCreate("RtlCreateUserProcess", {
          pid: null,
          image: null,
          command_line: null,
          flags: [],
        });
      }
    },
  });

  hook(ntdll, "NtCreateProcess", {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitProcessCreate("NtCreateProcess", { pid: null, image: null, flags: [] });
      }
    },
  });

  hook(ntdll, "NtCreateProcessEx", {
    onEnter(args) {
      this.flags = args[6].toString();
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitProcessCreate("NtCreateProcessEx", {
          pid: null,
          image: null,
          flags: [this.flags],
        });
      }
    },
  });

  hook(ntdll, "NtCreateUserProcess", {
    onEnter(args) {
      this.flags = args[6].toString();
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitProcessCreate("NtCreateUserProcess", {
          pid: null,
          image: null,
          flags: [this.flags],
        });
      }
    },
  });

  hook(advapi32, "CreateProcessWithTokenW", {
    onEnter(args) {
      this.flags = creationFlags(args[8]);
    },
    onLeave(retval) {
      if (boolSuccess(retval)) {
        emitProcessCreate("CreateProcessWithTokenW", {
          pid: null,
          image: null,
          flags: this.flags,
        });
      }
    },
  });

  hook(shell32, "ShellExecuteA", {
    onEnter(args) {
      emitProcessCreate("ShellExecuteA", {
        pid: null,
        image: readAnsiSafe(args[2]),
        command_line: readAnsiSafe(args[3]),
        flags: [],
      });
    },
  });

  hook(shell32, "ShellExecuteW", {
    onEnter(args) {
      emitProcessCreate("ShellExecuteW", {
        pid: null,
        image: readUtf16Safe(args[2]),
        command_line: readUtf16Safe(args[3]),
        flags: [],
      });
    },
  });

  hook(shell32, "ShellExecuteExA", {
    onEnter(args) {
      this.info = args[0];
    },
    onLeave(retval) {
      if (boolSuccess(retval) && this.info && !this.info.isNull()) {
        emitProcessCreate("ShellExecuteExA", {
          pid: null,
          image: readAnsiSafe(Memory.readPointer(this.info.add(Process.pointerSize * 3))),
          command_line: readAnsiSafe(Memory.readPointer(this.info.add(Process.pointerSize * 4))),
          flags: [],
        });
      }
    },
  });

  hook(shell32, "ShellExecuteExW", {
    onEnter(args) {
      this.info = args[0];
    },
    onLeave(retval) {
      if (boolSuccess(retval) && this.info && !this.info.isNull()) {
        emitProcessCreate("ShellExecuteExW", {
          pid: null,
          image: readUtf16Safe(Memory.readPointer(this.info.add(Process.pointerSize * 3))),
          command_line: readUtf16Safe(Memory.readPointer(this.info.add(Process.pointerSize * 4))),
          flags: [],
        });
      }
    },
  });

  hook(user32, "SetWindowsHookExA", {
    onEnter(args) {
      emit("execute", "SetWindowsHookExA", {
        target_pid: currentPid(),
        address: args[2].toString(),
        size: "1",
        hook_type: args[0].toString(),
      });
    },
  });

  hook(user32, "SetWindowsHookExW", {
    onEnter(args) {
      emit("execute", "SetWindowsHookExW", {
        target_pid: currentPid(),
        address: args[2].toString(),
        size: "1",
        hook_type: args[0].toString(),
      });
    },
  });

  hook(kernel32, "GlobalAddAtomA", {
    onEnter(args) {
      emitObservation("execute", "GlobalAddAtomA", {
        atom: readAnsiSafe(args[0]),
      });
    },
  });

  hook(kernel32, "GlobalAddAtomW", {
    onEnter(args) {
      emitObservation("execute", "GlobalAddAtomW", {
        atom: readUtf16Safe(args[0]),
      });
    },
  });

  hook(ntdll, "RtlMoveMemory", {
    onEnter(args) {
      this.size = args[2].toString();
      if (parseInt(this.size, 10) >= 0x1000) {
        emit("write", "RtlMoveMemory", {
          target_pid: currentPid(),
          address: args[0].toString(),
          size: this.size,
          source: args[1].toString(),
        });
      }
    },
  });

  ["msvcrt", "ucrtbase", "ucrtbased"].forEach(function (moduleName) {
    hook(moduleName, "memcpy", {
      onEnter(args) {
        this.size = args[2].toString();
        if (parseInt(this.size, 10) >= 0x1000) {
          emit("write", "memcpy", {
            target_pid: currentPid(),
            address: args[0].toString(),
            size: this.size,
            source: args[1].toString(),
            module: moduleName,
          });
        }
      },
    });
  });
}

function installDynamicResolverHooks() {
  hook(kernel32, "GetProcAddress", {
    onEnter(args) {
      this.procName = args[1].isNull() ? null : readAnsiSafe(args[1]);
    },
    onLeave(retval) {
      trackResolvedApi(this.procName, retval, "GetProcAddress");
    },
  });

  hook(ntdll, "LdrGetProcedureAddress", {
    onEnter(args) {
      this.procName = readAnsiStringStruct(args[1]);
      this.procPointerOut = args[3];
    },
    onLeave(retval) {
      if (!ntSuccess(retval) || !this.procPointerOut) {
        return;
      }
      try {
        const procPointer = Memory.readPointer(this.procPointerOut);
        trackResolvedApi(this.procName, procPointer, "LdrGetProcedureAddress");
      } catch (_) {}
    },
  });
}

function emitEvasion(kind, api, fields) {
  send({
    type: "evasion_signal",
    kind: kind,
    api: api,
    pid: currentPid(),
    image: actorImage(),
    timestamp: new Date().toISOString(),
    ...fields,
  });
}

function installEvasionHooks() {
  hook(kernel32, "IsDebuggerPresent", {
    onLeave(retval) {
      emitEvasion("debugger_check", "IsDebuggerPresent", {
        result: boolSuccess(retval),
      });
    },
  });

  hook(kernel32, "CheckRemoteDebuggerPresent", {
    onEnter(args) {
      this.outPtr = args[1];
    },
    onLeave(retval) {
      let remote = null;
      try {
        if (this.outPtr) {
          remote = Memory.readU32(this.outPtr) !== 0;
        }
      } catch (_) {}
      emitEvasion("remote_debugger", "CheckRemoteDebuggerPresent", {
        success: boolSuccess(retval),
        remote_debugger: remote,
      });
    },
  });

  hook(kernel32, "GetTickCount", {
    onLeave(retval) {
      emitEvasion("timing_probe", "GetTickCount", {
        tick: ptrToNumber(retval),
      });
    },
  });

  hook(kernel32, "GetTickCount64", {
    onLeave(retval) {
      emitEvasion("timing_probe", "GetTickCount64", {
        tick: ptrToString(retval),
      });
    },
  });

  hook(kernel32, "QueryPerformanceCounter", {
    onEnter(args) {
      this.counterPtr = args[0];
    },
    onLeave(retval) {
      emitEvasion("timing_probe", "QueryPerformanceCounter", {
        success: boolSuccess(retval),
      });
    },
  });

  hook(ntdll, "NtQueryInformationProcess", {
    onEnter(args) {
      this.infoClass = ptrToNumber(args[1]);
    },
    onLeave(retval) {
      if (this.infoClass === 7 || this.infoClass === 30 || this.infoClass === 31) {
        emitEvasion("debug_port_query", "NtQueryInformationProcess", {
          info_class: this.infoClass,
          status: ptrToNumber(retval),
        });
      }
    },
  });

  const regOpenKey = getExport(advapi32, "RegOpenKeyExW");
  if (regOpenKey) {
    hook(advapi32, "RegOpenKeyExW", {
      onEnter(args) {
        this.subKey = readUtf16Safe(args[1]);
      },
      onLeave(retval) {
        const key = (this.subKey || "").toLowerCase();
        if (
          key.indexOf("vmware") >= 0 ||
          key.indexOf("vbox") >= 0 ||
          key.indexOf("virtualbox") >= 0 ||
          key.indexOf("qemu") >= 0
        ) {
          emitEvasion("vm_artifact", "RegOpenKeyExW", { sub_key: this.subKey });
        }
      },
    });
  }
}

function installIredTeamHooks() {
  hook(kernel32, "ConvertThreadToFiber", {
    onEnter(args) {
      emit("execute", "ConvertThreadToFiber", {
        target_pid: currentPid(),
        address: args[0] ? args[0].toString() : null,
        size: "1",
      });
    },
  });

  hook(kernel32, "CreateFiber", {
    onEnter(args) {
      emit("execute", "CreateFiber", {
        target_pid: currentPid(),
        address: args[0] ? args[0].toString() : null,
        size: args[1] ? args[1].toString() : null,
      });
    },
  });

  hook(kernel32, "SwitchToFiber", {
    onEnter(args) {
      emit("execute", "SwitchToFiber", {
        target_pid: currentPid(),
        address: args[0] ? args[0].toString() : null,
        size: "1",
      });
    },
  });

  hook(kernel32, "CreateThreadpoolWait", {
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("execute", "CreateThreadpoolWait", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: "1",
        });
      }
    },
  });

  hook(kernel32, "SetThreadpoolWait", {
    onEnter(args) {
      emit("execute", "SetThreadpoolWait", {
        target_pid: currentPid(),
        address: args[1] ? args[1].toString() : null,
        size: "1",
        wait_handle: args[0] ? args[0].toString() : null,
      });
    },
  });

  hook(kernel32, "SubmitThreadpoolWait", {
    onEnter(args) {
      emit("execute", "SubmitThreadpoolWait", {
        target_pid: currentPid(),
        address: args[0] ? args[0].toString() : null,
        size: "1",
      });
    },
  });

  hook(kernel32, "CreateThreadpoolWork", {
    onLeave(retval) {
      if (!retval.isNull()) {
        emit("execute", "CreateThreadpoolWork", {
          target_pid: currentPid(),
          address: retval.toString(),
          size: "1",
        });
      }
    },
  });

  hook(kernel32, "SubmitThreadpoolWork", {
    onEnter(args) {
      emit("execute", "SubmitThreadpoolWork", {
        target_pid: currentPid(),
        address: args[0] ? args[0].toString() : null,
        size: "1",
      });
    },
  });

  hook(kernel32, "VirtualProtect", {
    onEnter(args) {
      this.address = args[0].toString();
      this.size = args[1].toString();
      this.protection = protectionToString(args[2]);
    },
    onLeave(retval) {
      if (boolSuccess(retval)) {
        emit("allocate", "VirtualProtect", {
          target_pid: currentPid(),
          address: this.address,
          size: this.size,
          protection: this.protection,
        });
      }
    },
  });

  hook(kernel32, "SleepEx", {
    onEnter(args) {
      const alertable = ptrToNumber(args[1]) !== 0;
      if (alertable) {
        emitObservation("execute", "SleepEx", {
          target_pid: currentPid(),
          alertable: true,
          milliseconds: ptrToNumber(args[0]),
        });
      }
    },
  });

  hook(user32, "SetWindowLongPtrA", {
    onEnter(args) {
      emit("write", "SetWindowLongPtrA", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: Process.pointerSize.toString(),
        index: ptrToNumber(args[1]),
      });
    },
  });

  hook(user32, "SetWindowLongPtrW", {
    onEnter(args) {
      emit("write", "SetWindowLongPtrW", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: Process.pointerSize.toString(),
        index: ptrToNumber(args[1]),
      });
    },
  });

  hook(user32, "SendMessageA", {
    onEnter(args) {
      emit("execute", "SendMessageA", {
        target_pid: currentPid(),
        address: args[1] ? args[1].toString() : null,
        size: "1",
        message: ptrToNumber(args[1]),
      });
    },
  });

  hook(user32, "SendMessageW", {
    onEnter(args) {
      emit("execute", "SendMessageW", {
        target_pid: currentPid(),
        address: args[1] ? args[1].toString() : null,
        size: "1",
        message: ptrToNumber(args[1]),
      });
    },
  });

  hook(user32, "SendMessageCallbackA", {
    onEnter(args) {
      emit("execute", "SendMessageCallbackA", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: "1",
      });
    },
  });

  hook(user32, "SendMessageCallbackW", {
    onEnter(args) {
      emit("execute", "SendMessageCallbackW", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: "1",
      });
    },
  });

  hook(user32, "SetWindowLongA", {
    onEnter(args) {
      emit("write", "SetWindowLongA", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: Process.pointerSize.toString(),
        index: ptrToNumber(args[1]),
      });
    },
  });

  hook(user32, "SetWindowLongW", {
    onEnter(args) {
      emit("write", "SetWindowLongW", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: Process.pointerSize.toString(),
        index: ptrToNumber(args[1]),
      });
    },
  });

  hook(ntdll, "NtCreateTransaction", {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emit("allocate", "NtCreateTransaction", {
          target_pid: currentPid(),
          address: null,
          size: null,
          txf: true,
        });
      }
    },
  });

  hook(ntdll, "NtCommitTransaction", {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitObservation("txf", "NtCommitTransaction", { txf: true });
      }
    },
  });

  hook(ntdll, "NtRollbackTransaction", {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitObservation("txf", "NtRollbackTransaction", { txf: true });
      }
    },
  });

  hook(ntdll, "RtlCreateProcessReflection", {
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitProcessCreate("RtlCreateProcessReflection", {
          pid: null,
          image: null,
          flags: ["PROCESS_REFLECTION"],
        });
        emitObservation("txf", "RtlCreateProcessReflection", {
          process_reflection: true,
        });
      }
    },
  });
}

installStaticHooks();
installPaperExtendedHooks();
installIredTeamHooks();
installDynamicResolverHooks();
installEvasionHooks();

send({
  type: "hook_ready",
  timestamp: new Date().toISOString(),
  actor_pid: currentPid(),
  actor_image: actorImage(),
  hooked_exports: hookedAddresses.size,
});
