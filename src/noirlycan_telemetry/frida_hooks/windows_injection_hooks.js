"use strict";

const kernel32 = "kernel32.dll";
const ntdll = "ntdll.dll";

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

function getExport(moduleName, exportName) {
  try {
    return Module.getExportByName(moduleName, exportName);
  } catch (_) {
    return null;
  }
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

function currentPid() {
  if (GetCurrentProcessId) {
    return GetCurrentProcessId();
  }
  return Process.id;
}

function processIdFromHandle(handle) {
  if (handle.isNull()) {
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
  if (!GetProcessIdOfThread || handle.isNull()) {
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
  const payload = Object.assign(
    {
      type: "memory_primitive",
      primitive: primitive,
      api: api,
      timestamp: new Date().toISOString(),
      actor_pid: currentPid(),
      actor_image: Process.enumerateModules()[0].path,
    },
    fields
  );
  send(payload);
}

function emitProcessCreate(api, fields) {
  const payload = Object.assign(
    {
      type: "process_create",
      api: api,
      timestamp: new Date().toISOString(),
      parent_pid: currentPid(),
      parent_image: Process.enumerateModules()[0].path,
    },
    fields
  );
  send(payload);
}

function hook(moduleName, exportName, handlers) {
  const address = getExport(moduleName, exportName);
  if (!address) {
    return;
  }
  Interceptor.attach(address, handlers);
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

hook(kernel32, "CreateProcessW", {
  onEnter(args) {
    this.image = readUtf16Safe(args[0]);
    this.commandLine = readUtf16Safe(args[1]);
    this.flags = creationFlags(args[5]);
    this.processInformation = args[9];
  },
  onLeave(retval) {
    if (!retval.isNull()) {
      emitProcessCreate("CreateProcessW", {
        pid: processInformationPid(this.processInformation),
        image: this.image,
        command_line: this.commandLine,
        flags: this.flags,
      });
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
    if (!retval.isNull()) {
      emitProcessCreate("CreateProcessA", {
        pid: processInformationPid(this.processInformation),
        image: this.image,
        command_line: this.commandLine,
        flags: this.flags,
      });
    }
  },
});

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

hook(ntdll, "NtAllocateVirtualMemory", {
  onEnter(args) {
    this.targetPid = processIdFromHandle(args[0]);
    this.baseAddressPointer = args[1];
    this.sizePointer = args[3];
    this.protection = protectionToString(args[5]);
  },
  onLeave(retval) {
    if (retval.toInt32() === 0) {
      emit("allocate", "NtAllocateVirtualMemory", {
        target_pid: this.targetPid,
        address: readPointerSafe(this.baseAddressPointer).toString(),
        size: readSizeSafe(this.sizePointer),
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

hook(ntdll, "NtWriteVirtualMemory", {
  onEnter(args) {
    emit("write", "NtWriteVirtualMemory", {
      target_pid: processIdFromHandle(args[0]),
      address: args[1].toString(),
      size: args[3].toString(),
    });
  },
});

hook(ntdll, "NtCreateSection", {
  onEnter(args) {
    this.sectionHandlePointer = args[0];
    this.sizePointer = args[3];
    this.protection = protectionToString(args[4]);
    this.attributes = args[5].toString();
  },
  onLeave(retval) {
    if (retval.toInt32() === 0) {
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
});

hook(ntdll, "NtMapViewOfSection", {
  onEnter(args) {
    this.sectionHandle = args[0].toString();
    this.targetPid = processIdFromHandle(args[1]);
    this.baseAddressPointer = args[2];
    this.viewSizePointer = args[6];
    this.protection = protectionToString(args[9]);
  },
  onLeave(retval) {
    if (retval.toInt32() === 0) {
      const targetPid = this.targetPid;
      const primitive = targetPid === currentPid() ? "write" : "write";
      emit(primitive, "NtMapViewOfSection", {
        target_pid: targetPid,
        address: readPointerSafe(this.baseAddressPointer).toString(),
        size: readSizeSafe(this.viewSizePointer),
        section_handle: this.sectionHandle,
        protection: this.protection,
      });
    }
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

hook(ntdll, "NtCreateThreadEx", {
  onEnter(args) {
    emit("execute", "NtCreateThreadEx", {
      target_pid: processIdFromHandle(args[3]),
      address: args[4].toString(),
      size: "1",
      thread_parameter: args[5].toString(),
      create_flags: args[6].toString(),
    });
  },
});

hook(ntdll, "RtlCreateUserThread", {
  onEnter(args) {
    emit("execute", "RtlCreateUserThread", {
      target_pid: processIdFromHandle(args[0]),
      address: args[4].toString(),
      size: "1",
      thread_parameter: args[5].toString(),
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

hook(ntdll, "NtQueueApcThread", {
  onEnter(args) {
    emit("execute", "NtQueueApcThread", {
      target_pid: processIdFromThreadHandle(args[0]),
      address: args[1].toString(),
      size: "1",
      thread_handle: args[0].toString(),
    });
  },
});

hook(ntdll, "NtQueueApcThreadEx", {
  onEnter(args) {
    emit("execute", "NtQueueApcThreadEx", {
      target_pid: processIdFromThreadHandle(args[0]),
      address: args[2].toString(),
      size: "1",
      thread_handle: args[0].toString(),
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

hook(ntdll, "NtSetContextThread", {
  onEnter(args) {
    emit("execute", "NtSetContextThread", {
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

hook(ntdll, "NtResumeThread", {
  onEnter(args) {
    emit("execute", "NtResumeThread", {
      target_pid: processIdFromThreadHandle(args[0]),
      address: null,
      size: null,
      thread_handle: args[0].toString(),
    });
  },
});

hook(ntdll, "NtAlertResumeThread", {
  onEnter(args) {
    emit("execute", "NtAlertResumeThread", {
      target_pid: processIdFromThreadHandle(args[0]),
      address: null,
      size: null,
      thread_handle: args[0].toString(),
    });
  },
});
