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
        const base = readPointerSafe(this.baseAddressPointer);
        emit("allocate", "NtAllocateVirtualMemory", {
          target_pid: this.targetPid,
          address: base.isNull() || base.toString() === "0x0" ? null : base.toString(),
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
      // Extract the new instruction pointer from the CONTEXT structure so
      // memory-range congruence (paper §3.3) can correlate the redirect
      // target with a prior allocate/write in the victim.
      const ripAddress = readInstructionPointerFromContext(args[1]);
      emit("execute", "NtSetContextThread", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: ripAddress,
        size: ripAddress === null ? null : "1",
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
      const targetPid = processIdFromThreadHandle(args[0]);
      requestChildAttach(targetPid);
      emit("execute", "NtResumeThread", {
        target_pid: targetPid,
        address: null,
        size: null,
        thread_handle: args[0].toString(),
      });
    },
  },
  NtAlertResumeThread: {
    onEnter(args) {
      const targetPid = processIdFromThreadHandle(args[0]);
      requestChildAttach(targetPid);
      emit("execute", "NtAlertResumeThread", {
        target_pid: targetPid,
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
      // Remote read is observation-only — paper §3 does not classify it as a
      // write primitive. Emit as observation so it appears in the timeline
      // but does not contribute to the 2-of-3 primitive rule.
      emitObservation("remote_read", "NtReadVirtualMemory", {
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

function installZwAliases() {
  Object.keys(API_HANDLERS).forEach(function (apiName) {
    if (apiName.indexOf("Nt") !== 0) {
      return;
    }
    const zwApi = "Zw" + apiName.substring(2);
    if (!API_HANDLERS[zwApi]) {
      API_HANDLERS[zwApi] = API_HANDLERS[apiName];
    }
  });
}

installZwAliases();

var lastNtCreateUserProcessPid = null;
var awaitingChildPid = false;
var pendingChildPids = {};

_onCrossProcessTarget = function (targetPid) {
  if (awaitingChildPid) {
    pendingChildPids[targetPid] = true;
    awaitingChildPid = false;
  }
};

function requestChildAttach(targetPid) {
  return;
}

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
      const pid = processInformationPid(this.processInformation) || lastNtCreateUserProcessPid;
      lastNtCreateUserProcessPid = null;
      const image = this.image || extractExecutablePath(this.commandLine) || this.commandLine;
      emitProcessCreate("CreateProcessW", {
        pid: pid,
        image: image,
        command_line: this.commandLine,
        flags: this.flags,
      });
      if (pid && image) {
        rememberProcessImage(pid, image);
      }
      if (Array.isArray(this.flags) && this.flags.indexOf("CREATE_SUSPENDED") >= 0) {
        if (pid) {
          pendingChildPids[pid] = true;
        } else {
          awaitingChildPid = true;
        }
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
      const pid = processInformationPid(this.processInformation) || lastNtCreateUserProcessPid;
      lastNtCreateUserProcessPid = null;
      const image = this.image || extractExecutablePath(this.commandLine) || this.commandLine;
      emitProcessCreate("CreateProcessA", {
        pid: pid,
        image: image,
        command_line: this.commandLine,
        flags: this.flags,
      });
      if (pid && image) {
        rememberProcessImage(pid, image);
      }
      if (Array.isArray(this.flags) && this.flags.indexOf("CREATE_SUSPENDED") >= 0) {
        if (pid) {
          pendingChildPids[pid] = true;
        } else {
          awaitingChildPid = true;
        }
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
      const ripAddress = readInstructionPointerFromContext(args[1]);
      emit("execute", "SetThreadContext", {
        target_pid: processIdFromThreadHandle(args[0]),
        address: ripAddress,
        size: ripAddress === null ? null : "1",
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
      const targetPid = processIdFromThreadHandle(args[0]);
      requestChildAttach(targetPid);
      emit("execute", "ResumeThread", {
        target_pid: targetPid,
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
      // Observation-only — see paper §3 / audit D2.
      emitObservation("remote_read", "ReadProcessMemory", {
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
        var loadedModule = readUtf16Safe(Memory.readPointer(this.modulePointer));
        emit("execute", "LdrLoadDll", {
          target_pid: currentPid(),
          address: null,
          size: null,
          module: loadedModule,
        });
        if (loadedModule) {
          var lower = loadedModule.toLowerCase();
          if (lower.indexOf("ws2_32") >= 0 || lower.indexOf("winhttp") >= 0 ||
              lower.indexOf("wininet") >= 0) {
            installNetworkHooks();
          }
        }
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
      this.processHandlePtr = args[0];
      this.flags = args[6].toString();
    },
    onLeave(retval) {
      var pid = null;
      if (ntSuccess(retval) && this.processHandlePtr && !this.processHandlePtr.isNull()) {
        try {
          var hProcess = Memory.readPointer(this.processHandlePtr);
          pid = processIdFromHandle(hProcess);
        } catch (_) {}
      }
      lastNtCreateUserProcessPid = pid;
      if (ntSuccess(retval)) {
        emitProcessCreate("NtCreateUserProcess", {
          pid: pid,
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
        if (parseInt(this.size, 10) >= 0x40) {
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
      retval.replace(ptr(0));
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

  hook(kernel32, "ExitProcess", {
    onEnter(args) {
      emitEvasion("process_exit", "ExitProcess", {
        exit_code: ptrToNumber(args[0]),
      });
    },
  });

  hook(kernel32, "TerminateProcess", {
    onEnter(args) {
      emitEvasion("process_exit", "TerminateProcess", {
        target_pid: processIdFromHandle(args[0]),
        exit_code: ptrToNumber(args[1]),
      });
    },
  });

  hook(ntdll, "NtTerminateProcess", {
    onEnter(args) {
      emitEvasion("process_exit", "NtTerminateProcess", {
        target_pid: processIdFromHandle(args[0]),
        exit_code: ptrToNumber(args[1]),
      });
    },
  });
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

// FileInformationClass values from ntifs.h that mark a delete-pending file
// (Process Ghosting precursor). 13 = FileDispositionInformation,
// 64 = FileDispositionInformationEx (flag 0x1 = DELETE).
const FILE_DISPOSITION_INFORMATION = 13;
const FILE_DISPOSITION_INFORMATION_EX = 64;

// ProcessInformationClass values from winternl.h for instrumentation hooks.
const PROCESS_INSTRUMENTATION_CALLBACK = 40;

// AF_INET / AF_INET6 constants from winsock2.h.
const AF_INET = 2;
const AF_INET6 = 23;

function parseSockAddr(addrPtr) {
  if (!addrPtr || addrPtr.isNull()) {
    return null;
  }
  try {
    const family = Memory.readU16(addrPtr);
    const portBytes = new Uint8Array(Memory.readByteArray(addrPtr.add(2), 2));
    const port = (portBytes[0] << 8) | portBytes[1];
    if (family === AF_INET) {
      const ipBytes = new Uint8Array(Memory.readByteArray(addrPtr.add(4), 4));
      return { ip: ipBytes.join("."), port: port, family: "IPv4" };
    }
    if (family === AF_INET6) {
      const ipBytes = new Uint8Array(Memory.readByteArray(addrPtr.add(8), 16));
      const groups = [];
      for (let i = 0; i < 16; i += 2) {
        groups.push(((ipBytes[i] << 8) | ipBytes[i + 1]).toString(16));
      }
      return { ip: groups.join(":"), port: port, family: "IPv6" };
    }
  } catch (_) {}
  return null;
}

function emitNetworkConnect(api, addrPtr, succeeded) {
  const parsed = parseSockAddr(addrPtr);
  if (!parsed) {
    return;
  }
  send({
    type: "network_connect",
    api: api,
    pid: currentPid(),
    image: actorImage(),
    protocol: "tcp",
    destination_ip: parsed.ip,
    destination_port: parsed.port,
    succeeded: succeeded,
    timestamp: new Date().toISOString(),
  });
}

var _networkHooksInstalled = false;

function installNetworkHooks() {
  if (_networkHooksInstalled) {
    return;
  }
  const ws2_32 = "ws2_32.dll";
  if (!getModuleByName(ws2_32)) {
    return;
  }

  hook(ws2_32, "WSASocketW", {
    onLeave(retval) {
      send({
        type: "network_connect",
        api: "WSASocketW",
        pid: currentPid(),
        image: actorImage(),
        protocol: "socket_create",
        destination_ip: "0.0.0.0",
        destination_port: 0,
        succeeded: ptrToNumber(retval) !== -1,
        timestamp: new Date().toISOString(),
      });
    },
  });

  hook(ws2_32, "socket", {
    onLeave(retval) {
      send({
        type: "network_connect",
        api: "socket",
        pid: currentPid(),
        image: actorImage(),
        protocol: "socket_create",
        destination_ip: "0.0.0.0",
        destination_port: 0,
        succeeded: ptrToNumber(retval) !== -1,
        timestamp: new Date().toISOString(),
      });
    },
  });

  hook(ws2_32, "connect", {
    onEnter(args) {
      this.addrPtr = args[1];
    },
    onLeave(retval) {
      emitNetworkConnect("connect", this.addrPtr, ptrToNumber(retval) === 0);
    },
  });

  hook(ws2_32, "WSAConnect", {
    onEnter(args) {
      this.addrPtr = args[1];
    },
    onLeave(retval) {
      emitNetworkConnect("WSAConnect", this.addrPtr, ptrToNumber(retval) === 0);
    },
  });

  hook(ws2_32, "sendto", {
    onEnter(args) {
      this.addrPtr = args[4];
      this.addrLen = ptrToNumber(args[5]);
    },
    onLeave(retval) {
      if (this.addrPtr && !this.addrPtr.isNull() && this.addrLen > 0) {
        emitNetworkConnect("sendto", this.addrPtr, ptrToNumber(retval) >= 0);
      }
    },
  });

  var winhttp = "winhttp.dll";
  if (getModuleByName(winhttp)) {
    hook(winhttp, "WinHttpConnect", {
      onEnter(args) {
        this.server = readUtf16Safe(args[1]);
        this.port = ptrToNumber(args[2]);
      },
      onLeave(retval) {
        if (!retval.isNull() && this.server) {
          send({
            type: "network_connect",
            api: "WinHttpConnect",
            pid: currentPid(),
            image: actorImage(),
            protocol: "http",
            destination_ip: this.server,
            destination_port: this.port || 443,
            succeeded: true,
            timestamp: new Date().toISOString(),
          });
        }
      },
    });
  }

  var wininet = "wininet.dll";
  if (getModuleByName(wininet)) {
    hook(wininet, "InternetConnectW", {
      onEnter(args) {
        this.server = readUtf16Safe(args[1]);
        this.port = ptrToNumber(args[2]);
      },
      onLeave(retval) {
        if (!retval.isNull() && this.server) {
          send({
            type: "network_connect",
            api: "InternetConnectW",
            pid: currentPid(),
            image: actorImage(),
            protocol: "http",
            destination_ip: this.server,
            destination_port: this.port || 80,
            succeeded: true,
            timestamp: new Date().toISOString(),
          });
        }
      },
    });

    hook(wininet, "InternetConnectA", {
      onEnter(args) {
        this.server = readAnsiSafe(args[1]);
        this.port = ptrToNumber(args[2]);
      },
      onLeave(retval) {
        if (!retval.isNull() && this.server) {
          send({
            type: "network_connect",
            api: "InternetConnectA",
            pid: currentPid(),
            image: actorImage(),
            protocol: "http",
            destination_ip: this.server,
            destination_port: this.port || 80,
            succeeded: true,
            timestamp: new Date().toISOString(),
          });
        }
      },
    });
  }

  _networkHooksInstalled = true;
}

function installAdvancedInjectionHooks() {
  // ---- Process Ghosting / Herpaderping precursor ----
  hook(ntdll, "NtSetInformationFile", {
    onEnter(args) {
      this.infoClass = ptrToNumber(args[4]);
      this.fileHandle = args[0].toString();
      this.dataPointer = args[2];
    },
    onLeave(retval) {
      if (!ntSuccess(retval)) {
        return;
      }
      if (
        this.infoClass === FILE_DISPOSITION_INFORMATION ||
        this.infoClass === FILE_DISPOSITION_INFORMATION_EX
      ) {
        emitObservation("ghosting", "NtSetInformationFile", {
          target_pid: currentPid(),
          file_handle: this.fileHandle,
          info_class: this.infoClass,
          delete_pending: true,
          note: "process_ghosting_precursor",
        });
      }
    },
  });

  // ---- Instrumentation Callback ----
  hook(ntdll, "NtSetInformationProcess", {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.infoClass = ptrToNumber(args[1]);
      this.dataPointer = args[2];
    },
    onLeave(retval) {
      if (!ntSuccess(retval)) {
        return;
      }
      if (this.infoClass === PROCESS_INSTRUMENTATION_CALLBACK) {
        // The callback address is the first pointer of the supplied struct.
        const callback = readPointerSafe(this.dataPointer);
        emit("execute", "NtSetInformationProcess", {
          target_pid: this.targetPid,
          address: callback ? callback.toString() : null,
          size: "1",
          info_class: this.infoClass,
          note: "instrumentation_callback",
        });
      }
    },
  });

  // ---- PROPagate (window property + notify message) ----
  hook(user32, "SetPropA", {
    onEnter(args) {
      emit("write", "SetPropA", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: Process.pointerSize.toString(),
        property_name: readAnsiSafe(args[1]),
        note: "propagate",
      });
    },
  });
  hook(user32, "SetPropW", {
    onEnter(args) {
      emit("write", "SetPropW", {
        target_pid: currentPid(),
        address: args[2] ? args[2].toString() : null,
        size: Process.pointerSize.toString(),
        property_name: readUtf16Safe(args[1]),
        note: "propagate",
      });
    },
  });
  hook(user32, "SendNotifyMessageA", {
    onEnter(args) {
      emit("execute", "SendNotifyMessageA", {
        target_pid: currentPid(),
        address: null,
        size: "1",
        message: ptrToNumber(args[1]),
        note: "propagate_trigger",
      });
    },
  });
  hook(user32, "SendNotifyMessageW", {
    onEnter(args) {
      emit("execute", "SendNotifyMessageW", {
        target_pid: currentPid(),
        address: null,
        size: "1",
        message: ptrToNumber(args[1]),
        note: "propagate_trigger",
      });
    },
  });

  // ---- EnumXxx callback injection family ----
  // Callback pointer is arg[1] for EnumSystemLocalesA/EnumDateFormatsA/
  // EnumUILanguagesW, arg[0] for EnumWindows, arg[1] for EnumChildWindows.
  function enumHook(module, api, callbackArgIndex) {
    hook(module, api, {
      onEnter(args) {
        const cb = args[callbackArgIndex];
        emit("execute", api, {
          target_pid: currentPid(),
          address: cb ? cb.toString() : null,
          size: "1",
          callback_arg_index: callbackArgIndex,
          note: "enum_callback",
        });
      },
    });
  }
  enumHook(kernel32, "EnumSystemLocalesA", 0);
  enumHook(kernel32, "EnumSystemLocalesW", 0);
  enumHook(kernel32, "EnumDateFormatsA", 1);
  enumHook(kernel32, "EnumDateFormatsW", 1);
  enumHook(kernel32, "EnumUILanguagesW", 0);
  enumHook(kernel32, "EnumResourceTypesA", 1);
  enumHook(kernel32, "EnumResourceTypesW", 1);
  enumHook(user32, "EnumWindows", 0);
  enumHook(user32, "EnumChildWindows", 1);
  enumHook(user32, "EnumDesktopWindows", 1);
  enumHook(user32, "EnumThreadWindows", 1);

  // ---- PoolParty (Windows thread-pool worker factory) ----
  hook(ntdll, "TpAllocWork", {
    onEnter(args) {
      // TpAllocWork(*OutWork, Callback, Context, CallbackEnviron)
      const callback = args[1];
      emit("execute", "TpAllocWork", {
        target_pid: currentPid(),
        address: callback ? callback.toString() : null,
        size: "1",
        note: "poolparty_alloc",
      });
    },
  });
  hook(ntdll, "TpPostWork", {
    onEnter(args) {
      emitObservation("execute", "TpPostWork", {
        target_pid: currentPid(),
        work_handle: args[0].toString(),
        note: "poolparty_post",
      });
    },
  });
  hook(ntdll, "RtlQueueWorkItem", {
    onEnter(args) {
      emit("execute", "RtlQueueWorkItem", {
        target_pid: currentPid(),
        address: args[0].toString(),
        size: "1",
        note: "rtl_work_item",
      });
    },
  });
  hook(ntdll, "NtSetInformationWorkerFactory", {
    onEnter(args) {
      this.targetPid = processIdFromHandle(args[0]);
      this.infoClass = ptrToNumber(args[1]);
    },
    onLeave(retval) {
      if (ntSuccess(retval)) {
        emitObservation("execute", "NtSetInformationWorkerFactory", {
          target_pid: this.targetPid,
          info_class: this.infoClass,
          note: "poolparty_worker_factory",
        });
      }
    },
  });
}

installStaticHooks();
installPaperExtendedHooks();
installIredTeamHooks();
installAdvancedInjectionHooks();
installDynamicResolverHooks();
installEvasionHooks();
installNetworkHooks();

send({
  type: "hook_ready",
  timestamp: new Date().toISOString(),
  actor_pid: currentPid(),
  actor_image: actorImage(),
  hooked_exports: hookedAddresses.size,
  network_hooks: _networkHooksInstalled,
  ws2_32_loaded: !!getModuleByName("ws2_32.dll"),
  winhttp_loaded: !!getModuleByName("winhttp.dll"),
  wininet_loaded: !!getModuleByName("wininet.dll"),
  policy_version: CONFIG ? CONFIG.version || 0 : 0,
  policy_hooks: ENABLED_EXPORTS ? ENABLED_EXPORTS.size : null,
});
