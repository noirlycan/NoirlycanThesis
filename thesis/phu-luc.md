# PHỤ LỤC

## Phụ lục A. Danh mục API equivalence class (chống né tránh E1)

*Nguồn:* `src/noirlycan_core/detection/api_classes.py` — `PAPER_API_CLASSES` căn cứ [7].

### A.1. Lớp allocate

| API | Ghi chú né tránh |
|-----|------------------|
| VirtualAllocEx, VirtualAllocExNuma | Win32 classic |
| NtAllocateVirtualMemory | NT thay Win32 (E1) |
| VirtualProtectEx, NtProtectVirtualMemory | Re-protect RW→RX (E2) |
| NtCreateSection, CreateFileMappingA/W | Section-based (E2) |
| MapViewOfFile, MapViewOfFileEx | Local/remote map |

### A.2. Lớp write

| API | Ghi chú |
|-----|---------|
| WriteProcessMemory, NtWriteVirtualMemory | Classic write |
| NtMapViewOfSection | Gộp write+allocate (E2) |
| RtlCopyMemory, CopyMemory | Copy local/remote |

### A.3. Lớp execute

| API | Ghi chú |
|-----|---------|
| CreateRemoteThread(Ex), NtCreateThreadEx | Thread creation (E1) |
| RtlCreateUserThread | NT variant |
| QueueUserAPC, NtQueueApcThread(Ex) | APC injection |
| SetThreadContext, NtSetContextThread | Thread hijack |
| ResumeThread, NtResumeThread | Hollowing resume |
| LoadLibraryA/W, LdrLoadDll | DLL injection |

### A.4. Lớp observation (không tính 2-of-3)

ReadProcessMemory, NtReadVirtualMemory — phục vụ reflective heuristic, không inflate write count.

---

## Phụ lục B. Cấu hình Sysmon phòng lab

**File:** `configs/sysmon-noirlycan.xml`

**Event ID và vai trò chống né tránh:**

| Event ID | Tên | Chống |
|----------|-----|-------|
| 1 | ProcessCreate | E3 lineage, CREATE_SUSPENDED |
| 3 | NetworkConnect | Hậu kiểm beacon |
| 7 | ImageLoad | Reflective vs LoadLibrary |
| 8 | CreateRemoteThread | E4 fallback |
| 10 | ProcessAccess | E4 cross-process handle |
| 11 | FileCreate | E3 provenance |
| 15 | FileCreateStreamHash | ADS drop |

**Cài đặt:**

```powershell
cd D:\thesis\NoirlycanThesis
.\Sysmon\Sysmon64.exe -accepteula -i .\configs\sysmon-noirlycan.xml
```

---

## Phụ lục C. Hướng dẫn tái lập thí nghiệm

### C.1. Yêu cầu phần cứng và phần mềm

- VM Windows 10/11 64-bit, 4 vCPU, 8 GB RAM, snapshot sạch.
- Python 3.11+, Git, Sysmon 64-bit (thư mục `Sysmon/`).
- Frida: `pip install frida frida-tools` (ghi version vào log).

### C.2. Cài đặt Noirlycan

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e .[dev]
```

### C.3. Chạy thí nghiệm có kiểm soát (spawn — chống E6)

```powershell
noirlycan-agent spawn --watch-sysmon -- C:\Lab\loader.exe
```

### C.4. Chạy file-drop (chống E3)

```powershell
noirlycan-agent run --watch-sysmon --auto-attach-new-processes
# Copy sample vào thư mục watch
```

### C.5. Dashboard

```powershell
noirlycan-backend api --host 0.0.0.0 --port 8765
cd dashboard-ui && npm install && npm run build && cd ..
noirlycan-dashboard serve --port 8080
# http://127.0.0.1:8080
```

### C.6. Kiểm thử tự động

```powershell
uv run pytest tests/test_correlation.py tests/test_ired_team_classifier.py -v
```

### C.7. Ghi chú reproducibility

Ghi vào luận văn: SHA256 VM image, phiên bản Frida, ngày chạy, đường dẫn `logs/session-*.jsonl`.

---

## Phụ lục D. Thiết kế PoC-Bench (loader an toàn)

| ID | Kỹ thuật | Né tránh mục tiêu | API điển hình |
|----|----------|-------------------|---------------|
| L1 | Section-mapping | E1, E2 | NtCreateSection, NtMapViewOfSection, ResumeThread |
| L2 | Shellcode remote thread | E1 | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread |
| L3 | APC injection | E2 | VirtualAllocEx, WriteProcessMemory, QueueUserAPC |
| L4 | Reflective DLL | E1, E3 | Manual map, không LoadLibrary |
| L5 | Classic hollowing | E2 | CREATE_SUSPENDED, SetThreadContext, ResumeThread |

Payload: MessageBox only — không shellcode weaponized. Ground truth do tác giả gắn nhãn.

---

## Phụ lục E. Protocol đánh giá Frida fidelity (M5)

**Giả thuyết H₀:** Frida drop > 1 % API call dưới tải trung bình.

**Driver:** `tests/manual/frida_fidelity_driver.py`

**Quy trình:**

1. Baseline: `python -m tests.manual.frida_fidelity_driver 1000`
2. Frida: `noirlycan-agent spawn -- python -m tests.manual.frida_fidelity_driver 1000`
3. So sánh `driver_count` vs event JSONL.
4. Lặp N = 100, 1000, 10000; mỗi N chạy 3 lần.

**Tiêu chí bác bỏ H₀:** drop-rate trung bình < 1 %.

*(Bảng kết quả điền sau khi chạy trên VM lab.)*

---

## Phụ lục F. Mẫu cấu trúc finding JSONL

```json
{
  "type": "finding",
  "severity": "high",
  "score": 75,
  "actor_pid": 4321,
  "target_pid": 5678,
  "technique": "process_hollowing_section",
  "evidence": {
    "cross_process": true,
    "section_mapping": true,
    "related_file": "C:\\Users\\Lab\\Downloads\\sample.exe"
  },
  "primitives": ["allocate", "write", "execute"]
}
```

Trường `related_file` thể hiện đóng góp chống **E3** — liên kết injection với nguồn file.
