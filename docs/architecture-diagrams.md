# Sơ đồ kiến trúc — Noirlycan & ASIA CCS 2025

Tài liệu phục vụ **Chương 5 (Phương pháp)** và **Chương 6 (Thiết kế & hiện thực)** của luận văn.  
Phiên bản một trang cho slide bảo vệ: [`architecture-diagrams-slide.md`](architecture-diagrams-slide.md).

**Paper tham chiếu:** Di Pietro, D'Elia, Querzoni — *Can You Run My Code? A Close Look at Process Injection in Windows Malware* (ASIA CCS 2025).  
DOI: [10.1145/3708821.3736206](https://doi.org/10.1145/3708821.3736206)

**Đối chiếu chi tiết:** [`report-asiaccs25-comparison.md`](report-asiaccs25-comparison.md), [`paper-and-repo-analysis.md`](paper-and-repo-analysis.md).

---

## 1. Kiến trúc paper (ASIA CCS 2025)

Paper là **framework phân tích batch quy mô lớn**. Mục tiêu: đo prevalence injection và đề xuất phương pháp phát hiện tổng quát trên sandbox.

### 1.1. Sơ đồ tổng thể

```mermaid
flowchart TB
  subgraph input [Đầu vào]
    DS["Malware corpus<br/>56.340 mẫu · 2017–2023"]
    AE["Anti-evasion layer"]
  end

  subgraph sandbox [Môi trường thực thi]
    QEMU["Sandbox / QEMU"]
    TR["Custom API Tracer<br/>Sap4Sec/process-injection"]
  end

  subgraph trace [Trace & trích xuất]
    LOG["API trace logs"]
    EC["API Equivalence Classes<br/>Allocate · Write · Execute"]
    PRIM["Primitive events"]
  end

  subgraph core [Lõi phát hiện]
    R23["Rule 2-of-3<br/>≥2 primitive khác loại<br/>cùng actor, victim"]
    MEM["Memory Range Congruence"]
    TMP["Temporal Ordering"]
    MULTI["Multi-process / recursive chain"]
  end

  subgraph classify [Phân loại & đánh giá]
    TECH["Technique classifier<br/>~12 kỹ thuật"]
    STAT["Thống kê prevalence"]
    CMP["So sánh sandbox<br/>Cuckoo · VT"]
  end

  subgraph output [Đầu ra khoa học]
    ART["Artifact: code · dataset · logs"]
    PUB["~16.5% có injection<br/>21.2% sandbox bỏ sót"]
  end

  DS --> AE --> QEMU --> TR --> LOG
  LOG --> EC --> PRIM
  PRIM --> R23 --> MEM --> TMP --> MULTI
  MULTI --> TECH --> STAT --> CMP --> ART --> PUB
```

### 1.2. Đặc điểm kiến trúc

| Lớp | Vai trò |
|-----|---------|
| Tracer đơn | Một lớp instrumentation custom trong sandbox QEMU |
| Batch-first | Chạy hàng chục nghìn mẫu; không UI real-time |
| Điểm bắt đầu | Process đã thực thi trong sandbox |
| Đầu ra | Dataset, thống kê prevalence, so sánh sandbox |

### 1.3. Bốn thành tố methodology (paper §3)

```mermaid
flowchart LR
  subgraph primitives [Operational primitives]
    A[Allocate]
    W[Write]
    E[Execute]
  end

  subgraph rules [Correlation rules]
    R["2-of-3 rule"]
    M["Memory congruence<br/>overlap addr range"]
    T["Temporal order<br/>A → W → E"]
  end

  subgraph map [API equivalence]
    EC["VirtualAllocEx ≡ NtAllocateVirtualMemory<br/>NtMapViewOfSection ≡ Write+Allocate<br/>ResumeThread ≡ Execute …"]
  end

  primitives --> rules
  map --> primitives
```

---

## 2. Kiến trúc hệ thống Noirlycan (implementation)

Prototype lab Windows 10/11: **kế thừa lõi 2/3 primitive**, mở rộng file provenance, dual telemetry, dashboard.

### 2.1. Sơ đồ phân lớp

```mermaid
flowchart TB
  subgraph win [Windows Lab VM]
    subgraph sensors [Lớp cảm biến]
      SM["Sysmon kernel<br/>EID 1·3·7·8·10·11·15"]
      FR["Frida user-mode<br/>windows_injection_hooks.js"]
      FW["FileDropWatcher"]
    end

    subgraph collector [Collector]
      LOOP["cli.py · collector_runtime.py<br/>run · spawn · batch"]
      AQ["analysis_queue.py"]
      RT["runtime_config.py · .runtime.json"]
    end

    subgraph analysis [Phân tích]
      TRI["triage.py — static"]
      COR["correlation.py"]
      subgraph paper_core [Lõi paper]
        R23N["2-of-3"]
        MEMN["Memory congruence"]
        TMPN["Temporal ordering"]
      end
      CLS["technique_classifier.py<br/>36 techniques"]
      NET["network.py — beacon watch"]
    end

    subgraph persist [Persistence]
      JSONL["log_store — session-*.jsonl"]
      SQLITE["analysis_db — noirlycan.db"]
      CACHE["jsonl_analytics_cache"]
      RULES[".classifier_rules.json"]
    end

    subgraph present [Presentation]
      API["Django REST /api/*"]
      WS["WebSocket live_sync"]
      UI["Dashboard — 10 tabs EN/VI"]
      OFF["corpus · reclassify · compare"]
    end
  end

  FW --> LOOP
  SM --> LOOP
  FR --> LOOP
  LOOP --> AQ
  AQ -->|spawn| FR
  FW --> TRI --> COR
  LOOP --> COR
  paper_core --> COR
  COR --> CLS
  COR --> NET
  COR -->|Finding| JSONL
  JSONL --> SQLITE
  JSONL --> CACHE
  SQLITE --> API
  JSONL --> API
  API --> UI
  WS --> UI
  JSONL --> OFF
  RULES --> COR
  RT <--> API
  RT <--> LOOP
```

### 2.2. Module map (Chương 6)

| Module | Vai trò | Kết nối |
|--------|---------|---------|
| `cli.py` | Entry: run, spawn, dashboard, corpus, reclassify | → collector_runtime, log_store |
| `collector_runtime.py` | Vòng lặp, JsonlWriter, drain Frida/Sysmon | → correlation, sysmon, frida_manager |
| `sysmon.py` | Đọc Event Log Sysmon | → correlator |
| `frida_manager.py` | Attach/spawn, primitive bridge | → correlator |
| `file_watch.py` | Poll thư mục lab | → triage, analysis_queue |
| `correlation.py` | Lõi 2/3 + scoring + network watch | ← paper methodology |
| `injection_api_manifest.py` | PAPER_API_CLASSES | ← paper Appendix |
| `technique_classifier.py` | Rule cascade 36 kỹ thuật | extension |
| `log_store.py` | Đọc/ghi JSONL, aggregate | → dashboard views |
| `analysis_db.py` | SQLite uploads, findings, cache | → dashboard views |
| `session_analytics.py` | Corpus metrics | → /api/corpus |
| `reclassify.py` | Replay JSONL offline | → /api/reclassify |
| `dashboard/` | Django + Daphne :8765 | REST + WebSocket |

### 2.3. Luồng dữ liệu — file-drop loader

```mermaid
sequenceDiagram
  participant F as File / Sysmon / Frida
  participant C as Collector
  participant R as Correlator
  participant J as JSONL
  participant D as Dashboard

  F->>C: FileCreate E11 / file watcher
  C->>J: type=file
  C->>C: triage SHA256 PE entropy
  F->>C: ProcessCreate E1
  C->>R: add_process lineage related_file
  F->>C: Frida primitive A/W/E
  C->>R: add_primitive
  R->>R: 2/3 congruence temporal classify
  R->>C: Finding
  C->>J: type=finding
  R->>C: network watch target PID 5min
  D->>J: GET /api/overview /api/session
```

### 2.4. JSONL event types

| `type` | Nguồn | Ý nghĩa |
|--------|--------|---------|
| `file` | Sysmon E11/E15, watcher | File mới trên đĩa |
| `sysmon` | Sysmon E1/E7/E8/E10 | Process, image, access |
| `primitive` | Frida | Allocate / write / execute |
| `finding` | Correlator | Injection phát hiện |
| `triage` | triage.py | Static analysis |
| `network` | Sysmon E3 | Kết nối sau injection watch |
| `evasion` | Frida | Anti-analysis signal |
| `frida_raw` | Frida | Raw hook payload |

### 2.5. Storage layers

| Layer | Path | Nội dung |
|-------|------|----------|
| JSONL sessions | `logs/session-*.jsonl` | Telemetry chính, append-only |
| Analysis DB | `logs/noirlycan.db` | uploads, parsed_sessions, stored_findings, cache |
| Runtime | `logs/.runtime.json` | Heartbeat, watch toggles |
| Queue | `logs/.analysis_queue.json` | Spawn requests từ dashboard |
| Classifier | `logs/.classifier_rules.json` | Thresholds, custom rules |

---

## 3. So sánh kiến trúc Paper ↔ Noirlycan

### 3.1. Sơ đồ đặt chồng (overlay)

```mermaid
flowchart TB
  subgraph outer [Extension Noirlycan — đóng góp thesis]
    FP["File Provenance<br/>E11 + triage + watcher"]
    DUAL["Dual telemetry Sysmon + Frida"]
    OPS["Operational pipeline queue spawn dashboard"]
    TOOL["corpus reclassify compare"]
  end

  subgraph inner [Lõi paper — replication]
    EC2["injection_api_manifest.py"]
    COR2["correlation.py 2/3 rule"]
    TEST["tests/test_correlation.py"]
  end

  FP --> COR2
  DUAL --> EC2 --> COR2
  COR2 --> OPS --> TOOL
  TEST -.->|validate| COR2
```

### 3.2. Bảng đối chiếu

| Khía cạnh | Paper ASIA CCS 2025 | Noirlycan |
|-----------|---------------------|-----------|
| Mục tiêu | Prevalence injection quy mô lớn | Lab: file → process → injection |
| Instrumentation | 1 lớp custom tracer (sandbox) | Frida user + Sysmon kernel |
| Điểm bắt đầu | Process trong sandbox | File trên đĩa (E11 + watcher) |
| Lõi detection | 2/3 + congruence + temporal | **Kế thừa** `correlation.py` |
| API classes | Equivalence classes đầy đủ | **Kế thừa** `injection_api_manifest.py` |
| Phân loại kỹ thuật | ~12 kỹ thuật | 36 enum + rule cascade |
| Static analysis | Không | triage PE/entropy/signature |
| Vận hành | Batch offline | CLI real-time + dashboard |
| Persistence | Dataset nghiên cứu | JSONL + SQLite + cache |
| Hậu injection | Phân tích thủ công | Network beacon watch 5 phút |
| Đánh giá | 56.340 mẫu | PoC loader + subset |
| Đầu ra | Thống kê, artifact | JSONL, findings score, UI |

### 3.3. Mapping methodology → module

| Thành tố paper | Module repo | File |
|----------------|-------------|------|
| 3 operational primitive | `PrimitiveKind` | `models.py` |
| API equivalence class | `PAPER_API_CLASSES` | `injection_api_manifest.py` |
| Quy tắc 2/3 | `operational_kind_count >= 2` | `correlation.py`, `execution_analysis.py` |
| Memory congruence | `_has_memory_congruence()` | `correlation.py` |
| Temporal ordering | `_has_temporal_consistency()` | `correlation.py` |
| File provenance | `add_file`, `created_from_file` | `correlation.py`, `file_watch.py` |
| Technique labeling | `InjectionTechnique` + rules | `technique_classifier.py` |

### 3.4. Chỉ paper / chỉ Noirlycan

```mermaid
flowchart LR
  subgraph shared [Lõi chung]
    S1["3 primitive A/W/E"]
    S2["2-of-3 rule"]
    S3["Memory congruence"]
    S4["Temporal ordering"]
    S5["API equivalence"]
  end

  subgraph paper_only [Paper only]
    P1["QEMU sandbox 56k mẫu"]
    P2["Anti-evasion integration"]
    P3["Prevalence statistics"]
    P4["Sandbox comparison"]
  end

  subgraph noir_only [Noirlycan only]
    N1["Sysmon + Frida dual layer"]
    N2["File provenance pipeline"]
    N3["Dashboard WebSocket i18n"]
    N4["SQLite corpus cache reclassify"]
    N5["Network beacon watch"]
  end

  shared --> paper_only
  shared --> noir_only
```

---

## 4. Gợi ý chèn vào luận văn

| Chương | Sơ đồ | Mục đích |
|--------|-------|----------|
| **Ch. 5 — Methodology** | §1.3 (4 thành tố paper) | Định nghĩa phương pháp gốc |
| **Ch. 5 — Methodology** | §3.1 (overlay) | Vị trí đóng góp thesis |
| **Ch. 6 — Design** | §2.1 (phân lớp) | Kiến trúc implementation |
| **Ch. 6 — Design** | §2.2 (module map) | Chi tiết module |
| **Ch. 6 — Design** | §2.3 (sequence) | Luồng file-drop loader |
| **Ch. 3 — Related Work** | §3.2 (bảng đối chiếu) | Positioning vs paper |

**Chú thích hình (gợi ý):**  
*Figure X: Architecture of the ASIA CCS 2025 process-injection detection framework (left) and the Noirlycan lab telemetry extension (right). Shared core: 2-of-3 operational primitive rule with memory congruence and temporal ordering.*

---

## 5. Tài liệu liên quan

- [`architecture-diagrams-slide.md`](architecture-diagrams-slide.md) — một trang FigJam cho slide
- [`report-asiaccs25-comparison.md`](report-asiaccs25-comparison.md)
- [`paper-and-repo-analysis.md`](paper-and-repo-analysis.md)
- [`thesis-outline.md`](thesis-outline.md)
- [`design/noirlycan-figma-blueprint.md`](design/noirlycan-figma-blueprint.md)
