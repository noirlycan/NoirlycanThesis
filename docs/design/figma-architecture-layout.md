# Figma — Vẽ sơ đồ kiến trúc (không chồng lớp)

Hướng dẫn vẽ **đẹp, có hệ thống**, tránh hình chồng hình.  
Dùng **Figma Design** (khuyến nghị cho slide đẹp) hoặc **FigJam** (nhanh hơn).

**Khung import sẵn:** [`architecture-comparison-template.svg`](architecture-comparison-template.svg)  
**Tokens màu/chữ:** [`design-tokens.json`](design-tokens.json)

---

## Nguyên tắc chống chồng lớp

1. **Swimlane (cột / hàng cố định)** — không đặt node tự do trên canvas.
2. **Kích thước node cố định** — mọi hộp cùng loại cùng `W × H`.
3. **Gutter (vùng trống)** — chỉ dành cho mũi tên; không đặt text/hộp trong gutter.
4. **Connector bám cạnh** — nối từ **bottom center** → **top center** (dọc); nối ngang chỉ ở **1 hàng bridge** duy nhất.
5. **Auto Layout** — mỗi cột là Frame `Vertical, gap 40, padding 24`.
6. **Snap 8px** — bật grid 8px + snap trong Figma.

---

## Thiết lập file Figma

| Thuộc tính | Giá trị |
|------------|---------|
| Frame chính | `1920 × 1080` (16:9 slide) |
| Grid | 8px, subdivisions 4 |
| Layout grid (optional) | 12 cột, margin 64, gutter 24 |
| Font display | Space Grotesk |
| Font mono | IBM Plex Mono |

### Tạo file

1. Figma → **New design file** → đặt tên `Noirlycan — Architecture`.
2. Frame `Slide / Comparison` — `1920 × 1080`, fill `#F5F6F7`.
3. Import SVG: **File → Place image** → chọn `architecture-comparison-template.svg` → khóa layer làm nền (optional).
4. Vẽ đè lên SVG bằng components bên dưới (hoặc ungroup SVG và đổi màu).

---

## Component library (tạo trước khi vẽ)

Tạo page `Components` với các master sau.

### `Arch/Node` — hộp chuẩn

| Prop | Giá trị |
|------|---------|
| Size | `300 × 72` |
| Radius | `14` |
| Padding | `16` horizontal, `12` vertical |
| Title | Space Grotesk 14 Semibold |
| Subtitle | IBM Plex Mono 11, muted |
| Border | 1px |
| Shadow | `0 4px 12px rgba(15,23,42,0.08)` |

**Variants (Property: `lane`):**

| Variant | Fill | Border | Title color |
|---------|------|--------|-------------|
| `paper` | `#EEF0F3` | `#CBD2D9` | `#3D4F5F` |
| `shared` | `#FFF8E6` | `#F0D78C` | `#7A5B00` |
| `noirlycan` | `#E8FAF8` | `#8FD9D2` | `#0D5C55` |
| `sensor` | `#EDF4FF` | `#A8C4F5` | `#1E4A8A` |
| `output` | `#F3EEFF` | `#C4B5FD` | `#5B3E96` |

### `Arch/Lane` — vùng cột (swimlane)

| Prop | Giá trị |
|------|---------|
| Width | xem bảng layout §1 |
| Min height | `720` |
| Fill | lane tint 6% opacity |
| Radius | `20` |
| Label | eyebrow 11px uppercase, tracking 0.14em |

### `Arch/Arrow` — connector

- Dùng Figma **Connector** (plugin native) hoặc vector line **orthogonal**.
- Stroke `2px`; màu `#94A3B8` (solid) hoặc `#F59E0B` (dashed replicate).
- **Không** vẽ chéo qua node — nếu cần ngang, đi qua **gutter 80px**.

---

## §1. Slide so sánh — Paper | Shared | Noirlycan

### Layout tọa độ (frame 1920×1080)

```
Y=0
├─ 0–64     margin top
├─ 64–148   TITLE + subtitle
├─ 148–868  DIAGRAM (3 lanes + 2 gutters)  ← chỉ vẽ trong vùng này
├─ 868–940  LEGEND
└─ 940–1080 FOOTER bullets
```

### Cột (X từ trái frame)

| Vùng | X | W | Ghi chú |
|------|---|---|---------|
| Margin L | 0 | 64 | |
| **Lane A — Paper** | 64 | 500 | 5 node dọc |
| **Gutter G1** | 564 | 80 | chỉ mũi tên replicate |
| **Lane B — Shared** | 644 | 380 | 6 node dọc |
| **Gutter G2** | 1024 | 80 | chỉ mũi tên extend |
| **Lane C — Noirlycan** | 1104 | 752 | sensors + collector + engine + output |
| Margin R | 1856 | 64 | |

### Lane A — nodes (căn giữa trong cột, W=300)

| # | Label | Subtitle | Y (top) |
|---|-------|----------|---------|
| A1 | Malware corpus | 56.340 samples · 2017–2023 | 180 |
| A2 | QEMU sandbox | dynamic execution | 292 |
| A3 | Custom API tracer | Sap4Sec/process-injection | 404 |
| A4 | Batch correlate | 2/3 · congruence · temporal | 516 |
| A5 | Dataset & stats | prevalence · sandbox compare | 628 |

**Mũi tên trong Lane A:** A1↓A2↓A3↓A4↓A5 (thẳng đứng, không lệch X).

### Lane B — nodes (W=280, căn giữa cột)

| # | Label | Y |
|---|-------|---|
| B1 | ALLOCATE | 200 |
| B2 | WRITE | 272 |
| B3 | EXECUTE | 344 |
| B4 | Rule 2-of-3 | 440 |
| B5 | Memory congruence | 512 |
| B6 | Temporal ordering | 584 |
| B7 | `correlation.py` | 672 |

B1–B3: nhóm primitive (gap 24). B4–B6: gap 32. B7: module box, mono font.

### Lane C — chia 4 sub-row (không chồng)

**Row C1 — Sensors** `Y=180`, H=200

| Node | X trong lane | W | Label |
|------|--------------|---|-------|
| C1a | 1104 | 220 | Sysmon (kernel) |
| C1b | 1340 | 220 | Frida hooks |
| C1c | 1576 | 220 | File watcher |

3 hộp **ngang**, gap `24`. Auto Layout horizontal.

**Row C2 — Collector** `Y=420`, H=72`

| C2 | X=1104, W=692 | Collector loop · cli.py · analysis_queue |

**Row C3 — Engine** `Y=520`, H=120`

| C3a | X=1104, W=330 | Correlator + file provenance |
| C3b | X=1458, W=338 | Classifier + network watch |

2 hộp ngang, gap `24`.

**Row C4 — Output** `Y=680`, H=72`

| C4a | 1104, W=200 | JSONL |
| C4b | 1328, W=200 | SQLite |
| C4c | 1552, W=244 | Dashboard |

**Mũi tên dọc giữa các row C:** C1↓C2↓C3↓C4 (một cột trung tâm lane, X≈1450).

### Bridge arrows (qua gutter — không cắt node)

| From | To | Route |
|------|-----|-------|
| A3 right edge | B4 left | ngang qua G1, Y=468 |
| B7 right edge | C3a left | ngang qua G2, Y=580 |
| Style replicate | dashed amber `#F59E0B` | |
| Style extend | solid cyan `#06B6D4` | |

**Cách vẽ bridge không chồng:**

1. Từ A3: đi ra **right** 20px → xuống/ lên tới `Y=468` → sang phải tới B4.
2. Đặt label `replicate` **trên** đoạn ngang trong G1 (không đè node).
3. Tương tự B7 → C3a qua G2 tại `Y=580`.

---

## §2. Slide pipeline Noirlycan (4 swimlane ngang)

Frame `1920 × 900` — **hàng** thay vì cột, rất ít chồng lớp.

| Lane | Y | H | Nội dung |
|------|---|---|----------|
| L1 INPUTS | 120 | 140 | File watcher · Sysmon · Frida |
| L2 RUNTIME | 300 | 140 | Collector · Queue · Triage |
| L3 ENGINE | 480 | 160 | Correlator · Classifier |
| L4 OUTPUT | 680 | 120 | JSONL · SQLite · Dashboard |

**Gutter giữa lane:** 40px trống (chỉ arrows).

**Nodes mỗi lane:** max 4 hộp `240×72`, gap `32`, căn giữa theo X trong `64…1856`.

**Arrows:**

- L1 → L2: 3 mũi tên gộp về 1 **bus line** ngang `Y=278` rồi xuống Collector (tránh 3 line chồng nhau).
- L2 → L3: Queue → spawn → Frida: dùng **đường cong rộng** đi **vòng phía trái** frame (X=40), không đi qua giữa.

---

## §3. FigJam (nhanh, ít chỉnh pixel)

1. Tạo board `Noirlycan — Architecture`.
2. Bật **snap to grid**.
3. Dùng **Sections** (không phải stickies chồng tùy ý):

| Section | Size gợi ý |
|---------|------------|
| Paper | 520 × 800 |
| Shared | 400 × 800 |
| Noirlycan | 760 × 800 |

4. Trong mỗi section: **Sort nodes vertically** (plugin) hoặc align top, distribute vertical spacing `48`.
5. Connector tool: click **bottom dot** → **top dot** của node kế tiếp.
6. **Không** dùng auto-layout Mermaid paste (hay bị chồng) — chỉ dùng làm tham chiếu logic.

---

## §4. Checklist trước khi export slide

- [ ] Không có node nào overlap (Figma: Select all → không viền đỏ khi measure)
- [ ] Mọi mũi tên có `≥12px` clearance từ cạnh node
- [ ] Text không tràn — subtitle max 2 dòng, truncate bằng `…`
- [ ] Legend góc dưới: 3 màu lane + dashed/solid bridge
- [ ] Export PNG @2x hoặc PDF vector cho PowerPoint/Keynote

---

## §5. Import SVG template

1. Mở [`architecture-comparison-template.svg`](architecture-comparison-template.svg).
2. Figma → drag vào frame `1920×1080`.
3. Ungroup nếu cần đổi màu từng lane.
4. Thay text bằng font Space Grotesk / IBM Plex Mono cho đồng bộ thesis.

SVG đã căn sẵn: **3 cột + 2 gutter + bridge tại Y cố định** — không chồng hộp.

---

## Liên kết

- [`architecture-diagrams.md`](../architecture-diagrams.md) — nội dung logic
- [`architecture-diagrams-slide.md`](../architecture-diagrams-slide.md) — speaker notes
- [`noirlycan-figma-blueprint.md`](noirlycan-figma-blueprint.md) — dashboard UI
