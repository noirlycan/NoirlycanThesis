#!/usr/bin/env bash
# Build markdown HTW + xuất Word final (UET 139/ĐT + HTW Nguyễn Việt Hà).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

./build-full.sh

REF="$ROOT/uet-reference.docx"
if [[ ! -f "$REF" ]]; then
  echo "Tạo mẫu reference.docx (chạy một lần)..."
  pandoc --print-default-data-file reference.docx > "$REF" 2>/dev/null || true
fi

COMBINED="$ROOT/.pandoc-input.md"
{
  cat "$ROOT/pandoc-metadata.yaml"
  echo ""
  cat "$ROOT/00-bia-chinh.md"
  echo -e "\n---\n"
  cat "$ROOT/00-front-matter.md"
  echo -e "\n---\n"
  # Mục lục: pandoc --toc tự sinh; không chèn placeholder 01-muc-luc.md
  cat "$ROOT/02-danh-muc-viet-tat.md"
  echo -e "\n---\n"
  cat "$ROOT/danh-muc-bang.md"
  echo -e "\n---\n"
  cat "$ROOT/danh-muc-hinh.md"
  echo -e "\n---\n"
  cat "$ROOT/chapters/01-mo-dau.md"
  echo -e "\n---\n"
  cat "$ROOT/chapters/02-co-so-ly-thuyet.md"
  echo -e "\n---\n"
  python3 "$ROOT/assemble-htw.py" >/dev/null
  cat "$ROOT/chapters/_assembled/03-phuong-phap-htw.md"
  echo -e "\n---\n"
  cat "$ROOT/chapters/_assembled/04-thiet-ke-htw.md"
  echo -e "\n---\n"
  cat "$ROOT/chapters/_assembled/05-thuc-nghiem-htw.md"
  echo -e "\n---\n"
  cat "$ROOT/ket-luan.md"
  echo -e "\n---\n"
  cat "$ROOT/danh-muc-cong-trinh.md"
  echo -e "\n---\n"
  cat "$ROOT/tai-lieu-tham-khao.md"
  echo -e "\n---\n"
  cat "$ROOT/phu-luc.md"
} > "$COMBINED"

OUT_FINAL="$ROOT/luan-van-final.docx"
OUT_LV="$ROOT/luan-van-day-du.docx"
OUT_TT="$ROOT/tom-tat-final.docx"
OUT_INFO="$ROOT/thong-tin-luan-van.docx"

PANDOC_ARGS=(
  --from markdown
  --standalone
  --toc
  --toc-depth=3
  -V lang=vi-VN
  -V mainfont="Times New Roman"
  -V fontsize=13pt
  -V geometry:"top=2cm,bottom=2cm,left=3cm,right=2cm"
  -V linestretch=1.2
  -V documentclass=article
)

if [[ -f "$REF" ]]; then
  PANDOC_ARGS+=(--reference-doc="$REF")
fi

echo "→ $OUT_FINAL"
pandoc "$COMBINED" -o "$OUT_FINAL" "${PANDOC_ARGS[@]}"

cp "$OUT_FINAL" "$OUT_LV"

echo "→ $OUT_TT"
pandoc "$ROOT/tom-tat-luan-van.md" -o "$OUT_TT" \
  --from markdown --standalone \
  -V mainfont="Times New Roman" -V fontsize=11pt \
  ${REF:+--reference-doc="$REF"}

echo "→ $OUT_INFO"
pandoc "$ROOT/thong-tin-luan-van.md" -o "$OUT_INFO" \
  --from markdown --standalone \
  -V mainfont="Times New Roman" -V fontsize=13pt \
  ${REF:+--reference-doc="$REF"}

rm -f "$COMBINED"

WORDS=$(wc -w < "$ROOT/luan-van-day-du.md" | tr -d ' ')
# Ước lượng: ~450 từ/trang (Times 13, giãn 1.2) + ~15 trang front matter
EST_PAGES=$(( WORDS / 450 + 15 ))

echo ""
echo "════════════════════════════════════════"
echo "  LUẬN VĂN WORD FINAL"
echo "  File:  $OUT_FINAL"
echo "  Từ:    $WORDS (~${EST_PAGES} trang A4 ước lượng)"
echo "  Tóm tắt: $OUT_TT"
echo "  Thông tin LV: $OUT_INFO"
echo "════════════════════════════════════════"
ls -lh "$OUT_FINAL" "$OUT_TT" "$OUT_INFO"
