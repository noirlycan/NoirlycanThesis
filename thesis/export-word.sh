#!/usr/bin/env bash
# Build markdown HTW + xuất Word final (UET 139/ĐT + HTW Nguyễn Việt Hà).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

./build-full.sh

REF="$ROOT/uet-reference.docx"
if [[ ! -f "$REF" ]]; then
  echo "THIẾU $REF — tạo bằng scratchpad/make_uet_ref.py (Times 13, lề UET, số trang)." >&2
  exit 1
fi

# Heading 1 trong uet-reference.docx đã có page-break-before → mỗi phần tự sang trang mới.
COMBINED="$ROOT/.pandoc-input.md"
{
  cat "$ROOT/pandoc-metadata.yaml"
  echo ""
  cat "$ROOT/00-bia-chinh.md"        # Trang bìa (Phụ lục 1)
  printf '\n\n'
  cat "$ROOT/00-front-matter.md"     # Phụ bìa (Phụ lục 2) + Lời cam đoan
  printf '\n\n'
  cat "$ROOT/01-muc-luc.md"          # MỤC LỤC — TOC field (F9 trong Word)
  printf '\n\n'
  cat "$ROOT/02-danh-muc-viet-tat.md"
  printf '\n\n'
  cat "$ROOT/danh-muc-bang.md"
  printf '\n\n'
  cat "$ROOT/danh-muc-hinh.md"
  printf '\n\n'
  cat "$ROOT/chapters/01-mo-dau.md"
  printf '\n\n'
  cat "$ROOT/chapters/02-co-so-ly-thuyet.md"
  printf '\n\n'
  python3 "$ROOT/assemble-htw.py" >/dev/null
  cat "$ROOT/chapters/_assembled/03-phuong-phap-htw.md"
  printf '\n\n'
  cat "$ROOT/chapters/_assembled/04-thiet-ke-htw.md"
  printf '\n\n'
  cat "$ROOT/chapters/_assembled/05-thuc-nghiem-htw.md"
  printf '\n\n'
  cat "$ROOT/ket-luan.md"
  printf '\n\n'
  cat "$ROOT/danh-muc-cong-trinh.md"
  printf '\n\n'
  cat "$ROOT/tai-lieu-tham-khao.md"
  printf '\n\n'
  cat "$ROOT/phu-luc.md"
} > "$COMBINED"

OUT_FINAL="$ROOT/luan-van-final.docx"
OUT_LV="$ROOT/luan-van-day-du.docx"
OUT_TT="$ROOT/tom-tat-final.docx"
OUT_INFO="$ROOT/thong-tin-luan-van.docx"

PANDOC_ARGS=(
  --from markdown
  --standalone
  --resource-path="$ROOT"
  -V lang=vi-VN
  --reference-doc="$REF"
)

echo "→ $OUT_FINAL"
pandoc "$COMBINED" -o "$OUT_FINAL" "${PANDOC_ARGS[@]}"

# Bật "update fields" để Word tự đề nghị cập nhật MỤC LỤC khi mở file
python3 - "$OUT_FINAL" <<'PY'
import sys, zipfile, shutil, os, re
path = sys.argv[1]
tmp = path + ".tmp"
with zipfile.ZipFile(path) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename == "word/settings.xml":
            text = data.decode("utf-8")
            if "<w:updateFields" not in text:
                text = re.sub(r"(<w:settings[^>]*>)", r'\1<w:updateFields w:val="true" />', text, count=1)
            data = text.encode("utf-8")
        zout.writestr(item, data)
os.replace(tmp, path)
print("  updateFields: ON")
PY

cp "$OUT_FINAL" "$OUT_LV"

echo "→ $OUT_TT (lưu ý: in khổ A5, Times 11 — chỉnh Page Setup khi in)"
pandoc "$ROOT/tom-tat-luan-van.md" -o "$OUT_TT" \
  --from markdown --standalone \
  --reference-doc="$REF"

echo "→ $OUT_INFO"
pandoc "$ROOT/thong-tin-luan-van.md" -o "$OUT_INFO" \
  --from markdown --standalone \
  --reference-doc="$REF"

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
