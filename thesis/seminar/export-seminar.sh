#!/usr/bin/env bash
# Export seminar report to Word/PDF (requires pandoc).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

INPUT="${1:-bao-cao-seminar-chi-tiet.md}"
BASE="${INPUT%.md}"
DOCX="${BASE}.docx"
PDF="${BASE}.pdf"
REF="$ROOT/seminar-reference.docx"
FILTER="$ROOT/pagebreak.lua"

if ! command -v pandoc >/dev/null 2>&1; then
  echo "[!] pandoc not found. Install: brew install pandoc"
  exit 1
fi

echo "[+] Export Word: $DOCX"
PANDOC_ARGS=(
  --from markdown
  --standalone
  --toc
  --toc-depth=3
  --resource-path=.
  --lua-filter="$FILTER"
  -V lang=vi-VN
)
if [[ -f "$REF" ]]; then
  PANDOC_ARGS+=(--reference-doc="$REF")
fi
pandoc "$INPUT" -o "$DOCX" "${PANDOC_ARGS[@]}"

if command -v pdflatex >/dev/null 2>&1; then
  echo "[+] Export PDF: $PDF"
  pandoc "$INPUT" \
    -o "$PDF" \
    --from markdown \
    --pdf-engine=pdflatex \
    --toc \
    --toc-depth=3 \
    -V lang=vi-VN \
    -V geometry:margin=2.5cm \
    2>/dev/null || echo "[!] PDF export skipped (pdflatex issue)"
else
  echo "[~] pdflatex not found — skip PDF (Word OK)"
fi

echo "[+] Done: $ROOT/$DOCX"
