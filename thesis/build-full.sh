#!/usr/bin/env bash
# Ghép luận văn đầy đủ → thesis/luan-van-day-du.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="$ROOT/luan-van-day-du.md"
{
  cat "$ROOT/00-front-matter.md"
  echo -e "\n---\n"
  cat "$ROOT/chapters/01-mo-dau.md"
  for f in "$ROOT/chapters"/0{2..8}-*.md; do
    echo -e "\n---\n"
    cat "$f"
  done
  echo -e "\n---\n"
  cat "$ROOT/ket-luan.md"
  echo -e "\n---\n"
  cat "$ROOT/tai-lieu-tham-khao.md"
  echo -e "\n---\n"
  cat "$ROOT/phu-luc.md"
} > "$OUT"
echo "Wrote $OUT ($(wc -l < "$OUT") lines)"
