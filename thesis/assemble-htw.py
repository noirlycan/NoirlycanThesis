#!/usr/bin/env python3
"""Ghép các chương nguồn theo cấu trúc HTW (IMRAD) — Nguyễn Việt Hà, Khoa CNTT UET."""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CH = ROOT / "chapters"
OUT = CH / "_assembled"


def read_body(path: Path) -> str:
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if lines and lines[0].startswith("# "):
        return "\n".join(lines[1:]).lstrip("\n")
    return text


def renumber_major_sections(body: str, old_ch: int, new_ch: int, offset: int = 0) -> str:
    """## old.N -> ## new.(N+offset); ### old.N.M -> ### new.(N+offset).M; Bảng/Hình tương ứng."""

    def sec_num(m: re.Match[str]) -> str:
        n = int(m.group(1))
        return f"{new_ch}.{n + offset}"

    body = re.sub(rf"^## {old_ch}\.(\d+)", lambda m: f"## {sec_num(m)}", body, flags=re.M)
    body = re.sub(
        rf"^### {old_ch}\.(\d+)\.(\d+)",
        lambda m: f"### {new_ch}.{int(m.group(1)) + offset}.{m.group(2)}",
        body,
        flags=re.M,
    )
    body = re.sub(rf"\*\*Bảng {old_ch}\.", f"**Bảng {new_ch}.", body)
    body = re.sub(rf"\*\*Hình {old_ch}\.", f"**Hình {new_ch}.", body)
    body = re.sub(rf"Hình {old_ch}\.", f"Hình {new_ch}.", body)
    body = re.sub(rf"Bảng {old_ch}\.", f"Bảng {new_ch}.", body)
    body = re.sub(rf"Chương {old_ch}\b", f"Chương {new_ch}", body)
    body = re.sub(rf"chương {old_ch}\b", f"chương {new_ch}", body)
    return body


def extract_related_for_experiment(src: str) -> tuple[str, int]:
    """Trích khảo sát liên quan từ chương nguồn 03; trả về (nội dung, số mục ##)."""
    start = src.find("## 2.1. Bối cảnh")
    end = src.find("## 2.11. Định vị luận văn")
    if start == -1 or end == -1:
        return "", 0
    chunk = src[start:end].strip()
    chunk = re.sub(r"^## 2\.", "## 4.", chunk, flags=re.M)
    chunk = re.sub(r"^### 2\.", "### 4.", chunk, flags=re.M)
    chunk = re.sub(r"\*\*Bảng 2\.", "**Bảng 4.", chunk)
    chunk = re.sub(r"\*\*Hình 2\.", "**Hình 4.", chunk)
    intro = (
        "Phần đầu chương trình bày **nghiên cứu liên quan và baseline so sánh** theo hướng dẫn "
        "HTW — đặt sau phương pháp và hiện thực, trước kết quả thực nghiệm. Căn cứ trung tâm "
        "là Di Pietro et al. (ASIA CCS 2025) [4]; các công trình [7], [12] bổ sung nền tảng "
        "primitive và behavior graph.\n\n"
    )
    body = intro + chunk
    n = count_major_sections(body, 4)
    return body, n


def count_major_sections(body: str, ch: int) -> int:
    nums = [int(m.group(1)) for m in re.finditer(rf"^## {ch}\.(\d+)", body, re.M)]
    return max(nums) if nums else 0


def assemble_chapter2() -> str:
    threat = read_body(CH / "04-threat-model.md")
    method = read_body(CH / "05-phuong-phap.md")
    threat = renumber_major_sections(threat, 3, 2, offset=0)
    max_threat = count_major_sections(threat, 2)
    method = renumber_major_sections(method, 4, 2, offset=max_threat)
    header = (
        "# CHƯƠNG 2. PHƯƠNG PHÁP TĂNG CƯỜNG PHÁT HIỆN MÃ ĐỘC DƯỚI NÉ TRÁNH\n\n"
        "Chương này trình bày **định nghĩa bài toán**, **threat model**, **phương pháp giải quyết** "
        "(kế thừa và mở rộng [4]), và **phân tích đánh giá phương pháp** — phân biệt rõ kết quả đã có "
        "và đóng góp của luận văn (nguyên tắc khởi–thừa–chuyển–kết). Phần đầu formal hóa đối thủ "
        "và giả định; phần sau mô tả pipeline 2-of-3, provenance và telemetry kép.\n\n---\n\n"
    )
    return header + threat + "\n\n---\n\n" + method


def assemble_chapter3() -> str:
    body = read_body(CH / "06-thiet-ke-hien-thuc.md")
    body = renumber_major_sections(body, 5, 3, offset=0)
    header = (
        "# CHƯƠNG 3. THIẾT KẾ VÀ HIỆN THỰC HỆ THỐNG NOIRLYCAN\n\n"
        "Chương cụ thể hóa phương pháp Chương 2 thành artifact phần mềm — theo định hướng "
        "ứng dụng công nghệ trong hướng dẫn HTW: phân tích, thiết kế (Clean Architecture), "
        "cài đặt (Python, Frida, Sysmon, Django dashboard). Mục tiêu là tái tạo được "
        "(*reproducible*) trên VM Windows lab.\n\n---\n\n"
    )
    return header + body


def assemble_chapter4() -> str:
    related_src = (CH / "03-cong-trinh-lien-quan.md").read_text(encoding="utf-8")
    related, related_sections = extract_related_for_experiment(related_src)
    eval_body = read_body(CH / "07-danh-gia.md")
    discuss_body = read_body(CH / "08-thao-luan.md")
    offset = related_sections  # đẩy phần thực nghiệm sau khảo sát liên quan
    eval_body = renumber_major_sections(eval_body, 6, 4, offset=offset)
    max_eval = count_major_sections(eval_body, 4)
    discuss_body = renumber_major_sections(discuss_body, 7, 4, offset=max_eval)
    header = (
        "# CHƯƠNG 4. THỰC NGHIỆM, KẾT QUẢ VÀ SO SÁNH ĐÁNH GIÁ\n\n"
        "Chương mô tả công cụ thực nghiệm, môi trường, dữ liệu, cách tổ chức thí nghiệm, "
        "kết quả định lượng và định tính, ví dụ điển hình, **so sánh với nghiên cứu liên quan** "
        "và thảo luận (Discussion trong khuôn IMRAD). Nguyên tắc tái tạo được: đủ chi tiết để "
        "người có năng lực tương đương lặp lại thực nghiệm.\n\n---\n\n"
    )
    parts = [header]
    if related:
        parts.append(related + "\n\n---\n\n")
    parts.append(eval_body)
    parts.append("\n\n---\n\n")
    parts.append(discuss_body)
    return "".join(parts)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    (OUT / "03-phuong-phap-htw.md").write_text(assemble_chapter2(), encoding="utf-8")
    (OUT / "04-thiet-ke-htw.md").write_text(assemble_chapter3(), encoding="utf-8")
    (OUT / "05-thuc-nghiem-htw.md").write_text(assemble_chapter4(), encoding="utf-8")
    print("Assembled HTW chapters in", OUT)


if __name__ == "__main__":
    main()
