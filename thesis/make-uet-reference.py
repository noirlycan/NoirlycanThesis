#!/usr/bin/env python3
"""Tạo uet-reference.docx chuẩn UET 139/ĐT từ pandoc default reference (đã unzip tại uetref/)."""
import os
import re
import shutil
import subprocess
import sys

SRC = sys.argv[1]          # thư mục uetref đã unzip
OUT = sys.argv[2]          # đường dẫn uet-reference.docx đầu ra

sty_path = os.path.join(SRC, "word", "styles.xml")
xml = open(sty_path, encoding="utf-8").read()

# ── 1. docDefaults: Times New Roman 13pt, giãn dòng 1.2, lang vi-VN ──
xml = xml.replace(
    '<w:rFonts w:asciiTheme="minorHAnsi" w:eastAsiaTheme="minorEastAsia" w:hAnsiTheme="minorHAnsi" w:cstheme="minorBidi" />\n        <w:sz w:val="24" />\n        <w:szCs w:val="24" />\n        <w:lang w:val="en-US" w:eastAsia="zh-CN" w:bidi="ar-SA" />',
    '<w:rFonts w:ascii="Times New Roman" w:eastAsia="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" />\n        <w:sz w:val="26" />\n        <w:szCs w:val="26" />\n        <w:lang w:val="vi-VN" w:eastAsia="vi-VN" w:bidi="ar-SA" />',
)
xml = xml.replace(
    '<w:pPrDefault>\n      <w:pPr>\n        <w:spacing w:after="200" />\n      </w:pPr>\n    </w:pPrDefault>',
    '<w:pPrDefault>\n      <w:pPr>\n        <w:spacing w:after="120" w:line="288" w:lineRule="auto" />\n      </w:pPr>\n    </w:pPrDefault>',
)

# ── 2. Normal: căn đều hai bên ──
xml = xml.replace(
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">\n    <w:name w:val="Normal" />\n    <w:qFormat />\n  </w:style>',
    '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">\n    <w:name w:val="Normal" />\n    <w:qFormat />\n    <w:pPr><w:jc w:val="both" /></w:pPr>\n    <w:rPr><w:rFonts w:ascii="Times New Roman" w:eastAsia="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" /><w:sz w:val="26" /><w:szCs w:val="26" /></w:rPr>\n  </w:style>',
)

# ── 3. Heading: Times, đen; H1 14pt đậm căn giữa + sang trang mới ──
def style_block(styleid):
    m = re.search(r'<w:style [^>]*w:styleId="%s"\s*>.*?</w:style>' % styleid, xml, re.S)
    return m.group(0) if m else None

h1 = style_block("Heading1")
h1_new = h1.replace(
    "<w:keepLines />",
    "<w:keepLines />\n      <w:pageBreakBefore />",
).replace(
    '<w:outlineLvl w:val="0" />',
    '<w:jc w:val="center" />\n      <w:outlineLvl w:val="0" />',
)
h1_new = re.sub(r"<w:rPr>.*?</w:rPr>", (
    '<w:rPr>\n      <w:rFonts w:ascii="Times New Roman" w:eastAsia="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" />\n'
    '      <w:b />\n      <w:color w:val="000000" />\n      <w:sz w:val="28" />\n      <w:szCs w:val="28" />\n    </w:rPr>'
), h1_new, flags=re.S)
xml = xml.replace(h1, h1_new)

for hid, sz, extra in [("Heading2", 26, "<w:b />"), ("Heading3", 26, "<w:b /><w:i />"),
                       ("Heading4", 26, "<w:b /><w:i />"), ("Heading5", 26, "<w:b />"),
                       ("Heading6", 26, "<w:b />"), ("Heading7", 26, "<w:b />"),
                       ("Heading8", 26, "<w:b />"), ("Heading9", 26, "<w:b />")]:
    blk = style_block(hid)
    if not blk:
        continue
    new = re.sub(r"<w:rPr>.*?</w:rPr>", (
        '<w:rPr>\n      <w:rFonts w:ascii="Times New Roman" w:eastAsia="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" />\n'
        f'      {extra}\n      <w:color w:val="000000" />\n      <w:sz w:val="{sz}" />\n      <w:szCs w:val="{sz}" />\n    </w:rPr>'
    ), blk, flags=re.S)
    xml = xml.replace(blk, new)

# Char styles của heading + Hyperlink + TOCHeading: bỏ màu xanh
xml = re.sub(r'<w:color w:val="0F4761"[^/]*/>', '<w:color w:val="000000" />', xml)
xml = re.sub(r'<w:color w:val="365F91"[^/]*/>', '<w:color w:val="000000" />', xml)
xml = re.sub(r'<w:color w:val="4F81BD"[^/]*/>', '<w:color w:val="000000" />', xml)
xml = re.sub(r'<w:color w:val="595959"[^/]*/>', '<w:color w:val="000000" />', xml)
xml = re.sub(r'<w:color w:val="272727"[^/]*/>', '<w:color w:val="000000" />', xml)

toch = style_block("TOCHeading")
if toch:
    new = toch.replace('<w:b w:val="0" />', "<w:b />").replace('<w:bCs w:val="0" />', "<w:bCs />")
    new = new.replace(
        '<w:rFonts w:asciiTheme="majorHAnsi" w:eastAsiaTheme="majorEastAsia" w:hAnsiTheme="majorHAnsi" w:cstheme="majorBidi" />',
        '<w:rFonts w:ascii="Times New Roman" w:eastAsia="Times New Roman" w:hAnsi="Times New Roman" w:cs="Times New Roman" /><w:sz w:val="28" /><w:szCs w:val="28" />',
    )
    xml = xml.replace(toch, new)

# ── 4. Caption (đầu đề bảng/hình): 13pt, đậm nhãn không tách được → in thường, căn giữa ──
for cid in ("Caption", "TableCaption", "ImageCaption"):
    blk = style_block(cid)
    if not blk:
        continue
    new = blk
    if "<w:jc" in new:
        continue  # đã căn giữa sẵn
    if "</w:pPr>" in new:
        # jc đứng sau spacing/ind/keepNext trong CT_PPrBase → chèn cuối pPr
        new = new.replace("</w:pPr>", '  <w:jc w:val="center" />\n    </w:pPr>', 1)
    elif "<w:rPr>" in new:
        new = new.replace("<w:rPr>", '<w:pPr><w:jc w:val="center" /></w:pPr>\n    <w:rPr>', 1)
    else:
        new = new.replace("</w:style>", '  <w:pPr><w:jc w:val="center" /></w:pPr>\n  </w:style>', 1)
    xml = xml.replace(blk, new)

open(sty_path, "w", encoding="utf-8").write(xml)

# ── 5. theme1.xml: đổi font theme → Times New Roman (mọi tham chiếu theme còn sót) ──
thm_path = os.path.join(SRC, "word", "theme", "theme1.xml")
thm = open(thm_path, encoding="utf-8").read()
thm = re.sub(r'(<a:latin typeface=")[^"]*(")', r"\1Times New Roman\2", thm)
open(thm_path, "w", encoding="utf-8").write(thm)

# ── 6. sectPr: A4, lề 2-2-3-2, header số trang căn giữa phía trên, trang bìa không số ──
doc_path = os.path.join(SRC, "word", "document.xml")
doc = open(doc_path, encoding="utf-8").read()
sect_new = (
    "<w:sectPr>"
    '<w:headerReference w:type="default" r:id="rId100" />'
    '<w:headerReference w:type="first" r:id="rId101" />'
    "<w:footnotePr><w:numRestart w:val=\"eachSect\" /></w:footnotePr>"
    '<w:pgSz w:w="11906" w:h="16838" />'
    '<w:pgMar w:top="1134" w:right="1134" w:bottom="1134" w:left="1701" w:header="567" w:footer="567" w:gutter="0" />'
    "<w:titlePg />"
    '<w:cols w:space="708" />'
    '<w:docGrid w:linePitch="360" />'
    "</w:sectPr>"
)
doc = re.sub(r"<w:sectPr>.*?</w:sectPr>", sect_new, doc, flags=re.S)
open(doc_path, "w", encoding="utf-8").write(doc)

# header mặc định: số trang căn giữa
hdr1 = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:p><w:pPr><w:pStyle w:val="Header" /><w:jc w:val="center" /></w:pPr>'
    '<w:r><w:fldChar w:fldCharType="begin" /></w:r>'
    '<w:r><w:instrText xml:space="preserve"> PAGE </w:instrText></w:r>'
    '<w:r><w:fldChar w:fldCharType="separate" /></w:r>'
    "<w:r><w:t>1</w:t></w:r>"
    '<w:r><w:fldChar w:fldCharType="end" /></w:r>'
    "</w:p></w:hdr>"
)
# header trang đầu (bìa): rỗng
hdr2 = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
    '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
    '<w:p><w:pPr><w:pStyle w:val="Header" /></w:pPr></w:p></w:hdr>'
)
open(os.path.join(SRC, "word", "header1.xml"), "w", encoding="utf-8").write(hdr1)
open(os.path.join(SRC, "word", "header2.xml"), "w", encoding="utf-8").write(hdr2)

# Header style nếu chưa có
xml = open(sty_path, encoding="utf-8").read()
if 'w:styleId="Header"' not in xml:
    hdr_style = (
        '<w:style w:type="paragraph" w:styleId="Header">'
        '<w:name w:val="header" /><w:basedOn w:val="Normal" />'
        '<w:pPr><w:spacing w:after="0" w:line="240" w:lineRule="auto" /><w:jc w:val="center" /></w:pPr>'
        "</w:style>"
    )
    xml = xml.replace("</w:styles>", hdr_style + "</w:styles>")
    open(sty_path, "w", encoding="utf-8").write(xml)

# rels + content types
rels_path = os.path.join(SRC, "word", "_rels", "document.xml.rels")
rels = open(rels_path, encoding="utf-8").read()
if "rId100" not in rels:
    add = (
        '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Id="rId100" Target="header1.xml" />'
        '<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/header" Id="rId101" Target="header2.xml" />'
    )
    rels = rels.replace("</Relationships>", add + "</Relationships>")
    open(rels_path, "w", encoding="utf-8").write(rels)

ct_path = os.path.join(SRC, "[Content_Types].xml")
ct = open(ct_path, encoding="utf-8").read()
if "header1.xml" not in ct:
    add = (
        '<Override PartName="/word/header1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml" />'
        '<Override PartName="/word/header2.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml" />'
    )
    ct = ct.replace("</Types>", add + "</Types>")
    open(ct_path, "w", encoding="utf-8").write(ct)

# ── 7. Zip lại ──
if os.path.exists(OUT):
    os.remove(OUT)
subprocess.run(["zip", "-Xrq", os.path.abspath(OUT), "."], cwd=SRC, check=True)
print("OK →", OUT)
