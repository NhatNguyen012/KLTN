#!/usr/bin/env python3
"""STEP 19j - điền ô ghi chú (cột I) của dòng 'Tìm thêm dataset có multi-label cho DL' trong todolist.
Chỉ sửa đúng một ô trong xl/worksheets/sheet1.xml; mọi phần khác của file xlsx được chép nguyên byte. Có sao lưu trước.
"""
import os
import re
import shutil
import sys
import zipfile
from xml.sax.saxutils import escape

sys.stdout.reconfigure(encoding="utf-8")
SRC = "D:/UIT/KLTNv2/00_docs/NhatNguyen-HoangLam-KLTN-TodoList.xlsx"
BAK = "D:/UIT/KLTNv2/00_docs/NhatNguyen-HoangLam-KLTN-TodoList.backup_2026-10-10.xlsx"
TMP = SRC + ".tmp"

NOTE = """Đã tải và phân tích 3 dataset thầy gợi ý (báo cáo, mẫu thô, slide: 02_artifacts/19_dataset_analysis_v1):
- SAGA (IEEE TDSC 2025): 27.8M event, nhãn technique ATT&CK cho TỪNG event (58 technique, 98 nhãn technique+ability), log host kiểu Procmon. Bất cập: không có hostname/ppid, không có network; 91.4% event độc hại là 1 ability (T1005) chép y hệt ở 5 file => phải dedup và chia theo chiến dịch.
- Windows-APT 2025: 102,011 dòng, chỉ 5 máy. Nhãn tactic do LUẬT Wazuh gán (62.4% dòng), không phải ground truth; Collection/Exfiltration = 0 dòng; toàn là cảnh báo nên không có nền benign.
- skrghosh/apt-dataset: log eCAR (cùng định dạng OpTC) 22.3M event, 5 chiến dịch; KHÔNG có nhãn từng event (ground truth là PDF theo kịch bản), hostname luôn là "localhost".
- arXiv 2606.18190 (host + network + browser): chưa có link phát hành, chưa lấy được.
=> Không dataset nào có host + network kèm ground truth để thay OpTC. SAGA phù hợp nhất để làm thí nghiệm phụ multi-label tactic (sau khi dedup T1005); skrghosh có thể dùng lại tokenizer eCAR (chưa kiểm) nhưng phải tự dựng nhãn như STEP 12B.
=> Cần thầy/Nguyễn thẩm định ánh xạ technique -> tactic (do mình tự ánh xạ, chưa thẩm định)."""


def main():
    if not os.path.exists(BAK):
        shutil.copy2(SRC, BAK)
    zin = zipfile.ZipFile(SRC)
    sheet = zin.read("xl/worksheets/sheet1.xml").decode("utf-8")
    old = '<c r="I17" s="35"/>'
    assert sheet.count(old) == 1, "không tìm thấy ô I17 rỗng đúng như dự kiến"
    # xác nhận hàng 17 là dòng 'Tìm thêm dataset' (shared string 43)
    row17 = re.search(r'<row [^>]*r="17"[^>]*>(.*?)</row>', sheet, re.S).group(1)
    assert '<c r="F17" s="35" t="s"><v>43</v></c>' in row17
    ss = zin.read("xl/sharedStrings.xml").decode("utf-8")
    items = re.findall(r"<si>(.*?)</si>", ss, re.S)
    assert "Tìm thêm dataset có multi-label cho DL" in "".join(re.findall(r"<t[^>]*>(.*?)</t>", items[43], re.S))
    new = f'<c r="I17" s="35" t="inlineStr"><is><t xml:space="preserve">{escape(NOTE)}</t></is></c>'
    sheet2 = sheet.replace(old, new)
    with zipfile.ZipFile(TMP, "w") as zout:
        for info in zin.infolist():
            data = zin.read(info.filename)
            if info.filename == "xl/worksheets/sheet1.xml":
                data = sheet2.encode("utf-8")
            zi = zipfile.ZipInfo(info.filename, date_time=info.date_time)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = info.external_attr
            zout.writestr(zi, data)
    zin.close()
    os.replace(TMP, SRC)
    print("OK: đã ghi I17; bản sao lưu:", BAK)


if __name__ == "__main__":
    main()
