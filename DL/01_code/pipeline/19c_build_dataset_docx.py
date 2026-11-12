#!/usr/bin/env python3
"""STEP 19c - dựng 2 file Word phân tích sơ lược SAGA và Windows-APT 2025 (tiếng Việt), từ số liệu đã đếm ở 19a/19b."""
import sys

import pandas as pd
from docx import Document
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor

sys.stdout.reconfigure(encoding="utf-8")
OUT = "D:/UIT/KLTNv2/02_artifacts/19_dataset_analysis_v1"
BLUE = "DCE6F1"
GREY = "F2F2F2"

TACTICS = [
    ("Reconnaissance", "Trinh sát", "Kẻ tấn công thu thập thông tin về mục tiêu trước khi ra tay."),
    ("Resource Development", "Chuẩn bị tài nguyên", "Dựng hạ tầng, mua tên miền, chuẩn bị công cụ."),
    ("Initial Access", "Xâm nhập ban đầu", "Bước đầu tiên lọt vào hệ thống (thư lừa đảo, đăng nhập lậu)."),
    ("Execution", "Thực thi", "Chạy mã độc hoặc lệnh (PowerShell, cmd)."),
    ("Persistence", "Duy trì hiện diện", "Cài cắm để vẫn còn sau khi khởi động lại (Run key, tác vụ định kỳ)."),
    ("Privilege Escalation", "Nâng quyền", "Giành quyền cao hơn (admin, SYSTEM)."),
    ("Defense Evasion", "Né tránh phòng thủ", "Tắt hoặc qua mặt phần mềm bảo vệ, xóa dấu vết."),
    ("Credential Access", "Lấy cắp thông tin đăng nhập", "Đánh cắp mật khẩu, băm mật khẩu (ví dụ dump LSASS)."),
    ("Discovery", "Khám phá / thăm dò", "Tìm hiểu máy, mạng, tài khoản của nạn nhân."),
    ("Lateral Movement", "Di chuyển ngang", "Nhảy từ máy này sang máy khác trong mạng (RDP, WMI)."),
    ("Collection", "Thu thập dữ liệu", "Gom dữ liệu cần lấy (file, ảnh chụp màn hình)."),
    ("Command and Control (C2)", "Điều khiển từ xa", "Kênh liên lạc giữa máy bị hại và máy chủ của kẻ tấn công (beacon)."),
    ("Exfiltration", "Đánh cắp dữ liệu ra ngoài", "Gửi dữ liệu ra khỏi mạng nạn nhân."),
    ("Impact", "Gây tác động / phá hoại", "Mã hóa tống tiền, xóa dữ liệu, chiếm tài nguyên."),
]
TERMS = [
    ("MITRE ATT&CK", "Bộ danh mục chuẩn quốc tế về chiến thuật và kỹ thuật của kẻ tấn công. Dùng làm 'từ điển' gán nhãn."),
    ("Tactic", "Chiến thuật: mục tiêu của kẻ tấn công ở một bước (ví dụ: Thực thi, Nâng quyền). Có 14 tactic (bảng trên)."),
    ("Technique / Sub-technique", "Kỹ thuật / kỹ thuật con: cách cụ thể đạt mục tiêu đó. Mã dạng T1059 (kỹ thuật) hoặc T1059.001 (kỹ thuật con: PowerShell). Một technique có thể thuộc nhiều tactic."),
    ("Ability", "Một 'bước tấn công' cụ thể trong công cụ Caldera (ví dụ: 'chụp thông tin LSASS'). Một technique có thể có nhiều ability."),
    ("Campaign / Scenario", "Chiến dịch / kịch bản tấn công mô phỏng một nhóm APT."),
    ("APT", "Advanced Persistent Threat: tấn công có chủ đích, kéo dài, nhiều bước."),
    ("Benign / Malicious", "Lành tính (bình thường) / độc hại."),
    ("Label / Ground truth", "Nhãn / nhãn chuẩn: đáp án đúng dùng để dạy và chấm điểm mô hình."),
    ("Multi-label", "Đa nhãn: một mẫu có thể mang nhiều nhãn cùng lúc (ví dụ cửa sổ 15 phút vừa có Thực thi vừa có Thăm dò)."),
    ("Event / Log", "Sự kiện / nhật ký: một dòng ghi lại hành động trên máy hoặc mạng."),
    ("Alert", "Cảnh báo: dòng log do hệ thống giám sát (Wazuh) sinh ra khi một luật khớp."),
    ("Host / Network", "Máy (log hệ điều hành: tiến trình, file, registry) / Mạng (log kết nối, flow)."),
    ("Window", "Cửa sổ thời gian (đề tài dùng 15 phút) gom các event của một máy."),
    ("Host-disjoint split", "Chia train/val/test sao cho một máy chỉ nằm ở một tập, tránh rò rỉ."),
    ("Data leakage / Shortcut", "Rò rỉ dữ liệu / đường tắt: mô hình điểm cao nhờ mẹo (mẫu lặp) chứ không nhờ hiểu tấn công."),
    ("Beacon / C2", "Tín hiệu máy bị hại gọi đều đặn về máy chủ điều khiển; trong OpTC chiếm ~98% cửa sổ dương."),
    ("Imbalance", "Mất cân bằng: mẫu độc hại rất ít so với lành tính."),
    ("Dedup", "Loại bỏ bản sao trùng lặp."),
]


def shade(cell, color):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), color)
    tcPr.append(shd)


def new_doc(title, subtitle):
    d = Document()
    s = d.sections[0]
    s.page_width, s.page_height = Cm(21), Cm(29.7)
    s.left_margin = s.right_margin = Cm(1.9)
    s.top_margin = s.bottom_margin = Cm(1.7)
    st = d.styles["Normal"]
    st.font.name = "Calibri"
    st.element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
    st.font.size = Pt(11)
    st.paragraph_format.space_after = Pt(4)
    for name, size in (("Heading 1", 13.5), ("Heading 2", 11.5)):
        h = d.styles[name]
        h.font.name = "Calibri"
        h.element.rPr.rFonts.set(qn("w:eastAsia"), "Calibri")
        h.font.size = Pt(size)
        h.font.bold = True
        h.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
        h.paragraph_format.space_before = Pt(9)
        h.paragraph_format.space_after = Pt(3)
    p = d.add_paragraph()
    r = p.add_run(title)
    r.bold = True
    r.font.size = Pt(18)
    r.font.color.rgb = RGBColor(0x1F, 0x3A, 0x5F)
    p.paragraph_format.space_after = Pt(0)
    p = d.add_paragraph()
    r = p.add_run(subtitle)
    r.italic = True
    r.font.size = Pt(10)
    r.font.color.rgb = RGBColor(0x59, 0x59, 0x59)
    return d


def para(d, text, bold_prefix=None, size=None, italic=False):
    p = d.add_paragraph()
    if bold_prefix:
        r = p.add_run(bold_prefix)
        r.bold = True
        if size:
            r.font.size = Pt(size)
    r = p.add_run(text)
    r.italic = italic
    if size:
        r.font.size = Pt(size)
    return p


def bullets(d, items, size=None):
    for it in items:
        p = d.add_paragraph(style="List Bullet")
        p.paragraph_format.space_after = Pt(1.5)
        if isinstance(it, tuple):
            r = p.add_run(it[0])
            r.bold = True
            r2 = p.add_run(it[1])
            if size:
                r.font.size = r2.font.size = Pt(size)
        else:
            r = p.add_run(it)
            if size:
                r.font.size = Pt(size)


def table(d, rows, widths_cm, header=True, size=10, first_col_bold=False):
    t = d.add_table(rows=len(rows), cols=len(rows[0]))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    for i, row in enumerate(rows):
        for j, val in enumerate(row):
            c = t.cell(i, j)
            c.width = Cm(widths_cm[j])
            c.text = ""
            p = c.paragraphs[0]
            p.paragraph_format.space_after = Pt(0)
            r = p.add_run(str(val))
            r.font.size = Pt(size)
            if header and i == 0:
                r.bold = True
                shade(c, BLUE)
            elif first_col_bold and j == 0:
                r.bold = True
                shade(c, GREY)
    d.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def glossary(d, extra_note):
    d.add_heading("5. Bảng từ khóa Anh → Việt", level=1)
    para(d, "Mười bốn chiến thuật (tactic) của MITRE ATT&CK, xếp theo thứ tự một cuộc tấn công thường diễn ra:", size=11)
    table(d, [("Tactic (tiếng Anh)", "Tiếng Việt", "Nghĩa dễ hiểu")] + TACTICS, [4.0, 4.0, 9.2], size=9.5, first_col_bold=True)
    para(d, "Các thuật ngữ khác dùng trong tài liệu:", size=11)
    table(d, [("Thuật ngữ", "Giải thích")] + TERMS, [4.0, 13.2], size=9.5, first_col_bold=True)
    if extra_note:
        para(d, extra_note, size=9, italic=True)


# ----------------------------------------------------------------------------------------------- SAGA
def build_saga():
    cov = pd.read_csv(f"{OUT}/saga_tactic_coverage.csv")
    d = new_doc("Phân tích sơ lược dataset SAGA", "Khóa luận APT detection trên DARPA OpTC, nhánh Network DL · Võ Ngọc Hoàng Lâm · 10/2026 · Số liệu đếm trực tiếp từ file đã tải, chưa huấn luyện mô hình nào")
    d.add_heading("1. SAGA là gì?", level=1)
    para(d, "SAGA là bộ log tấn công APT (tấn công có chủ đích, nhiều bước) trên máy Windows, thu bằng Procmon, kèm nhãn cho từng sự kiện: sự kiện nào bình thường, sự kiện nào thuộc kỹ thuật tấn công nào. "
            "Bài báo: Huang et al., IEEE TDSC 2025 (arXiv 2411.13138). Thầy gợi ý SAGA vì nó có nhãn chi tiết, phù hợp ý tưởng gán nhãn đa nhãn (multi-label) theo chiến thuật ATT&CK.")
    table(d, [("Mục", "Giá trị đã đếm"),
              ("Ba bộ", "Known (8 file C1–C8, chiến dịch APT đã biết) · Generated (20 file G1–G20, sinh tự động) · Composite (10 file M1–M10, ghép từ hai bộ trên)"),
              ("Quy mô", "27,805,563 event; 14.8 GB sau giải nén (676 MB nén); mỗi file là một lát log ≤ 15 phút (ngày 14/6/2022)"),
              ("Event độc hại", "77,090 event = 0.277%; 58 technique, 98 nhãn technique+ability"),
              ("Có hostname không?", "Không. Có tiến trình, file, registry, kết nối; không có tên máy"),
              ("Có network không?", "Chỉ là sự kiện 'kết nối' trong log hệ thống (0.05–0.4% số event trong các file mẫu đã đếm), không có flow kiểu Bro/Zeek")],
          [3.6, 13.6], first_col_bold=True)

    d.add_heading("2. Một sự kiện trông như thế nào?", level=1)
    para(d, "Mỗi dòng là một câu 'AI làm GÌ với CÁI GÌ': srcNode (tiến trình) – relation (hành động) – dstNode (file, registry, kết nối mạng hoặc tiến trình con) – timestamp – label. Sáu mẫu thật (rút gọn):")
    table(d, [("File", "Nhãn (label)", "Tiến trình", "Hành động", "Đối tượng"),
              ("C1", "benign", "SearchFilterHost.exe", "RegQueryValue", "Registry HKCR\\CLSID\\{083863F1-…}\\FilterData"),
              ("C3", "T1005_720a3356… (Collection)", "powershell.exe", "QueryDirectory", "File C:\\Users\\lmelendez"),
              ("C5", "T1046_5a4cb2be… (Discovery)", "powershell.exe", "TCP Connect", "Network DESKTOP-BA1RQFC → CCS:domain"),
              ("G4", "T1003.001_0ef4cc7b… (Credential Access)", "powershell.exe", "CreateFile", "File C:\\Users\\Public\\Procdump.zip"),
              ("C1", "T1566.001_1afaec09… (Initial Access)", "chrome.exe", "TCP Connect", "Network → 8.8.8.8, cổng 28877"),
              ("C4", "T1105_0856c235… (C2)", "powershell.exe", "CreateFile", "File '2021.12.01(1)' (tải công cụ về)")],
          [1.1, 4.9, 3.2, 2.6, 5.4], size=9.5)
    para(d, "File mẫu đầy đủ (2–3 dòng cho mỗi nhãn, 98 nhãn + 6 dòng benign = 276 dòng): saga_samples_per_label.csv. Bảng technique → tactic: saga_technique_tactic_map.csv.", size=9, italic=True)

    d.add_heading("3. Nhãn của SAGA như thế nào?", level=1)
    bullets(d, [
        ("Mỗi event có đúng 1 nhãn dạng chuỗi: ", "'benign' hoặc 'Txxxx_<mã ability>', ví dụ T1005_720a3356-… nghĩa là kỹ thuật T1005 (Thu thập dữ liệu từ máy), bước tấn công cụ thể có mã 720a3356…"),
        ("Không có nhãn chiến thuật (tactic) sẵn. ", "Muốn có nhãn tactic phải tự ánh xạ technique → tactic theo ATT&CK. Tôi đã ánh xạ 58 technique (bảng CSV đi kèm); đây là ánh xạ của tôi, chưa được thầy hay Nguyễn thẩm định. Một technique có thể thuộc nhiều tactic."),
        ("Đa nhãn nằm ở mức cửa sổ/file. ", "Mỗi file 15 phút chứa 3–18 technique khác nhau, nên gom lại có thể cho nhãn nhiều chiều (multi-hot theo tactic) cho từng cửa sổ, tương tự STEP 12B của đề tài."),
    ], size=11)
    para(d, "Độ phủ chiến thuật sau ánh xạ (12/14 tactic; không có Trinh sát và Chuẩn bị tài nguyên). Một event được đếm vào mọi tactic của technique đó:", size=11)
    tv = {"Discovery": "Khám phá", "Command and Control": "Điều khiển từ xa (C2)", "Execution": "Thực thi", "Initial Access": "Xâm nhập ban đầu", "Impact": "Gây tác động",
          "Credential Access": "Lấy cắp thông tin đăng nhập", "Defense Evasion": "Né tránh phòng thủ", "Privilege Escalation": "Nâng quyền", "Persistence": "Duy trì hiện diện",
          "Exfiltration": "Đánh cắp dữ liệu", "Collection": "Thu thập dữ liệu", "Lateral Movement": "Di chuyển ngang"}
    rows = [("Tactic", "Tiếng Việt", "Số technique", "Event (tính cả T1005)", "Event (bỏ T1005)")]
    for _, r in cov.iterrows():
        rows.append((r["tactic"], tv.get(r["tactic"], ""), int(r["techniques"]), f"{int(r['events']):,}", f"{int(r['events_without_T1005']):,}"))
    table(d, rows, [3.6, 4.6, 2.6, 3.4, 3.0], size=9.5)
    para(d, "Bẫy cần nhớ: 70,440 trong 77,090 event độc hại (91.4%) là cùng một ability T1005, lặp y hệt 14,088 event ở 5 file (C3, C7, M2, M5, M8). Chạy mô hình mà không dedup thì tactic 'Thu thập dữ liệu' chiếm gần hết và điểm số sẽ cao một cách giả tạo, giống hiện tượng beacon lặp ở OpTC. Bỏ T1005 còn 6,650 event độc hại, 57 technique.", size=11)

    d.add_heading("4. So với đề tài của bạn: bất cập gì?", level=1)
    table(d, [("Tiêu chí", "Đề tài (OpTC)", "SAGA", "Hệ quả"),
              ("Nguồn", "Host (eCAR) + Network (Bro), cùng một máy, cùng cửa sổ 15 phút", "Chỉ host (Procmon); không có flow mạng", "Không làm fusion host+network được"),
              ("Khóa ghép", "hostname + cửa sổ 15 phút", "Không có hostname", "Không chia host-disjoint được; chỉ chia theo file/chiến dịch"),
              ("Định dạng host", "eCAR (process, file, flow, registry…)", "Đồ thị src→dst kiểu Procmon", "Phải viết lại tokenizer, không dùng lại nhánh Host hiện có"),
              ("Nhãn", "Nhị phân theo event/flow; multi-label do ta tự dựng (788 cửa sổ, chưa thẩm định)", "Nhãn technique cho từng event do tác giả cung cấp", "Ưu điểm lớn: có nhãn thật để huấn luyện/chấm multi-label"),
              ("Tỉ lệ độc hại", "~0.027% flow (24,721 / 92M)", "0.277% event", "Mất cân bằng nặng ở cả hai"),
              ("Mẫu lặp", "Beacon C2 = 98% cửa sổ dương", "T1005 = 91.4% event độc hại, 5 file chép y hệt", "Phải dedup, và chia theo chiến dịch; Composite là bản ghép từ Known/Generated nên không chia ngẫu nhiên"),
              ("Môi trường", "Mạng doanh nghiệp mô phỏng nhiều trăm máy, 2019", "Lab/mô phỏng, một ngày 14/6/2022; Generated là dữ liệu sinh tự động", "Khả năng tổng quát sang OpTC chưa biết")],
          [2.4, 4.6, 4.6, 5.6], size=9.5, first_col_bold=True)
    para(d, "Kết luận ngắn: ", bold_prefix=None)
    bullets(d, [
        "SAGA không thay được OpTC cho bài toán fusion, vì thiếu network và thiếu hostname.",
        "Dùng được như thí nghiệm phụ về multi-label tactic ở nhánh host: có nhãn thật cho từng event ở quy mô lớn.",
        "Trước khi báo bất kỳ số nào phải: dedup T1005, chia theo chiến dịch, thẩm định bảng technique → tactic.",
    ], size=11)
    glossary(d, None)
    d.save(f"{OUT}/PHAN_TICH_SAGA.docx")


# ----------------------------------------------------------------------------------------------- Windows-APT
def build_win():
    d = new_doc("Phân tích sơ lược dataset Windows-APT 2025", "Khóa luận APT detection trên DARPA OpTC, nhánh Network DL · Võ Ngọc Hoàng Lâm · 10/2026 · Số liệu đếm trực tiếp từ file đã tải, chưa huấn luyện mô hình nào")
    d.add_heading("1. Windows-APT 2025 là gì?", level=1)
    para(d, "Bộ log do nhóm Mozaffari, Yazdinejad, Dehghantanha tạo (Mendeley Data V3, giấy phép CC BY 4.0). Họ chạy 36 kịch bản mô phỏng nhóm APT (theo manifest, cả 36 nhóm đều có nguồn gốc Trung Quốc, như APT1, APT41, Volt Typhoon…) bằng công cụ Caldera trên máy Windows 10, "
            "thu log bằng Sysmon và Wazuh. Mỗi kịch bản chạy khoảng 10 lần (tổng 360 lần, tỉ lệ kỹ thuật thành công trung bình ~84% theo file validation_summary.csv).")
    table(d, [("Mục", "Giá trị đã đếm"),
              ("File", "16 file CSV theo giai đoạn + combined.csv (gộp) + scenario_manifest.csv (36 kịch bản) + validation_summary.csv"),
              ("Quy mô", "102,011 dòng, 377 cột; 28/10/2024 → 22/12/2024 (40 ngày có dữ liệu); 459 MB giải nén"),
              ("Số máy (agent)", "Chỉ 5: window-agent3 (56,177 dòng), wazuh-agent (23,772), agent1 (17,665), DESKTOP-DS4FBF4 (3,435), Maryam (962)"),
              ("Bản chất mỗi dòng", "Một cảnh báo Wazuh (chỉ mục wazuh-alerts-4.x-*), KHÔNG phải log thô đầy đủ"),
              ("Cột nhãn?", "Không có cột 'độc hại/lành tính' và không có cột mã kịch bản")],
          [3.6, 13.6], first_col_bold=True)

    d.add_heading("2. Một dòng dữ liệu trông như thế nào?", level=1)
    para(d, "Mỗi dòng gồm: máy sinh log, thời gian, mô tả luật Wazuh đã khớp, mức nghiêm trọng (rule.level 0–15), nhãn tactic/technique của luật, và nội dung Sysmon (tiến trình, dòng lệnh, IP đích…). Tám mẫu thật (rút gọn):")
    table(d, [("Máy · thời gian", "Luật Wazuh đã khớp (rule.description)", "Mức", "Tactic · technique do luật gán", "Chi tiết"),
              ("window-agent3 · 29/11", "Windows command prompt started by an abnormal process", "4", "Execution · T1059.003", "cmd.exe /C copy calc.exe %temp%"),
              ("window-agent3 · 1/12", "User account changed", "8", "Persistence · T1098", "Sự kiện Windows 4738"),
              ("DESKTOP-DS4FBF4 · 6/11", "Lsass process was accessed by …", "12", "Credential Access · T1003.001", "Sysmon EID 10"),
              ("window-agent3 · 10/12", "Discovery activity executed", "3", "Discovery · T1087", "net1 sessions"),
              ("wazuh-agent · 8/11", "curl.exe process created a dll binary", "6", "Command and Control · T1105", "curl.exe"),
              ("Maryam · 5/11", "Integrity checksum changed", "7", "Impact · T1565.001", "Giám sát toàn vẹn file"),
              ("wazuh-agent · 5/12", "Windows workstation logon success", "3", "4 tactic: Defense Evasion, Persistence, Privilege Escalation, Initial Access · T1078", "Đăng nhập bình thường"),
              ("window-agent3 · 13/12", "Summary event of the report's signatures", "4", "(không có tactic)", "Sự kiện tổng hợp báo cáo")],
          [3.3, 5.0, 0.9, 4.4, 3.6], size=9)
    para(d, "File mẫu đầy đủ (3 dòng cho mỗi tactic, thêm nhóm 'nhiều tactic' và 'không nhãn', 36 dòng): windows_apt_samples_per_tactic.csv.", size=9, italic=True)

    d.add_heading("3. Nhãn của dataset như thế nào?", level=1)
    bullets(d, [
        ("Không có nhãn tấn công thật. ", "Cột duy nhất liên quan là rule.mitre.tactic / id / technique, do LUẬT của Wazuh gán khi nó khớp một dòng log. Có giá trị ở 63,619/102,011 dòng (62.4%); 37.6% còn lại không có nhãn."),
        ("Nhãn là 'đầu ra của một bộ phát hiện', không phải đáp án. ", "Một lần đăng nhập Windows bình thường (mức 3) vẫn mang 4 tactic. Luật 'Executable file dropped in folder commonly used by malware' một mình chiếm 14,714 dòng."),
        ("Đa nhãn có sẵn nhưng do luật quyết định: ", "41,682 dòng có 1 tactic, 13,810 dòng có 2, 3,384 dòng có 3, 4,673 dòng có 4, 70 dòng có 5."),
        ("scenario_manifest.csv ", "liệt kê tactic/technique 'mong đợi' của 36 kịch bản nhưng không có thời gian chạy, nên không nối kịch bản với dòng log được."),
    ], size=11)
    cnt = [("Execution", "Thực thi", 20342), ("Defense Evasion", "Né tránh phòng thủ", 18776), ("Command and Control", "Điều khiển từ xa", 18365), ("Privilege Escalation", "Nâng quyền", 11948),
           ("Persistence", "Duy trì hiện diện", 9165), ("Discovery", "Khám phá", 7944), ("Lateral Movement", "Di chuyển ngang", 4884), ("Initial Access", "Xâm nhập ban đầu", 3626),
           ("Impact", "Gây tác động", 3397), ("Credential Access", "Lấy cắp thông tin đăng nhập", 49), ("Collection", "Thu thập dữ liệu", 0), ("Exfiltration", "Đánh cắp dữ liệu", 0)]
    manifest_cov = {"Collection": 20, "Exfiltration": 16, "Credential Access": 21}
    rows = [("Tactic", "Tiếng Việt", "Số dòng Wazuh gán nhãn", "Số kịch bản manifest nói có mô phỏng")]
    for a, b, c in cnt:
        rows.append((a, b, f"{c:,}", str(manifest_cov.get(a, "")) if a in manifest_cov else ""))
    table(d, rows, [4.0, 5.0, 4.2, 4.0], size=9.5)
    para(d, "Điểm lạ: manifest nói 20 kịch bản có Thu thập dữ liệu (Collection) và 16 có Đánh cắp dữ liệu (Exfiltration), nhưng log không có dòng nào gán hai tactic này; Credential Access chỉ có 49 dòng dù 21 kịch bản nhắc tới. Nghĩa là nhãn của luật Wazuh bỏ sót khá nhiều bước tấn công đã mô phỏng.", size=11)

    d.add_heading("4. So với đề tài của bạn: bất cập gì?", level=1)
    table(d, [("Tiêu chí", "Đề tài (OpTC)", "Windows-APT 2025", "Hệ quả"),
              ("Số máy", "620 máy có cả host và network; chia host-disjoint 434/93/93", "Chỉ 5 agent", "Host-disjoint chỉ còn khoảng 3/1/1 máy: không đủ để kết luận gì"),
              ("Bản chất dữ liệu", "Log thô nhiều tỷ dòng, phần lớn benign", "Toàn bộ là cảnh báo Wazuh", "Không có nền benign đầy đủ: không đo được báo nhầm (FP) hay precision thật"),
              ("Nhãn", "Nhãn ground truth từ red team (A New Hope)", "Nhãn do luật Wazuh, không phải đáp án", "Huấn luyện trên nhãn này = dạy mô hình học lại luật Wazuh (vòng tròn)"),
              ("Network", "Bro/Zeek conn join eCAR", "Chỉ 467 dòng có IP đích (0.46%)", "Không có nhánh network để fusion"),
              ("Phủ tactic", "Multi-label 5 nhóm tactic (đề xuất)", "10/14 tactic có dòng; Credential Access 49; Collection và Exfiltration = 0", "Mất cân bằng, hai tactic không có mẫu"),
              ("Nối kịch bản – log", "Có nhật ký red team theo giờ", "Manifest không có thời gian", "Không dựng được nhãn thật bằng giờ như STEP 12B"),
              ("Quy mô", "92M flow đã ghép", "102k dòng", "Quá nhỏ cho mô hình sâu (DL)")],
          [2.4, 4.4, 4.4, 6.0], size=9.5, first_col_bold=True)
    para(d, "Kết luận ngắn:", bold_prefix=None)
    bullets(d, [
        "Không dùng làm benchmark multi-label có ground truth: nhãn là đầu ra của luật, chỉ 5 máy, toàn cảnh báo.",
        "Chỉ nên dùng để (1) minh họa cách ánh xạ log → ATT&CK, (2) thử nhanh pipeline host trên dữ liệu nhỏ, hoặc (3) trích tập luật/nhãn yếu để so sánh.",
        "Muốn dùng nghiêm túc cần tác giả cung cấp thời gian chạy từng kịch bản (hoặc cột kịch bản) để dựng nhãn thật.",
    ], size=11)
    glossary(d, "Ghi chú: Wazuh là nền tảng giám sát bảo mật mã nguồn mở; Sysmon là công cụ ghi log chi tiết tiến trình, kết nối, file trên Windows; Caldera là công cụ mô phỏng tấn công tự động của MITRE.")
    d.save(f"{OUT}/PHAN_TICH_WINDOWS_APT_2025.docx")


if __name__ == "__main__":
    build_saga()
    build_win()
    print("OK")
