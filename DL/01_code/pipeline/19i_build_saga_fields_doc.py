#!/usr/bin/env python3
"""STEP 19i - Word + CSV: phân tích các trường (field) của SAGA ở dạng thô.
Số liệu từ 19h_saga_schema_scan.py: json.loads TẤT CẢ 77,090 event độc hại + 1/10 event benign (2,772,833 dòng) của 38 file (tổng 2,849,923 dòng).
Tỉ lệ của benign là ước lượng từ mẫu 1/10; tập khóa và kiểu dữ liệu kiểm trên toàn bộ 2,849,923 dòng đã parse.
"""
import csv
import importlib.util
import sys

sys.stdout.reconfigure(encoding="utf-8")
spec = importlib.util.spec_from_file_location("b19c", "D:/UIT/KLTNv2/01_code/pipeline/19c_build_dataset_docx.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
OUT = b.OUT

FIELDS = [
    ("timestamp", "int", "100%", "Thời điểm event, epoch giây (UTC). Nhiều event trùng cùng một giây.", "1655180399", "Độ phân giải 1 giây nên thứ tự trong cùng giây không xác định. Toàn bộ 38 file nằm trong ngày 2022-06-14."),
    ("relation", "string", "100%", "Hành động của tiến trình lên đối tượng đích.", "TCP Connect", "27 giá trị khác nhau (23 giá trị ở event độc hại); nhóm theo mục 3."),
    ("label", "string", "100%", "'benign' hoặc 'Txxxx[.yyy]_<ability>' (technique + mã bước tấn công).", "T1566.001_1afaec09315ab71fdfb167175e8a019a", "98 nhãn độc hại; không có nhãn tactic. Mã ability có hai kiểu: UUID có gạch ngang hoặc 32 ký tự hex."),
    ("srcNode.Type", "string", "100%", "Loại node nguồn; luôn là 'Process'.", "Process", "Hằng số: không mang thông tin."),
    ("srcNode.UUID", "string (UUID v5)", "100%", "Mã định danh node tiến trình, sinh theo tên (UUID version 5).", "2d97c036-3333-55df-93b6-76a766831c3b", "Cùng thực thể thì cùng UUID, kể cả giữa các file; dùng làm id nút đồ thị."),
    ("srcNode.Name", "string", "100%", "Tên tiến trình.", "chrome.exe", "Không nhất quán: lúc là tên file, lúc là đường dẫn đầy đủ (WINWORD), lúc là chuỗi hash (G19)."),
    ("srcNode.Image", "string", "100%", "Đường dẫn file thực thi.", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "Tương đương image_path của eCAR."),
    ("srcNode.Cmdline", "string", "100%", "Dòng lệnh của tiến trình, lặp lại trên MỌI event của tiến trình đó (có thể rất dài).", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "eCAR chỉ có command_line ở event PROCESS."),
    ("srcNode.Pid", "int", "100%", "Process ID.", "6306", "Không có ppid, hostname, principal."),
    ("dstNode.Type", "string", "99.998%", "Loại đối tượng đích: Registry, File, Network, Process.", "Network", "56 trong 2,849,923 dòng có dstNode rỗng {}."),
    ("dstNode.UUID", "string (UUID v5)", "99.998%", "Mã định danh đối tượng đích.", "0945eb84-2203-598e-9948-dfe991f09330", "Cũng là UUID v5."),
    ("dstNode.Key", "string", "Registry (100%)", "Khóa registry bị đọc/ghi.", "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\NextRun", "Chỉ có khi Type = Registry."),
    ("dstNode.Value", "string (2 dòng là int)", "Registry: ~21% benign, ~27% độc hại", "Giá trị registry được ghi/đọc.", "2021.12.01(1)", "Có mặt tùy event."),
    ("dstNode.Name", "string", "File (100%)", "Tên (hoặc đường dẫn) file bị tác động.", "rFupMb75.exe", "Chỉ có khi Type = File."),
    ("dstNode.Path", "string", "File: ~5% benign, 0% độc hại", "Đường dẫn bổ sung của file.", "(không có trong file mẫu 221 dòng)", "Chỉ xuất hiện ở event benign trong mẫu quét."),
    ("dstNode.Srcaddress", "string", "Network (100%)", "Địa chỉ nguồn của kết nối: tên máy hoặc IP.", "desktop-85.zuniga.com", "Có thể là tên máy, không phải IP."),
    ("dstNode.Dstaddress", "string", "Network (100%)", "Địa chỉ đích của kết nối.", "8.8.8.8", "Có dạng 'CCS:domain' (tên:dịch vụ) ở một số event; không phải lúc nào cũng là IP."),
    ("dstNode.Port", "string", "Network (100%)", "Số cổng.", "28877", "Kiểu chuỗi; chưa rõ là cổng nguồn hay cổng đích (cổng 28877 đi cùng 8.8.8.8 trong mẫu)."),
    ("dstNode.Cmdline / Image / Name / Pid", "string / int", "Process (100%)", "Tiến trình CON vừa được tạo (khi relation = Process Create).", "cscript.exe, Pid 5992, Cmdline: cscript //E:Jscript \"Retrive….vbs\"", "Đây là cách duy nhất suy ra quan hệ cha→con: cạnh srcNode → dstNode."),
]


def build():
    # CSV tra cứu
    with open(f"{OUT}/saga_fields.csv", "w", encoding="utf-8-sig", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(["field", "type", "present_in", "meaning_vi", "real_example", "note"])
        w.writerows(FIELDS)

    d = b.new_doc("Phân tích các trường (field) của SAGA ở dạng thô",
                  "Khóa luận APT trên DARPA OpTC · 10/2026 · Quét 38 file: toàn bộ 77,090 event độc hại và 1/10 event benign (tổng 2,849,923 dòng đã parse); tỉ lệ của benign là ước lượng từ mẫu")
    d.add_heading("1. Một dòng SAGA gồm những gì?", level=1)
    b.para(d, "Mỗi dòng là một event dạng đồ thị 'tiến trình → hành động → đối tượng'. Chỉ có đúng 5 khóa ở cấp trên cùng, có mặt ở 100% dòng: srcNode (tiến trình thực hiện), dstNode (đối tượng bị tác động), relation (hành động), timestamp và label. "
              "Không có hostname, ppid (tiến trình cha), principal (tài khoản), tid hay kích thước dữ liệu. Ví dụ thật (rút gọn):", size=10.5)
    b.table(d, [("srcNode", "relation", "dstNode", "timestamp", "label"),
                ("chrome.exe (Pid 6306, kèm UUID, Image, Cmdline)", "TCP Connect", "Network: desktop-85.zuniga.com → 8.8.8.8, cổng 28877", "1655180399", "T1566.001_1afaec09…")],
            [4.4, 2.4, 5.4, 2.4, 2.6], size=9)
    b.table(d, [("Trường", "Kiểu", "Có mặt", "Ý nghĩa", "Ví dụ thật", "Ghi chú")] + [(f[0], f[1], f[2], f[3], f[4], f[5]) for f in FIELDS],
            [2.7, 1.8, 2.0, 3.6, 3.4, 3.7], size=7.5, first_col_bold=True)
    b.para(d, "Bảng đầy đủ để tra cứu: saga_fields.csv.", size=9, italic=True)

    d.add_heading("2. Loại đối tượng đích (dstNode.Type) quyết định các khóa còn lại", level=1)
    b.table(d, [("dstNode.Type", "Khóa", "Benign (mẫu 1/10)", "Độc hại (toàn bộ)"),
                ("Registry", "Key (+ Value tùy event)", "61.5%", "0.7% (528 event)"),
                ("File", "Name (+ Path tùy event)", "38.3%", "95.2% (73,426 event)"),
                ("Network", "Srcaddress, Dstaddress, Port", "0.18%", "3.5% (2,674 event)"),
                ("Process", "Cmdline, Image, Name, Pid", "0.006%", "0.6% (462 event)")],
            [3.0, 5.6, 4.2, 4.4], size=9.5, first_col_bold=True)
    b.para(d, "Điểm lệch cần lưu ý: event độc hại gần như toàn là event File (95.2%), trong đó 70,653 event là relation QueryDirectory của khối T1005 lặp lại; event benign thì chủ yếu là Registry. "
              "Cũng vì vậy 'loại đối tượng đích' và 'relation' có thể trở thành đường tắt (shortcut) nếu không dedup. Event có kết nối mạng rất hiếm (0.18% benign, 3.5% độc hại).", size=10.5)

    d.add_heading("3. Trường relation: 27 giá trị", level=1)
    b.table(d, [("Nhóm", "Giá trị"),
                ("File (12)", "CloseFile, CreateFile, QueryAllInformationFile, QueryAttributeTagFile, QueryBasicInformationFile, QueryDirectory, QueryNetworkOpenInformationFile, ReadFile, SetBasicInformationFile, SetDispositionInformationEx, SetDispositionInformationFile, WriteFile"),
                ("Registry (7)", "RegCloseKey, RegCreateKey, RegDeleteValue, RegOpenKey, RegQueryKey, RegQueryValue, RegSetValue"),
                ("Network (6)", "TCP Connect, TCP Disconnect, TCP Receive, TCP Send, UDP Receive, UDP Send"),
                ("Process (2)", "Process Create, Process Start")],
            [3.0, 14.2], size=9.5, first_col_bold=True)
    b.para(d, "Phổ biến nhất ở benign (mẫu): RegQueryValue, RegOpenKey, CreateFile, RegCloseKey, CloseFile. Phổ biến nhất ở độc hại: QueryDirectory (70,653), TCP Disconnect (2,171), CreateFile (792), QueryBasicInformationFile (548), CloseFile (533), Process Create (462).", size=10.5)

    d.add_heading("4. Trường label và srcNode", level=1)
    b.bullets(d, [
        ("label: ", "'benign' hoặc technique + mã ability. Có hai kiểu mã ability: UUID có gạch ngang (ví dụ T1005_720a3356-eee1-4015-9135-0fc08f7eb2d5) và chuỗi 32 ký tự hex (ví dụ T1566.001_1afaec09…). 98 nhãn độc hại, 58 technique."),
        ("Tiến trình độc hại chủ yếu là PowerShell: ", "74,173 / 77,090 event độc hại (96.2%) do powershell.exe thực hiện; phần lớn thuộc khối T1005 lặp, chưa tách riêng. Đây là đường tắt tương tự app_family của OpTC."),
        ("srcNode.Cmdline lặp ở mọi event ", "của cùng một tiến trình (kể cả dòng lệnh dài hàng trăm ký tự, ví dụ cmd.exe /C echo var url = …), nên dung lượng file lớn (14.8 GB cho 27.8M event)."),
        ("Name không nhất quán: ", "chrome.exe, đường dẫn đầy đủ (…\\Office16\\WINWORD) hoặc chuỗi hash (file G19). Nên dùng Image làm khóa thay vì Name."),
    ], size=10.5)

    d.add_heading("5. UUID: dùng được làm id, nhưng các file không độc lập", level=1)
    b.bullets(d, [
        ("UUID version 5 (sinh theo tên): ", "100% của 5,699,790 giá trị UUID đã kiểm có ký tự phiên bản là '5'. Cùng thực thể thì cùng UUID, kể cả giữa các file, nên dùng được làm id nút đồ thị."),
        ("Cùng một nhóm tiến trình lặp ở nhiều file: ", "chỉ có 993 srcNode.UUID khác nhau trong cả 38 file (trên mẫu quét); 117 UUID xuất hiện ở ít nhất 10 file. Ví dụ file Composite M1 dùng lại 93 / 95 UUID của file Known C1; C1 và C2 chia sẻ 60 UUID, C1 và G1 chia sẻ 55."),
        ("Với dstNode: ", "358,890 UUID khác nhau, trong đó 189,402 xuất hiện ở từ 2 file trở lên."),
        ("Hệ quả: ", "chia train/test ngẫu nhiên theo event hoặc theo file sẽ làm cùng một tiến trình và cùng một khối T1005 nằm ở cả hai tập (rò rỉ dữ liệu)."),
    ], size=10.5)

    d.add_heading("6. Đối chiếu với eCAR của OpTC", level=1)
    b.table(d, [("eCAR (OpTC)", "SAGA", "Nhận xét"),
                ("hostname", "(không có)", "Không chia host-disjoint được"),
                ("actorID / pid", "srcNode.UUID / srcNode.Pid", "Có tương đương"),
                ("ppid, parent_image_path", "(không có)", "Chỉ suy ra cha→con từ cạnh Process Create (462 event độc hại)"),
                ("principal (tài khoản)", "(không có)", "Mất ngữ cảnh người dùng"),
                ("image_path, command_line", "srcNode.Image, srcNode.Cmdline", "SAGA có Cmdline ở mọi event; eCAR chỉ ở event PROCESS"),
                ("(object, action)", "dstNode.Type + relation", "27 relation, gần như tương đương"),
                ("file_path / key, value", "dstNode.Name, Path / Key, Value", "Tương đương"),
                ("src_ip, dest_ip, dest_port, direction, size", "Srcaddress, Dstaddress, Port (chuỗi)", "Không có direction, kích thước; địa chỉ có thể là tên máy"),
                ("timestamp (ISO, mili-giây, EDT)", "timestamp (int, giây)", "Độ phân giải thô hơn")],
            [4.6, 5.0, 7.6], size=9, first_col_bold=True)
    b.para(d, "Kết luận: SAGA đủ trường để dựng đồ thị tiến trình–file–registry–mạng và có nhãn technique từng event, nhưng thiếu hostname, ppid, principal nên không dùng lại được nhánh Host (eCAR) mà không viết lại bộ mã hóa, và không có phần network để fusion.", size=10.5)
    d.save(f"{OUT}/PHAN_TICH_TRUONG_SAGA.docx")


if __name__ == "__main__":
    build()
    print("OK")
