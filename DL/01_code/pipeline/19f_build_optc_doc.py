#!/usr/bin/env python3
"""STEP 19f - Word: phân tích lại kết luận OpTC (SC3 ít positive, học thuộc beacon, bất cập khi nối field host vào network).
Mọi số liệu lấy từ artifact đã có (STEP 11, 10G, 10H, 14/S1, 12C, 15); không đo mới. Phần chưa kiểm chứng được nêu rõ.
"""
import importlib.util
import sys

sys.stdout.reconfigure(encoding="utf-8")
spec = importlib.util.spec_from_file_location("b19c", "D:/UIT/KLTNv2/01_code/pipeline/19c_build_dataset_docx.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
OUT = b.OUT

TERMS = [
    ("Beacon", "Mã độc trên máy nạn nhân gọi về máy chủ của kẻ tấn công đều đặn (ví dụ mỗi 30 giây) để hỏi 'có lệnh mới không?'."),
    ("C2 (Command and Control)", "Máy chủ điều khiển của kẻ tấn công; ở OpTC là các IP 132.197.158.98, 202.6.172.98, 53.192.68.50."),
    ("Template (mẫu)", "Một kiểu beacon cố định: cùng IP đích, cùng nhịp, cùng số byte; lặp lại giống hệt trên nhiều máy."),
    ("pid / ppid", "Số hiệu tiến trình / số hiệu tiến trình cha. Chỉ là con số; muốn biết 'cha là ai' phải tra ngược trong log host."),
    ("actorID", "Mã (UUID) của tiến trình thực hiện hành động trong eCAR; khóa để lần ra event PROCESS CREATE của chính tiến trình đó."),
    ("eCAR-Bro", "Bản eCAR chỉ chứa event FLOW kèm bro_uid: cầu nối duy nhất từ flow mạng sang tiến trình đã tạo ra nó."),
    ("REJ", "Trạng thái Bro: kết nối bị từ chối ngay (SYN bị trả lời bằng RST), không trao đổi dữ liệu."),
    ("Left join", "Giữ cả những flow không có bản ghi eCAR-Bro (đặt app_family = <MISSING>), thay vì chỉ giữ flow ghép được."),
    ("EDT / UTC", "Giờ miền Đông Mỹ (UTC−4, múi giờ của eCAR) / giờ chuẩn (epoch của Bro)."),
]


def build():
    d = b.new_doc("OpTC: SC3 quá ít positive, mô hình học thuộc beacon, và bất cập khi nối field host vào network",
                  "Khóa luận APT trên DARPA OpTC · nhánh Network DL · 10/2026 · Số liệu lấy từ các artifact STEP 10G/10H/11/12C/14/15/17 đã có, chưa đo thêm")

    d.add_heading("Tóm tắt", level=1)
    b.bullets(d, [
        ("SC3 gần như không có positive ở mạng: ", "chỉ 2 máy, 189 flow dương và 6 cửa sổ dương, trong khi tổng là 24,721 flow dương và 541 cửa sổ dương. Flow SC3 là các kết nối bị từ chối, trông giống nhiễu."),
        ("Positive của OpTC gần như toàn là beacon: ", "530 / 541 cửa sổ dương (98%) là hai mẫu beacon lặp giống hệt trên nhiều máy. Khi mẫu beacon chưa từng thấy, recall rơi từ khoảng 0.95 xuống khoảng 0.03."),
        ("Nối field host (ppid…) vào flow là bất cập: ", "flow không có bản ghi eCAR-Bro thì không có pid/ppid; flow có thì vẫn phải tra ngược log host và pid hay bị gán sai. Tỉ lệ tra được thật sự chưa đo (ổ E: chưa gắn)."),
    ], size=10.5)

    d.add_heading("1. SC3 cực kỳ ít positive", level=1)
    b.table(d, [("", "SC1 (23/9)", "SC2 (24–25/9)", "SC3 (25/9)"),
                ("Số máy bị tấn công", "17", "10", "2"),
                ("Flow positive (mạng)", "9,030", "15,502", "189"),
                ("Cửa sổ 15 phút dương", "61", "474", "6"),
                ("Event nhãn host (eCAR)", "124,217", "205,617", "30,733"),
                ("Dạng flow positive", "Beacon đều, cùng mẫu", "Beacon đều, cùng mẫu", "Kết nối bị từ chối (REJ) và vài HTTP")],
            [4.4, 4.0, 4.4, 4.4], size=9.5, first_col_bold=True)
    b.bullets(d, [
        ("Tỉ lệ: ", "SC3 chỉ là 189 / 24,721 = 0.76% flow dương và 6 / 541 = 1.1% cửa sổ dương. Cả bộ chỉ có 0.027% flow là dương (24,721 / 92,045,755)."),
        ("Hai máy: ", "sysclient0051 có 163 flow dương (159 flow REJ tới 53.192.68.50:8080, 3 flow HTTP cổng 80, 1 phiên RDP); sysclient0351 có 26 flow. Ở split dùng để train, TEST chỉ chứa sysclient0051 (4 cửa sổ dương)."),
        ("Giống nhiễu: ", "ngày 25/9 có 499 máy có flow nhãn benign tới cùng IP 53.192.68.50 (5,563 flow, khả năng là kiểm tra cập nhật notepad++), còn chỉ 2 máy có flow nhãn độc hại (188 flow). Điểm phân biệt thật nằm ở host (gup.exe sinh ra file .exe trong Temp)."),
        ("Còn bị mất thêm: ", "sysclient0051 có 488 flow độc hại trong Bro nhưng bảng đã ghép chỉ giữ 163 (mất 325 flow, 66.6%, phần lớn REJ cổng 8080). Nhãn host thì rất dày: sysclient0351 có 19,378 event nhãn host nhưng chỉ 26 flow dương."),
    ], size=10.5)
    b.para(d, "Mẫu thật (flows_sample.csv), sysclient0051, ngày 25/9, giờ UTC:", size=10.5)
    b.table(d, [("Giờ UTC", "Tiến trình", "Đích", "Trạng thái", "Byte gửi/nhận", "Thời lượng"),
                ("14:51:16", "biguwcmnsucig.exe", "53.192.68.50:8080", "REJ", "0 / 0", "0.002 s"),
                ("14:52:22", "biguwcmnsucig.exe", "53.192.68.50:8080", "REJ", "0 / 0", "0.002 s"),
                ("14:54:32", "biguwcmnsucig.exe", "53.192.68.50:8080", "REJ", "0 / 0", "0.001 s"),
                ("14:55:37", "biguwcmnsucig.exe", "53.192.68.50:8080", "REJ", "0 / 0", "0.001 s")],
            [2.4, 3.8, 4.2, 2.2, 2.6, 2.0], size=9.5)

    d.add_heading("2. Beacon là gì, trong OpTC trông ra sao?", level=1)
    b.para(d, "Beacon là việc mã độc đã nằm trên máy nạn nhân gọi về máy chủ điều khiển (C2) của kẻ tấn công đều đặn để hỏi có lệnh mới không, giống như một người cứ vài giây lại nhắn hỏi 'có việc gì không?'. "
              "Trong OpTC chỉ có hai kiểu beacon (hai 'mẫu'), được lặp giống hệt trên nhiều máy:", size=10.5)
    b.table(d, [("", "Mẫu A (SC1, và 2 máy SC2)", "Mẫu B (SC2, qua đêm)"),
                ("Gọi tới đâu", "132.197.158.98, cổng 80 (HTTP)", "202.6.172.98, cổng 443 (SSL)"),
                ("Cứ bao lâu một lần", "~5.1 giây (trung vị 5.13 s, biến thiên rất nhỏ)", "~30.1 giây (trung vị 30.14 s)"),
                ("Một cửa sổ 15 phút", "~169 flow", "~30 flow"),
                ("Dữ liệu mỗi lần", "gửi 199 byte, nhận 1,443 byte", "gửi 667 byte, nhận 2,277 byte"),
                ("Tiến trình", "powershell.exe", "powershell.exe"),
                ("Kéo dài bao lâu", "SC1: máy 0201 từ 11:24 đến 14:05 EDT (~2.7 giờ); 14 máy trạm 14:45–15:23, mỗi máy 3 cửa sổ (~449 flow)", "24/9 15:42 đến 25/9 ~09:15 EDT (~17.6 giờ), mỗi máy ~2,100 flow trong 72 cửa sổ"),
                ("Số máy / cửa sổ dương", "19 máy, 74 cửa sổ", "7 máy, 456 cửa sổ (cộng một số cửa sổ lẻ)")],
            [3.6, 6.8, 6.8], size=9.5, first_col_bold=True)
    b.para(d, "Một flow beacon mẫu B thật: sysclient0618, 2019-09-24 20:00:15 UTC (16:00 EDT), powershell.exe → 202.6.172.98:443, dịch vụ ssl, thời lượng 0.063 s, gửi 667 / nhận 2,277 byte, trạng thái SF, 6 gói gửi / 8 gói nhận. "
              "Theo hồ sơ mẫu B, các flow kế tiếp cùng máy lặp lại cách nhau khoảng 30 giây với số byte gần như y hệt (chưa đối chiếu từng flow của máy này).", size=10.5)
    b.para(d, "Tổng cộng 530 / 541 cửa sổ dương (98%) là beacon; chỉ 11 cửa sổ không phải (5 của SC2, 6 của SC3). Với benign, 99.8% flow là firefox.exe, nên powershell.exe gần như chắc chắn là positive.", size=10.5)

    d.add_heading("3. Vì sao nói mô hình 'học thuộc' beacon", level=1)
    b.para(d, "Mỗi mẫu đầu vào là chuỗi các flow của một máy trong 15 phút, gồm tên tiến trình, giao thức, dịch vụ, trạng thái, nhóm cổng, thời lượng, byte, gói và khoảng cách thời gian giữa hai flow (delta_t). "
              "Với beacon, cả chuỗi chỉ là cùng một dòng lặp lại (delta_t ≈ 30 giây ra đúng một giá trị, byte y hệt), nên rất dễ nhận ra khi mẫu đó có mặt ở cả TRAIN và TEST.", size=10.5)
    b.table(d, [("Bằng chứng", "Kết quả"),
                ("Luật 1 dòng: 'cửa sổ có powershell.exe thì là tấn công'", "F1 TEST 0.975–0.976, ngang mô hình sâu (0.969–0.988)"),
                ("Bỏ app_family, chỉ còn nhịp, byte, dịch vụ, cổng", "Vẫn F1 0.957–0.959, vì beacon lặp tự bộc lộ qua nhịp và byte"),
                ("Bỏ cả scenario SC2 (mẫu B) khỏi TRAIN, test trên SC2", "Recall 0.027 (BiLSTM) và 0.025 (Mixed-Type); ROC-AUC của BiLSTM 0.242, thấp hơn ngẫu nhiên"),
                ("Bỏ cả scenario SC1 (mẫu A) khỏi TRAIN, test trên SC1", "Recall 0.654 (BiLSTM, 51 / 78 cửa sổ) và 0.000 (Mixed-Type)"),
                ("Tham chiếu: split ngẫu nhiên theo máy, bỏ app_family", "Recall khoảng 0.95–0.96 (SC2) và 18 / 18 cửa sổ SC1")],
            [8.2, 9.0], size=9.5, first_col_bold=True)
    b.para(d, "Đọc kết quả: giả thuyết 'điểm cao là do mẫu beacon có mặt ở cả TRAIN và TEST' được ủng hộ mạnh; điểm cao ở split ngẫu nhiên không chứng minh mô hình nhận ra hành vi C2 mới. "
              "Hạn chế: chỉ 1 seed; scenario gần như trùng với ngày nên 'mẫu lạ' cũng là 'ngày lạ'; hold-out SC2 chỉ có 59 cửa sổ dương ở TRAIN. Chưa kết luận BiLSTM tốt hơn Mixed-Type.", size=10.5)

    d.add_heading("4. Bất cập khi lấy field từ host (ppid…) đưa vào network để train", level=1)
    b.para(d, "Ý tưởng 'mức đặc trưng': với mỗi flow, gắn thêm ngữ cảnh của tiến trình đã tạo ra nó (cha là ai, chạy từ thư mục nào, dòng lệnh) rồi cho cùng một mô hình học. Các trở ngại:", size=10.5)
    b.table(d, [("Trở ngại", "Chi tiết và số liệu"),
                ("1. Bảng flow hiện không có field đó", "Bảng ghép (34 trường) chỉ giữ app_family lấy từ image_path của eCAR-Bro. pid, ppid, actorID, principal có trong eCAR-Bro thô nhưng không được đưa vào. command_line và parent_image_path chỉ tồn tại ở event PROCESS của log host."),
                ("2. ppid chỉ là một con số", "ppid 4268 không có nghĩa nếu không tra ra 'tiến trình cha là gì'. Dùng thẳng pid/ppid làm feature là vô nghĩa (khác nhau theo từng máy, từng lần khởi động). Phải đi vòng: flow.actorID → event PROCESS CREATE trong log host → parent_image_path/command_line."),
                ("3. Thiếu: flow không có bản ghi eCAR-Bro", "Không có bản ghi thì không có pid, ppid, actorID. sysclient0051 thiếu 325 / 488 flow độc hại (66.6%); DC1 thiếu cả 4,190 flow (không có trong eCAR-Bro của pipeline). Tổng mất 4,590 / 29,311 flow độc hại (15.7%). Left join giữ được flow nhưng vẫn không có thông tin tiến trình."),
                ("4. Thiếu: host và network không phủ cùng tập máy", "123 máy chỉ có log mạng (6.42M flow), 5 máy chỉ có log host, và 6 máy bị tấn công chỉ có nhãn mạng (không có eCAR). Các máy này sẽ có cột host bị trống."),
                ("5. Ngay cả khi có, tra ngược dễ sai", "Bài báo A New Hope: khoảng 40% tiến trình và 4.22% event có actorID/pid sai do pid bị dùng lại và log đến sai thứ tự; sau 3 lượt sửa còn 1.6% event lỗi. Tra sai thì gắn nhầm 'cha' cho flow."),
                ("6. Hai nhãn khác tầng", "Nhãn host tính theo event và cây tiến trình (hàng chục nghìn event mỗi máy); nhãn mạng tính theo flow tới C2 (vài chục đến vài nghìn). Ví dụ sysclient0351: 19,378 event host so với 26 flow."),
                ("7. Mạng không thấy phần nội bộ", "Bro chỉ có 1 flow tới IP nội bộ trong 92M flow, nên di chuyển ngang (WMI, RDP nội bộ) và nhiều bước SC3 chỉ có ở host; gắn field host vào flow không tái tạo được phần đó."),
                ("8. Lệch giờ và đơn vị", "eCAR dùng EDT, Bro dùng UTC; cửa sổ 15 phút thì trùng nhưng ngày file eCAR-Bro cắt ở khoảng 03:00 EDT. Đơn vị mô hình là cửa sổ (máy, 15 phút) với tối đa 512 flow, không phải từng flow.")],
            [4.6, 12.6], size=9, first_col_bold=True)
    b.para(d, "Điều chưa kiểm chứng: trong số flow CÓ bản ghi eCAR-Bro, bao nhiêu phần trăm tra ra được event PROCESS CREATE đúng. Việc này cần log eCAR thô trên ổ E: (hiện chưa gắn); pilot trước đây cho thấy một file ~2.5 triệu event đọc mất khoảng 20–24 giây, nên đo thử trên vài máy là nhẹ, nhưng tôi chưa chạy. "
              "Thay vào đó, STEP 17 nối hai nhánh ở mức điểm theo khóa (hostname, cửa sổ 15 phút), tránh phải ánh xạ từng flow; kết quả: fusion chỉ cải thiện 2 cửa sổ trên 1,103.", size=10.5)

    d.add_heading("5. Bảng từ khóa", level=1)
    b.table(d, [("Thuật ngữ", "Giải thích")] + TERMS, [4.2, 13.0], size=9, first_col_bold=True)
    d.save(f"{OUT}/PHAN_TICH_OPTC_SC3_BEACON_VA_FIELD_HOST.docx")


if __name__ == "__main__":
    build()
    print("OK")
