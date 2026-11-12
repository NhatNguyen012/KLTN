# STEP 18 — Bốn dataset multi-label thầy đưa: phân tích và cách lấy

Ngày: 2026-10-07. Nguồn: trang web và bài báo của từng dataset (chưa tải, chưa mở file dữ liệu). Hạng tạp chí/hội nghị là hiểu biết của tôi, **cần kiểm** trên SCImago và CORE.

## Bảng so sánh
| | Windows-APT 2025 | SAGA (v1, v2) | skrghosh/apt-dataset | Multi-Source Logs (arXiv 2606.18190) |
|---|---|---|---|---|
| Bài báo | Mozaffari, Yazdinejad, Dehghantanha. *Data in Brief* 65, 112569 (2026) | Huang et al. *IEEE TDSC* (2025), arXiv 2411.13138 | Ghosh, Gjomemo, Venkatakrishnan. *Citar*, ACM CODASPY 2024 | Niloy et al. (Univ. Alabama), arXiv preprint 16/6/2026 |
| Hạng (cần kiểm) | Data in Brief: Q2–Q3? | TDSC: Q1 | CODASPY: B? | Chưa phản biện, không có hạng |
| Nguồn log | Wazuh + Sysmon trên Windows 10 (trang Mendeley không nhắc traffic mạng; Sysmon chỉ có sự kiện kết nối) | Procmon (audit log Windows), `<subject, operation, object>`; socket nằm trong event hệ thống | Audit log theo mô hình eCAR/CAR (JSON), Windows 10 | Sysmon + Windows Event Log + **PCAP (tshark)** + log trình duyệt (ActivityWatch) |
| Host + network | Chủ yếu host | Chủ yếu host | Chỉ host | **Có cả ba nguồn** |
| Nhãn | Kỹ thuật ATT&CK theo 36 kịch bản (cần mở file để biết cột) | **Mỗi event**: 7 giai đoạn APT, 80 kỹ thuật, 169 "ability", thực thể, nhóm tấn công | **Theo kịch bản** (file PDF `Ground_Truths/*_GT.pdf`), không phải từng event | Mỗi event độc hại: kỹ thuật ATT&CK (12 tactic, 53 kỹ thuật); nhãn phiên và chunk 7 event |
| Quy mô | ~102,000 bản ghi, 19 CSV (rất nhỏ) | 15 phút ≈ 0.9M event; 1 giờ ≈ 1.2M; 1 ngày ≈ 14.3M; 38 chiến dịch (8 thật, 20 sinh, 10 ghép) | 11 chiến dịch, 0.66–6.34M bản ghi mỗi cái, >99% benign | 870 phiên × 20 phút (70 tấn công, 800 benign), ~2.3M event |
| Cách lấy | Mendeley Data, CC BY 4.0 | 3 file zip trên Google Drive | GitHub, CC BY 4.0 | **Chưa thấy link công khai** |

## Cách lấy từng dataset
1. **Windows-APT 2025:** https://data.mendeley.com/datasets/b8fmtzvpy8/3 (DOI 10.17632/b8fmtzvpy8.3), bấm "Download All". Giấy phép CC BY 4.0. Có bản liên quan: https://data.mendeley.com/datasets/7w97twtz4p ("Comprehensive Analysis of Chinese APTs"). Bài báo: DOI 10.1016/j.dib.2026.112569.
2. **SAGA:** https://saga-tw.github.io/dataset/ → v2.0 (https://saga-tw.github.io/dataset/v2) có 3 zip Google Drive: Known APT Campaigns, Generated APT Campaigns, Composite APT Campaigns (link trong trang). v1.0 ở https://saga-tw.github.io/dataset/v1. Trang không ghi dung lượng, định dạng hay giấy phép; liên hệ saga.ants.tw@gmail.com. Site dự án: https://www.saga-cyber.net/.
3. **skrghosh/apt-dataset:** `git clone https://github.com/skrghosh/apt-dataset` hoặc tải ZIP. Gồm `apt29.json.zip`, `fin6.json.zip`, `oilrig.json.zip`, `output_menuPass.json.zip`, `wizard_spider.json.zip` và thư mục `Ground_Truths` (5 PDF). Giấy phép CC BY 4.0. README có link Google Drive cho OpTC Day-1/2.
4. **arXiv 2606.18190:** bài báo ghi CC BY 4.0 và nói các artifact được đưa lên Google Drive khi thu thập, nhưng **không có link phát hành trong phần văn bản tôi đọc được**. Cách lấy: gửi email nhóm tác giả (nơi công tác University of Alabama, địa chỉ corresponding trong bài: mrahman87@ua.edu) xin dataset.

## Đánh giá cho đề tài (OpTC, host eCAR + network Bro, fusion, multi-label)
- **Không dataset nào thay được OpTC** cho bài toán fusion: chỉ OpTC (và có thể 2606.18190) có cả host lẫn network.
- **SAGA phù hợp nhất để làm nhãn đa lớp cho nhánh host:** hạng Q1, nhãn theo từng event (giai đoạn + kỹ thuật), quy mô lớn, nhiều chiến dịch. Hạn chế: log tổng hợp từ Procmon (schema khác eCAR), không có network riêng.
- **skrghosh phù hợp nhất về định dạng:** cùng mô hình eCAR nên tokenizer/pipeline của nhánh host dùng được ngay. Hạn chế: nhãn theo kịch bản (PDF), phải tự dựng nhãn từng event như STEP 12B; chỉ host.
- **2606.18190 phù hợp nhất về nội dung (3 nguồn, nhãn kỹ thuật mỗi event)** nhưng nhỏ (70 phiên tấn công), chưa phản biện, chưa rõ cách lấy; chỉ nên coi là bổ trợ nếu xin được.
- **Windows-APT 2025 phù hợp ít nhất cho DL** (102k bản ghi); dùng được cho thử nhanh host ML hoặc luật.
- Lưu ý với yêu cầu của thầy "bài báo Q1/Q2 hoặc A/A*": SAGA đạt rõ nhất; Windows-APT 2025 và Citar cần kiểm hạng; 2606.18190 chưa đủ điều kiện.

## Chưa làm / cần xác nhận
Chưa tải gì. Dung lượng thật chỉ biết sau khi truy cập (đặc biệt 3 zip SAGA). Nếu muốn mở file để xem cột nhãn, tôi sẽ báo tên file, nguồn và dung lượng trước khi tải.
