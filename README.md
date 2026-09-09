# 🛡️ Mini Firewall – Packet Filter & Intrusion Detection bằng Python

Đồ án môn **An toàn và Bảo mật Thông tin** – Xây dựng một hệ thống firewall
mini dạng packet-filtering, có khả năng lọc gói tin theo luật cấu hình và
tự động phát hiện hành vi tấn công mạng (Port Scan, SYN Flood) theo thời
gian thực, kèm giao diện đồ họa quản lý.

---

## 📌 Giới thiệu

Dự án mô phỏng cách một firewall thực tế hoạt động ở mức cơ bản: bắt gói
tin đi qua card mạng, đối chiếu với bộ luật (rule) để quyết định cho phép
hay chặn, đồng thời giám sát hành vi bất thường (quét cổng, tấn công từ
chối dịch vụ) và ghi lại toàn bộ nhật ký hoạt động.

Hệ thống được xây dựng hoàn toàn bằng Python, sử dụng thư viện **Scapy**
để thao tác ở tầng gói tin (packet-level), có cả giao diện dòng lệnh (CLI)
và giao diện đồ họa (GUI) để tiện demo và sử dụng thực tế.

## ✨ Tính năng chính

- **Bắt và phân tích gói tin thời gian thực** trên card mạng đang hoạt động
- **Lọc gói tin theo luật (rule-based filtering)**, hỗ trợ:
  - Địa chỉ IP cụ thể
  - Dải mạng theo chuẩn CIDR (ví dụ `10.0.0.0/8`)
  - 1 port, danh sách nhiều port, hoặc dải port liên tục
  - Lọc theo giao thức: TCP / UDP / ICMP
- **Phát hiện tấn công tự động** dựa trên kỹ thuật sliding window:
  - Port Scan – phát hiện khi 1 IP truy cập quá nhiều port khác nhau trong
    thời gian ngắn
  - SYN Flood – phát hiện khi 1 IP gửi quá nhiều gói TCP-SYN liên tục
- **Ghi log đầy đủ** mọi quyết định (allow/block/cảnh báo) kèm thời gian
- **Giao diện đồ họa (GUI)** bằng Tkinter:
  - Bảng điều khiển: bắt đầu/dừng giám sát, chọn card mạng, xem thống kê
    và nhật ký hoạt động trực tiếp
  - Quản lý rule bằng bảng trực quan, thêm/xóa/lưu không cần sửa tay JSON
- **Giao diện dòng lệnh (CLI)** để quản lý rule nhanh, không cần GUI
- **Dashboard thống kê**: tự động đọc log và vẽ biểu đồ (tỷ lệ allow/block,
  top IP bị chặn, lưu lượng theo thời gian)
- **Công cụ mã hóa đi kèm**: mã hóa/giải mã văn bản và file bằng Caesar,
  AES, cùng hàm băm MD5/SHA256 (tính năng bổ sung, giao diện Tkinter)

## 🗂️ Cấu trúc dự án

```
├── main.py              # Chương trình chính chạy bằng CLI (dòng lệnh)
├── firewall_gui.py       # Giao diện đồ họa điều khiển firewall
├── rule_engine.py         # Bộ máy so khớp luật (IP / CIDR / port / protocol)
├── rules.json              # File cấu hình luật lọc
├── detector.py               # Module phát hiện Port Scan & SYN Flood
├── logger.py                  # Module ghi log hoạt động
├── quan_ly_rule.py             # Giao diện CLI quản lý rule
├── dashboard.py                  # Phân tích log, vẽ biểu đồ thống kê
├── test_syn_flood.py               # Script mô phỏng SYN Flood để kiểm thử
├── encrypt_tool.py                   # Công cụ mã hóa (tính năng phụ)
└── logs/
    └── firewall.log                    # Log được tạo tự động khi chạy
```

## ⚙️ Yêu cầu hệ thống

- Python 3.10+
- Hệ điều hành: Windows (đã test), cần cài thêm **Npcap** để bắt gói tin
- Quyền **Administrator** khi chạy (bắt buộc để sniff gói tin)

## 📦 Cài đặt

```bash
# Cài các thư viện cần thiết
pip install scapy matplotlib pycryptodome
```

Windows cần cài thêm **Npcap**: tải tại https://npcap.com (khi cài, tick
chọn *"Install Npcap in WinPcap API-compatible Mode"*).

## 🚀 Cách chạy

### Chạy bằng giao diện đồ họa (khuyến nghị)

```bash
python firewall_gui.py
```

Chọn card mạng cần giám sát ở dropdown, bấm **Bắt đầu**. Chuyển sang tab
**Quản lý Rule** để thêm/xóa luật trực quan.

### Chạy bằng dòng lệnh

```bash
python main.py
```

Nhấn `Ctrl + C` để dừng và xem bảng tổng kết.

### Quản lý rule qua CLI (không cần GUI)

```bash
python quan_ly_rule.py
```

### Xem thống kê trực quan sau khi đã chạy 1 thời gian

```bash
python dashboard.py
```

Kết quả sẽ tạo ra 3 file ảnh `.png` biểu đồ trong thư mục dự án.

## 🧩 Cấu hình luật (rules.json)

Mỗi rule là 1 object JSON, được xét theo **thứ tự từ trên xuống**, rule đầu
tiên khớp sẽ được áp dụng. Rule mặc định (không giới hạn gì) luôn đặt cuối.

```json
{
  "ip": "1.2.3.4",
  "ip_range": "10.0.0.0/8",
  "port": [21, 23, 3389],
  "port_range": [1, 1024],
  "protocol": "TCP",
  "action": "block",
  "reason": "Mô tả lý do"
}
```

Mỗi trường đều tùy chọn (có thể bỏ trống/`null` nếu không cần giới hạn).

## 🔬 Kỹ thuật phát hiện tấn công

| Loại tấn công | Nguyên lý phát hiện |
|---|---|
| Port Scan | 1 IP truy cập ≥ N port khác nhau trong X giây (cấu hình trong `detector.py`) |
| SYN Flood | 1 IP gửi ≥ N gói TCP-SYN (không kèm ACK) trong X giây |

Cả 2 dùng kỹ thuật **sliding window** (cửa sổ trượt thời gian) để đảm bảo
đánh giá luôn dựa trên hành vi gần đây nhất, không bị dữ liệu cũ làm sai
lệch.

## ⚠️ Hạn chế

- Đây là hệ thống **giám sát/ghi log (passive monitoring)**, chưa thực sự
  chặn kết nối ở tầng hệ điều hành. Muốn chặn thật cần tích hợp thêm công
  cụ như WinDivert (Windows) hoặc iptables (Linux).
- Chưa hỗ trợ IPv6.
- Chế độ giám sát đồng thời nhiều card mạng ("Tất cả các mạng") trên
  Windows chưa ổn định — khuyến nghị chọn 1 interface cụ thể.
- Ngưỡng phát hiện tấn công (số port, số gói SYN...) là cố định, chưa
  thích ứng động theo từng môi trường.

## 🔭 Hướng phát triển

- Tích hợp chặn thật ở tầng hệ điều hành
- Hỗ trợ IPv6
- Áp dụng Machine Learning để phát hiện tấn công phức tạp hơn
- Ghi log theo chuẩn syslog để tích hợp hệ thống SIEM

## 👥 Nhóm thực hiện

Đồ án môn An toàn và Bảo mật Thông tin.

## 📄 Giấy phép

Dự án phục vụ mục đích học tập.
