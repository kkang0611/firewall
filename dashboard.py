import re
from collections import Counter, defaultdict
import matplotlib.pyplot as plt

DUONG_DAN_LOG = "logs/firewall.log"

# Mẫu regex để tách thông tin từ mỗi dòng log
# Ví dụ dòng log: [2026-08-30 11:58:05] BLOCK  | IP: 47.253.216.242 | Port: 49372  | IP thử nghiệm...
MAU_DONG_LOG = re.compile(
    r"\[(?P<thoi_gian>[\d\-]+ [\d:]+)\]\s+(?P<hanh_dong>\S+)\s+\|\s+IP:\s+(?P<ip>\S+)\s+\|\s+Port:\s+(?P<port>\S+)\s+\|\s+(?P<ly_do>.*)"
)


def doc_va_phan_tich_log():
    """Đọc file log, trả về danh sách các bản ghi đã phân tích"""
    ban_ghi = []
    try:
        with open(DUONG_DAN_LOG, "r", encoding="utf-8") as f:
            for dong in f:
                khop = MAU_DONG_LOG.match(dong.strip())
                if khop:
                    ban_ghi.append(khop.groupdict())
    except FileNotFoundError:
        print(f"Không tìm thấy file {DUONG_DAN_LOG}. Hãy chạy main.py trước để tạo log.")
    return ban_ghi


def ve_bieu_do_allow_block(ban_ghi):
    """Biểu đồ tròn: tỷ lệ ALLOW vs BLOCK vs CANH_BAO"""
    dem = Counter(bg["hanh_dong"] for bg in ban_ghi)

    nhan = list(dem.keys())
    gia_tri = list(dem.values())

    plt.figure(figsize=(6, 6))
    plt.pie(gia_tri, labels=nhan, autopct="%1.1f%%", startangle=90)
    plt.title("Tỷ lệ hành động của Firewall")
    plt.savefig("dashboard_ty_le_hanh_dong.png")
    print("Đã lưu: dashboard_ty_le_hanh_dong.png")
    plt.close()


def ve_bieu_do_top_ip_bi_chan(ban_ghi):
    """Biểu đồ cột: Top 5 IP bị BLOCK nhiều nhất"""
    ip_bi_chan = [bg["ip"] for bg in ban_ghi if bg["hanh_dong"] == "BLOCK"]
    dem = Counter(ip_bi_chan)
    top_5 = dem.most_common(5)

    if not top_5:
        print("Không có dữ liệu IP bị chặn để vẽ biểu đồ.")
        return

    ips = [ip for ip, _ in top_5]
    so_lan = [n for _, n in top_5]

    plt.figure(figsize=(8, 5))
    plt.bar(ips, so_lan, color="crimson")
    plt.title("Top 5 IP bị chặn nhiều nhất")
    plt.xlabel("Địa chỉ IP")
    plt.ylabel("Số lần bị chặn")
    plt.xticks(rotation=30, ha="right")
    plt.tight_layout()
    plt.savefig("dashboard_top_ip_bi_chan.png")
    print("Đã lưu: dashboard_top_ip_bi_chan.png")
    plt.close()


def ve_bieu_do_traffic_theo_thoi_gian(ban_ghi):
    """Biểu đồ đường: số lượng gói tin theo từng phút"""
    dem_theo_phut = defaultdict(int)

    for bg in ban_ghi:
        # Cắt chuỗi thời gian tới đơn vị phút, bỏ giây (để gộp nhóm theo phút)
        phut = bg["thoi_gian"][:16]  # "2026-08-30 11:58"
        dem_theo_phut[phut] += 1

    thoi_diem = sorted(dem_theo_phut.keys())
    so_luong = [dem_theo_phut[t] for t in thoi_diem]

    plt.figure(figsize=(10, 5))
    plt.plot(thoi_diem, so_luong, marker="o", color="teal")
    plt.title("Số lượng gói tin theo thời gian")
    plt.xlabel("Thời điểm")
    plt.ylabel("Số gói tin")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.savefig("dashboard_traffic_theo_thoi_gian.png")
    print("Đã lưu: dashboard_traffic_theo_thoi_gian.png")
    plt.close()


def in_bang_tong_hop(ban_ghi):
    """In ra bảng tổng hợp số liệu dạng text"""
    dem = Counter(bg["hanh_dong"] for bg in ban_ghi)
    tong_so_ip_khac_nhau = len(set(bg["ip"] for bg in ban_ghi))

    print("\n" + "=" * 50)
    print("BẢNG TỔNG HỢP THỐNG KÊ")
    print("=" * 50)
    print(f"Tổng số dòng log:         {len(ban_ghi)}")
    print(f"Số gói ALLOW:             {dem.get('ALLOW', 0)}")
    print(f"Số gói BLOCK:             {dem.get('BLOCK', 0)}")
    print(f"Số lần CẢNH BÁO:          {dem.get('CANH_BAO', 0)}")
    print(f"Số IP khác nhau xuất hiện: {tong_so_ip_khac_nhau}")
    print("=" * 50)


def main():
    print("Đang đọc và phân tích file log...")
    ban_ghi = doc_va_phan_tich_log()

    if not ban_ghi:
        print("Không có dữ liệu để vẽ biểu đồ.")
        return

    print(f"Đã đọc được {len(ban_ghi)} dòng log hợp lệ.\n")

    in_bang_tong_hop(ban_ghi)
    ve_bieu_do_allow_block(ban_ghi)
    ve_bieu_do_top_ip_bi_chan(ban_ghi)
    ve_bieu_do_traffic_theo_thoi_gian(ban_ghi)

    print("\nHoàn tất! Kiểm tra các file .png vừa được tạo trong thư mục project.")


if __name__ == "__main__":
    main()