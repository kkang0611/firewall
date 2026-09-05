import time
from collections import defaultdict

# Lưu lịch sử: mỗi IP -> danh sách (port, thời điểm) đã truy cập
lich_su_port = defaultdict(list)

# Lưu lịch sử: mỗi IP -> danh sách thời điểm gửi gói SYN
lich_su_syn = defaultdict(list)

# ----- Ngưỡng cấu hình (có thể điều chỉnh để demo dễ kích hoạt hơn) -----
NGUONG_SO_PORT = 10        # số port khác nhau
KHOANG_THOI_GIAN_SCAN = 60   # trong vòng 60 giây -> nghi port scan  

NGUONG_SO_SYN = 20           # số gói SYN
KHOANG_THOI_GIAN_FLOOD = 5   # trong vòng X giây -> nghi SYN flood


def don_dep_lich_su(danh_sach, khoang_thoi_gian):
    """Chỉ giữ lại các bản ghi còn nằm trong khoảng thời gian gần đây"""
    now = time.time()
    return [(gia_tri, t) for (gia_tri, t) in danh_sach if now - t <= khoang_thoi_gian]


def phat_hien_port_scan(ip_nguon, port):
    """
    Trả về True nếu IP này đang truy cập quá nhiều port khác nhau
    trong khoảng thời gian ngắn (dấu hiệu port scan)
    """
    now = time.time()
    lich_su_port[ip_nguon].append((port, now))
    lich_su_port[ip_nguon] = don_dep_lich_su(lich_su_port[ip_nguon], KHOANG_THOI_GIAN_SCAN)

    cac_port_khac_nhau = set(p for p, t in lich_su_port[ip_nguon])

    if len(cac_port_khac_nhau) >= NGUONG_SO_PORT:
        return True
    return False


def phat_hien_syn_flood(ip_nguon, la_goi_syn):
    """
    Trả về True nếu IP này gửi quá nhiều gói SYN
    trong khoảng thời gian ngắn (dấu hiệu SYN flood)
    """
    if not la_goi_syn:
        return False

    now = time.time()
    lich_su_syn[ip_nguon].append((True, now))
    lich_su_syn[ip_nguon] = don_dep_lich_su(lich_su_syn[ip_nguon], KHOANG_THOI_GIAN_FLOOD)

    if len(lich_su_syn[ip_nguon]) >= NGUONG_SO_SYN:
        return True
    return False


# ----- Test nhanh module này -----
if __name__ == "__main__":
    print("Mô phỏng port scan từ IP 10.0.0.5 ...")
    for port in range(1, 15):
        bi_phat_hien = phat_hien_port_scan("10.0.0.5", port)
        print(f"  Truy cập port {port} -> nghi ngờ scan: {bi_phat_hien}")

    print("\nMô phỏng SYN flood từ IP 10.0.0.9 ...")
    for i in range(60):
        bi_phat_hien = phat_hien_syn_flood("10.0.0.9", la_goi_syn=True)
        if bi_phat_hien:
            print(f"  Gói SYN thứ {i+1} -> PHÁT HIỆN SYN FLOOD!")
            break