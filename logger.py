import datetime
import os

DUONG_DAN_LOG = "logs/firewall.log"

def dam_bao_thu_muc_ton_tai():
    """Tạo thư mục logs nếu chưa có, tránh lỗi khi ghi file"""
    os.makedirs("logs", exist_ok=True)


def ghi_log(ip_nguon, port, hanh_dong, ly_do=""):
    """
    Ghi 1 dòng log vào file firewall.log
    Mỗi dòng gồm: thời gian, hành động, IP, port, lý do
    """
    dam_bao_thu_muc_ton_tai()

    thoi_gian = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dong_log = f"[{thoi_gian}] {hanh_dong.upper():6} | IP: {ip_nguon:15} | Port: {str(port):6} | {ly_do}\n"

    with open(DUONG_DAN_LOG, "a", encoding="utf-8") as f:
        f.write(dong_log)


# Đoạn test nhanh module này
if __name__ == "__main__":
    ghi_log("47.253.216.242", 443, "block", "IP thử nghiệm - chặn để test")
    ghi_log("8.8.8.8", 443, "allow", "Luật mặc định")
    print("Đã ghi log thử nghiệm. Kiểm tra file logs/firewall.log")