from scapy.all import IP, TCP, sr1
import time

DIA_CHI_DICH = "10.128.128.128"   # Thay bằng Default Gateway vừa tìm được
DANH_SACH_PORT = list(range(20, 35))   # Quét 15 port liên tục từ 20-34

print(f"Đang mô phỏng quét cổng tới {DIA_CHI_DICH} ...")

for port in DANH_SACH_PORT:
    goi_tin = IP(dst=DIA_CHI_DICH) / TCP(dport=port, flags="S")
    sr1(goi_tin, timeout=0.3, verbose=0)
    print(f"Đã quét port {port}")
    time.sleep(0.1)

print("Hoàn tất mô phỏng.")