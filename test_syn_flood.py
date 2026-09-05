from scapy.all import IP, TCP, send
import random

DIA_CHI_DICH = "192.168.1.1"   # IP router trong mạng nhà bạn - CHỈ test nội bộ
PORT_DICH = 80
SO_GOI_GUI = 80

print(f"Đang gửi {SO_GOI_GUI} gói SYN giả lập tới {DIA_CHI_DICH}:{PORT_DICH} ...")

danh_sach_goi = [
    IP(dst=DIA_CHI_DICH) / TCP(sport=random.randint(1024, 65535), dport=PORT_DICH, flags="S")
    for _ in range(SO_GOI_GUI)
]

send(danh_sach_goi, verbose=0)
print("Đã gửi xong.")
