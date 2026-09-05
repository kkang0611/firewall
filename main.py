from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.arch.windows import get_windows_if_list
from rule_engine import doc_rules, kiem_tra_rule
from logger import ghi_log
from detector import phat_hien_port_scan, phat_hien_syn_flood


def tim_interface_theo_ip(ip_can_tim):
    """Tìm đúng tên interface dựa theo địa chỉ IP đã biết"""
    for iface in get_windows_if_list():
        if ip_can_tim in iface.get("ips", []):
            return iface["name"]
    return None


TEN_INTERFACE = tim_interface_theo_ip("192.168.1.17")
print(f"[DEBUG] Interface tìm được: {TEN_INTERFACE}")

# Đọc rule 1 lần khi khởi động chương trình
rules = doc_rules()

# Đếm số liệu để hiển thị khi dừng chương trình
so_goi_block = 0
so_goi_allow = 0
so_lan_phat_hien_scan = 0
so_lan_phat_hien_flood = 0

# Ghi nhớ các IP đã cảnh báo rồi, tránh spam log liên tục cho cùng 1 IP
da_canh_bao_scan = set()
da_canh_bao_flood = set()


def lay_thong_tin_goi_tin(packet):
    """Trích xuất IP nguồn, port đích, cờ SYN, và giao thức từ 1 gói tin"""
    try:
        if IP not in packet:
            return None, None, False, None

        ip_nguon = packet[IP].src
        port = None
        la_syn = False
        protocol = None

        if TCP in packet:
            port = packet[TCP].dport
            la_syn = (packet[TCP].flags & 0x02) != 0 and (packet[TCP].flags & 0x10) == 0
            protocol = "TCP"
        elif UDP in packet:
            port = packet[UDP].dport
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"

        return ip_nguon, port, la_syn, protocol
    except Exception:
        return None, None, False, None

def xu_ly_goi_tin(packet):
    global so_goi_block, so_goi_allow, so_lan_phat_hien_scan, so_lan_phat_hien_flood

    ip_nguon, port, la_syn, protocol = lay_thong_tin_goi_tin(packet)
    if ip_nguon is None:
        return

    hanh_dong, ly_do = kiem_tra_rule(ip_nguon, port, rules, protocol)
    # ... phần còn lại giữ nguyên không đổi

    ghi_log(ip_nguon, port, hanh_dong, ly_do)

    if hanh_dong == "block":
        so_goi_block += 1
        print(f"[CHẶN]      {ip_nguon}:{port}  ({ly_do})")
    else:
        so_goi_allow += 1
        print(f"[CHO PHÉP]  {ip_nguon}:{port}")

    if phat_hien_port_scan(ip_nguon, port):
        if ip_nguon not in da_canh_bao_scan:
            so_lan_phat_hien_scan += 1
            da_canh_bao_scan.add(ip_nguon)
            canh_bao = f"Nghi ngờ PORT SCAN từ IP {ip_nguon}"
            ghi_log(ip_nguon, port, "canh_bao", canh_bao)
            print(f"[CẢNH BÁO] {canh_bao}")

    if phat_hien_syn_flood(ip_nguon, la_syn):
        if ip_nguon not in da_canh_bao_flood:
            so_lan_phat_hien_flood += 1
            da_canh_bao_flood.add(ip_nguon)
            canh_bao = f"Nghi ngờ SYN FLOOD từ IP {ip_nguon}"
            ghi_log(ip_nguon, port, "canh_bao", canh_bao)
            print(f"[CẢNH BÁO] {canh_bao}")


def main():
    print("=" * 60)
    print("MINI FIREWALL - Đang khởi động...")
    print(f"Đã tải {len(rules)} rule(s) từ rules.json")
    print("Đang lắng nghe gói tin... (Nhấn Ctrl+C để dừng)")
    print("=" * 60)

    try:
        sniff(prn=xu_ly_goi_tin, store=False, iface=TEN_INTERFACE)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n" + "=" * 60)
        print("Đã dừng firewall.")
        print(f"Tổng số gói CHO PHÉP:        {so_goi_allow}")
        print(f"Tổng số gói CHẶN:            {so_goi_block}")
        print(f"Số IP nghi ngờ PORT SCAN:    {so_lan_phat_hien_scan}")
        print(f"Số IP nghi ngờ SYN FLOOD:    {so_lan_phat_hien_flood}")
        print("=" * 60)


if __name__ == "__main__":
    main()