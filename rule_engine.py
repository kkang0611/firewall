import json
import ipaddress


def doc_rules(duong_dan="rules.json"):
    """Đọc danh sách rule từ file JSON"""
    with open(duong_dan, "r", encoding="utf-8") as f:
        return json.load(f)


def _khop_ip(ip_nguon, rule):
    """Kiểm tra IP gói tin có khớp điều kiện IP của rule không.
    Hỗ trợ: không giới hạn, IP cụ thể, hoặc dải CIDR (ip_range)."""
    ip_rule = rule.get("ip")
    cidr_rule = rule.get("ip_range")

    if ip_rule is None and cidr_rule is None:
        return True

    if ip_rule is not None and ip_rule == ip_nguon:
        return True

    if cidr_rule is not None:
        try:
            return ipaddress.ip_address(ip_nguon) in ipaddress.ip_network(cidr_rule, strict=False)
        except ValueError:
            return False

    return False


def _khop_port(port, rule):
    """Kiểm tra port gói tin có khớp điều kiện port của rule không.
    Hỗ trợ: không giới hạn, 1 port, danh sách port, hoặc dải port (port_range)."""
    port_rule = rule.get("port")
    khoang_port = rule.get("port_range")

    if port_rule is None and khoang_port is None:
        return True

    if port_rule is not None:
        if isinstance(port_rule, list):
            return port in port_rule
        return port == port_rule

    if khoang_port is not None:
        start, end = khoang_port
        return port is not None and start <= port <= end

    return False


def _khop_protocol(protocol, rule):
    """Kiểm tra giao thức (TCP/UDP/ICMP) có khớp rule không"""
    protocol_rule = rule.get("protocol")
    if protocol_rule is None:
        return True
    return protocol_rule.upper() == (protocol or "").upper()


def kiem_tra_rule(ip_nguon, port, rules, protocol=None):
    """
    Duyệt qua từng rule theo thứ tự, trả về hành động (allow/block)
    của rule đầu tiên khớp CẢ 3 điều kiện: IP, port, protocol.
    """
    for rule in rules:
        if _khop_ip(ip_nguon, rule) and _khop_port(port, rule) and _khop_protocol(protocol, rule):
            return rule["action"], rule.get("reason", "")

    return "allow", "Không khớp rule nào - mặc định cho phép"


# Test nhanh module này
if __name__ == "__main__":
    rules = doc_rules()
    print(f"Đã đọc được {len(rules)} rule(s)")

    test_cases = [
        ("47.253.216.242", 443, "TCP"),
        ("10.5.5.5", 80, "TCP"),          # thử khớp ip_range 10.0.0.0/8
        ("192.168.1.50", 3389, "TCP"),     # thử khớp danh sách port
        ("192.168.1.50", 500, "TCP"),      # thử khớp dải port 1-1024
        ("8.8.8.8", None, "ICMP"),          # thử khớp theo protocol
        ("8.8.8.8", 443, "TCP"),             # không khớp gì -> allow mặc định
    ]

    for ip, port, proto in test_cases:
        hanh_dong, ly_do = kiem_tra_rule(ip, port, rules, proto)
        print(f"IP: {ip}, Port: {port}, Proto: {proto} -> {hanh_dong.upper()} ({ly_do})")