import json

DUONG_DAN_RULES = "rules.json"


def doc_rules():
    """Đọc danh sách rule từ file JSON"""
    try:
        with open(DUONG_DAN_RULES, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return []


def luu_rules(rules):
    """Ghi danh sách rule xuống file JSON"""
    with open(DUONG_DAN_RULES, "w", encoding="utf-8") as f:
        json.dump(rules, f, indent=2, ensure_ascii=False)


def hien_thi_rules(rules):
    """In danh sách rule ra màn hình dạng bảng dễ đọc"""
    if not rules:
        print("Chưa có rule nào.")
        return

    print("\n" + "-" * 70)
    print(f"{'STT':<5}{'IP':<18}{'Port':<8}{'Hành động':<12}{'Lý do'}")
    print("-" * 70)
    for i, rule in enumerate(rules, start=1):
        ip = rule.get("ip") or "*"
        port = rule.get("port") if rule.get("port") is not None else "*"
        print(f"{i:<5}{str(ip):<18}{str(port):<8}{rule.get('action', ''):<12}{rule.get('reason', '')}")
    print("-" * 70)


def them_rule(rules):
    """Hỏi thông tin từ người dùng để thêm 1 rule mới"""
    print("\n--- Thêm rule mới ---")

    ip = input("Nhập IP cần áp dụng (để trống nếu áp dụng mọi IP): ").strip()
    ip = ip if ip else None

    port_nhap = input("Nhập port cần áp dụng (để trống nếu áp dụng mọi port): ").strip()
    port = int(port_nhap) if port_nhap.isdigit() else None

    while True:
        action = input("Hành động (block/allow): ").strip().lower()
        if action in ("block", "allow"):
            break
        print("Vui lòng nhập đúng 'block' hoặc 'allow'.")

    reason = input("Lý do (mô tả ngắn gọn): ").strip()

    rule_moi = {"ip": ip, "port": port, "action": action, "reason": reason}

    # Chèn rule mới vào TRƯỚC rule cuối cùng (rule mặc định),
    # để đảm bảo rule mặc định luôn nằm cuối danh sách
    if rules and rules[-1].get("ip") is None and rules[-1].get("port") is None:
        rules.insert(len(rules) - 1, rule_moi)
    else:
        rules.append(rule_moi)

    print("Đã thêm rule mới!")
    return rules


def xoa_rule(rules):
    """Hỏi số thứ tự để xóa 1 rule"""
    hien_thi_rules(rules)
    if not rules:
        return rules

    so_nhap = input("\nNhập STT rule muốn xóa (hoặc Enter để hủy): ").strip()
    if not so_nhap.isdigit():
        print("Đã hủy.")
        return rules

    stt = int(so_nhap)
    if 1 <= stt <= len(rules):
        rule_da_xoa = rules.pop(stt - 1)
        print(f"Đã xóa rule: {rule_da_xoa}")
    else:
        print("STT không hợp lệ.")

    return rules


def hien_menu():
    print("\n" + "=" * 40)
    print("   QUẢN LÝ RULE - MINI FIREWALL")
    print("=" * 40)
    print("1. Xem danh sách rule")
    print("2. Thêm rule mới")
    print("3. Xóa rule")
    print("4. Lưu và thoát")
    print("=" * 40)


def main():
    rules = doc_rules()
    print(f"Đã tải {len(rules)} rule(s) từ {DUONG_DAN_RULES}")

    while True:
        hien_menu()
        lua_chon = input("Chọn chức năng (1-4): ").strip()

        if lua_chon == "1":
            hien_thi_rules(rules)
        elif lua_chon == "2":
            rules = them_rule(rules)
        elif lua_chon == "3":
            rules = xoa_rule(rules)
        elif lua_chon == "4":
            luu_rules(rules)
            print("Đã lưu vào rules.json. Tạm biệt!")
            break
        else:
            print("Lựa chọn không hợp lệ, vui lòng chọn từ 1-4.")


if __name__ == "__main__":
    main()