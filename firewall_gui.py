import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import queue
import json

from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.arch.windows import get_windows_if_list

from rule_engine import doc_rules as doc_rules_goc, kiem_tra_rule
from logger import ghi_log
from detector import phat_hien_port_scan, phat_hien_syn_flood

DUONG_DAN_RULES = "rules.json"


# ================== PHẦN LÕI: LOGIC SNIFF CHẠY TRONG THREAD RIÊNG ==================

class DongCoFirewall:
    """Đóng gói toàn bộ trạng thái + logic sniff, tách biệt khỏi giao diện,
    để GUI có thể bắt đầu/dừng dễ dàng mà không bị treo."""

    def __init__(self, hang_doi_thong_bao):
        self.hang_doi = hang_doi_thong_bao      # Queue để gửi log/thống kê an toàn cho GUI
        self.dang_dung = threading.Event()        # Cờ báo hiệu dừng, dùng thay cho Ctrl+C
        self.luong = None
        self.rules = []

        self.so_goi_allow = 0
        self.so_goi_block = 0
        self.so_lan_scan = 0
        self.so_lan_flood = 0
        self.da_canh_bao_scan = set()
        self.da_canh_bao_flood = set()

    def liet_ke_interface(self):
        """Trả về danh sách các interface hợp lệ (bỏ qua loopback/APIPA/IPv6),
        dạng: [(ten_hien_thi, ten_interface, ip), ...].
        Sắp xếp ưu tiên: 192.168.x.x -> 10.x.x.x/172.16-31.x.x -> còn lại,
        để interface mạng LAN thật luôn hiện lên đầu danh sách."""
        uu_tien_1, uu_tien_2, uu_tien_3 = [], [], []

        for iface in get_windows_if_list():
            for ip in iface.get("ips", []):
                if ip == "127.0.0.1" or ip.startswith("169.254") or ":" in ip:
                    continue

                ten_hien_thi = f"{iface['name']}  ({ip})"
                muc = (ten_hien_thi, iface["name"], ip)

                if ip.startswith("192.168."):
                    uu_tien_1.append(muc)
                elif ip.startswith("10.") or ip.startswith("172."):
                    uu_tien_2.append(muc)
                else:
                    uu_tien_3.append(muc)

        return uu_tien_1 + uu_tien_2 + uu_tien_3

    def tim_interface_mac_dinh(self):
        """Dùng khi cần 1 lựa chọn tự động (không qua giao diện chọn tay).
        Trả về (ten_interface, ip) của interface ưu tiên cao nhất, hoặc (None, None)."""
        danh_sach = self.liet_ke_interface()
        if danh_sach:
            _, ten_interface, ip = danh_sach[0]
            return ten_interface, ip
        return None, None

    def lay_thong_tin_goi_tin(self, packet):
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

    def xu_ly_goi_tin(self, packet):
        ip_nguon, port, la_syn, protocol = self.lay_thong_tin_goi_tin(packet)
        if ip_nguon is None:
            return

        hanh_dong, ly_do = kiem_tra_rule(ip_nguon, port, self.rules, protocol)
        ghi_log(ip_nguon, port, hanh_dong, ly_do)

        if hanh_dong == "block":
            self.so_goi_block += 1
            self.hang_doi.put(("log", f"[CHẶN]      {ip_nguon}:{port}  ({ly_do})"))
        else:
            self.so_goi_allow += 1
            self.hang_doi.put(("log", f"[CHO PHÉP]  {ip_nguon}:{port}"))

        if phat_hien_port_scan(ip_nguon, port):
            if ip_nguon not in self.da_canh_bao_scan:
                self.da_canh_bao_scan.add(ip_nguon)
                self.so_lan_scan += 1
                canh_bao = f"Nghi ngờ PORT SCAN từ IP {ip_nguon}"
                ghi_log(ip_nguon, port, "canh_bao", canh_bao)
                self.hang_doi.put(("log", f"[CẢNH BÁO] {canh_bao}"))

        if phat_hien_syn_flood(ip_nguon, la_syn):
            if ip_nguon not in self.da_canh_bao_flood:
                self.da_canh_bao_flood.add(ip_nguon)
                self.so_lan_flood += 1
                canh_bao = f"Nghi ngờ SYN FLOOD từ IP {ip_nguon}"
                ghi_log(ip_nguon, port, "canh_bao", canh_bao)
                self.hang_doi.put(("log", f"[CẢNH BÁO] {canh_bao}"))

        self.hang_doi.put(("thong_ke", {
            "allow": self.so_goi_allow,
            "block": self.so_goi_block,
            "scan": self.so_lan_scan,
            "flood": self.so_lan_flood,
        }))

    def _vong_lap_sniff(self, ten_interface):
        sniff(
            prn=self.xu_ly_goi_tin,
            store=False,
            iface=ten_interface,   # None = lắng nghe TẤT CẢ các interface, hoặc 1 tên cụ thể
            stop_filter=lambda pkt: self.dang_dung.is_set(),
        )
        self.hang_doi.put(("log", "Đã dừng lắng nghe."))

    def bat_dau(self, ten_interface_chon=None):
        """
        ten_interface_chon:
        - None -> lắng nghe TẤT CẢ các interface cùng lúc
        - 1 chuỗi tên -> chỉ lắng nghe đúng interface đó
        """
        self.rules = doc_rules_goc(DUONG_DAN_RULES)
        self.dang_dung.clear()

        self.hang_doi.put(("log", f"Đã tải {len(self.rules)} rule(s)."))

        if ten_interface_chon is None:
            self.hang_doi.put(("log", "Đang lắng nghe trên: TẤT CẢ các mạng"))
        else:
            self.hang_doi.put(("log", f"Đang lắng nghe trên: {ten_interface_chon}"))

        self.luong = threading.Thread(
            target=self._vong_lap_sniff, args=(ten_interface_chon,), daemon=True
        )
        self.luong.start()
        return True

    def dung(self):
        self.dang_dung.set()


# ================== GIAO DIỆN (GUI) ==================

class FirewallGUIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mini Firewall - Bảng điều khiển")
        self.root.geometry("850x680")

        self.hang_doi = queue.Queue()
        self.dong_co = DongCoFirewall(self.hang_doi)
        self.dang_chay = False
        self._ten_interface_that = {}

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.tab_giam_sat = ttk.Frame(notebook)
        self.tab_rule = ttk.Frame(notebook)
        notebook.add(self.tab_giam_sat, text="Giám sát & Điều khiển")
        notebook.add(self.tab_rule, text="Quản lý Rule")

        self._xay_dung_tab_giam_sat()
        self._xay_dung_tab_rule()

        self.root.after(200, self._xu_ly_hang_doi)
        self.root.protocol("WM_DELETE_WINDOW", self._khi_dong_cua_so)

    # ---------------- TAB GIÁM SÁT ----------------
    def _xay_dung_tab_giam_sat(self):
        frame = self.tab_giam_sat

        # ---- Khu vực chọn interface mạng ----
        khung_chon_mang = ttk.Frame(frame)
        khung_chon_mang.pack(fill="x", padx=10, pady=(10, 0))

        ttk.Label(khung_chon_mang, text="Chọn mạng cần giám sát:").pack(side="left")

        self.bien_interface = tk.StringVar()
        self.combo_interface = ttk.Combobox(
            khung_chon_mang, textvariable=self.bien_interface, state="readonly", width=45
        )
        self.combo_interface.pack(side="left", padx=10)

        ttk.Button(khung_chon_mang, text="Làm mới danh sách", command=self._lam_moi_interface).pack(side="left")

        self._lam_moi_interface()

        # ---- Khu vực nút điều khiển ----
        khung_dieu_khien = ttk.Frame(frame)
        khung_dieu_khien.pack(fill="x", padx=10, pady=10)

        self.nut_bat_dau = ttk.Button(khung_dieu_khien, text="Bắt đầu", command=self._bat_dau)
        self.nut_bat_dau.pack(side="left")
        self.nut_dung = ttk.Button(khung_dieu_khien, text="Dừng", command=self._dung, state="disabled")
        self.nut_dung.pack(side="left", padx=10)

        self.nhan_trang_thai = ttk.Label(khung_dieu_khien, text="Trạng thái: Chưa chạy", foreground="gray")
        self.nhan_trang_thai.pack(side="left", padx=20)

        # ---- Khu vực thống kê ----
        khung_thong_ke = ttk.LabelFrame(frame, text="Thống kê")
        khung_thong_ke.pack(fill="x", padx=10, pady=5)

        self.bien_allow = tk.StringVar(value="0")
        self.bien_block = tk.StringVar(value="0")
        self.bien_scan = tk.StringVar(value="0")
        self.bien_flood = tk.StringVar(value="0")

        self._tao_o_thong_ke(khung_thong_ke, "Cho phép:", self.bien_allow, 0)
        self._tao_o_thong_ke(khung_thong_ke, "Chặn:", self.bien_block, 1)
        self._tao_o_thong_ke(khung_thong_ke, "Cảnh báo Scan:", self.bien_scan, 2)
        self._tao_o_thong_ke(khung_thong_ke, "Cảnh báo Flood:", self.bien_flood, 3)

        # ---- Khu vực nhật ký ----
        ttk.Label(frame, text="Nhật ký hoạt động:").pack(anchor="w", padx=10, pady=(10, 0))
        self.o_log = scrolledtext.ScrolledText(frame, height=18, state="disabled", bg="#111", fg="#0f0")
        self.o_log.pack(fill="both", expand=True, padx=10, pady=5)

    def _tao_o_thong_ke(self, parent, nhan, bien, cot):
        khung = ttk.Frame(parent)
        khung.grid(row=0, column=cot, padx=15, pady=8)
        ttk.Label(khung, text=nhan).pack()
        ttk.Label(khung, textvariable=bien, font=("Segoe UI", 14, "bold")).pack()

    def _lam_moi_interface(self):
        """Cập nhật danh sách interface trong ô Combobox"""
        danh_sach = self.dong_co.liet_ke_interface()
        gia_tri_hien_thi = ["-- Tất cả các mạng --"] + [ten for ten, _, _ in danh_sach]
        self.combo_interface["values"] = gia_tri_hien_thi
        self.combo_interface.current(0)
        self._ten_interface_that = {ten: ten_iface for ten, ten_iface, _ in danh_sach}

    def _them_dong_log(self, dong):
        self.o_log.configure(state="normal")
        self.o_log.insert("end", dong + "\n")
        self.o_log.see("end")
        self.o_log.configure(state="disabled")

    def _bat_dau(self):
        lua_chon = self.bien_interface.get()

        if lua_chon == "-- Tất cả các mạng --":
            ten_interface_chon = None
        else:
            ten_interface_chon = self._ten_interface_that.get(lua_chon)

        thanh_cong = self.dong_co.bat_dau(ten_interface_chon)
        if thanh_cong:
            self.dang_chay = True
            self.nut_bat_dau.config(state="disabled")
            self.nut_dung.config(state="normal")
            self.combo_interface.config(state="disabled")  # khóa lại khi đang chạy, tránh đổi giữa chừng
            self.nhan_trang_thai.config(text="Trạng thái: Đang chạy", foreground="green")

    def _dung(self):
        self.dong_co.dung()
        self.dang_chay = False
        self.nut_bat_dau.config(state="normal")
        self.nut_dung.config(state="disabled")
        self.combo_interface.config(state="readonly")
        self.nhan_trang_thai.config(text="Trạng thái: Đã dừng", foreground="red")

    def _xu_ly_hang_doi(self):
        """Được gọi lặp lại mỗi 200ms để lấy dữ liệu từ thread nền,
        cập nhật giao diện một cách AN TOÀN (không update GUI trực tiếp từ thread khác)"""
        try:
            while True:
                loai, du_lieu = self.hang_doi.get_nowait()
                if loai == "log":
                    self._them_dong_log(du_lieu)
                elif loai == "thong_ke":
                    self.bien_allow.set(du_lieu["allow"])
                    self.bien_block.set(du_lieu["block"])
                    self.bien_scan.set(du_lieu["scan"])
                    self.bien_flood.set(du_lieu["flood"])
        except queue.Empty:
            pass
        self.root.after(200, self._xu_ly_hang_doi)

    def _khi_dong_cua_so(self):
        if self.dang_chay:
            self.dong_co.dung()
        self.root.destroy()

    # ---------------- TAB QUẢN LÝ RULE ----------------
    def _xay_dung_tab_rule(self):
        frame = self.tab_rule

        cot = ("ip", "port", "protocol", "action", "reason")
        self.bang_rule = ttk.Treeview(frame, columns=cot, show="headings", height=10)
        for c, tieu_de in zip(cot, ["IP", "Port", "Giao thức", "Hành động", "Lý do"]):
            self.bang_rule.heading(c, text=tieu_de)
            self.bang_rule.column(c, width=120)
        self.bang_rule.pack(fill="both", expand=True, padx=10, pady=10)

        khung_form = ttk.LabelFrame(frame, text="Thêm rule mới")
        khung_form.pack(fill="x", padx=10, pady=5)

        self.bien_ip = tk.StringVar()
        self.bien_port = tk.StringVar()
        self.bien_protocol = tk.StringVar()
        self.bien_action = tk.StringVar(value="block")
        self.bien_reason = tk.StringVar()

        self._tao_o_nhap(khung_form, "IP (để trống = mọi IP):", self.bien_ip, 0)
        self._tao_o_nhap(khung_form, "Port (để trống = mọi port):", self.bien_port, 1)
        self._tao_o_nhap(khung_form, "Giao thức (TCP/UDP/ICMP, trống = mọi loại):", self.bien_protocol, 2)

        ttk.Label(khung_form, text="Hành động:").grid(row=3, column=0, sticky="w", padx=5, pady=3)
        ttk.Combobox(khung_form, textvariable=self.bien_action, values=["block", "allow"],
                     state="readonly", width=15).grid(row=3, column=1, sticky="w", padx=5, pady=3)

        self._tao_o_nhap(khung_form, "Lý do:", self.bien_reason, 4)

        khung_nut = ttk.Frame(frame)
        khung_nut.pack(fill="x", padx=10, pady=10)
        ttk.Button(khung_nut, text="Thêm rule", command=self._them_rule).pack(side="left")
        ttk.Button(khung_nut, text="Xóa rule đã chọn", command=self._xoa_rule).pack(side="left", padx=10)
        ttk.Button(khung_nut, text="Lưu vào rules.json", command=self._luu_rule).pack(side="left")
        ttk.Button(khung_nut, text="Tải lại", command=self._tai_lai_rule).pack(side="left", padx=10)

        self.rules_hien_tai = []
        self._tai_lai_rule()

    def _tao_o_nhap(self, parent, nhan, bien, hang):
        ttk.Label(parent, text=nhan).grid(row=hang, column=0, sticky="w", padx=5, pady=3)
        ttk.Entry(parent, textvariable=bien, width=30).grid(row=hang, column=1, sticky="w", padx=5, pady=3)

    def _tai_lai_rule(self):
        try:
            with open(DUONG_DAN_RULES, "r", encoding="utf-8") as f:
                self.rules_hien_tai = json.load(f)
        except FileNotFoundError:
            self.rules_hien_tai = []
        self._ve_lai_bang_rule()

    def _ve_lai_bang_rule(self):
        for dong in self.bang_rule.get_children():
            self.bang_rule.delete(dong)
        for rule in self.rules_hien_tai:
            ip = rule.get("ip") or rule.get("ip_range") or "*"
            port = rule.get("port")
            port_hien = "*" if port is None else str(port)
            self.bang_rule.insert("", "end", values=(
                ip, port_hien, rule.get("protocol") or "*", rule.get("action", ""), rule.get("reason", "")
            ))

    def _them_rule(self):
        ip = self.bien_ip.get().strip() or None
        port_nhap = self.bien_port.get().strip()
        port = int(port_nhap) if port_nhap.isdigit() else None
        protocol = self.bien_protocol.get().strip().upper() or None
        action = self.bien_action.get()
        reason = self.bien_reason.get().strip()

        rule_moi = {"ip": ip, "port": port, "protocol": protocol, "action": action, "reason": reason}

        if self.rules_hien_tai and all(
            self.rules_hien_tai[-1].get(k) is None for k in ("ip", "ip_range", "port", "protocol")
        ):
            self.rules_hien_tai.insert(len(self.rules_hien_tai) - 1, rule_moi)
        else:
            self.rules_hien_tai.append(rule_moi)

        self._ve_lai_bang_rule()
        messagebox.showinfo("Thành công", "Đã thêm rule (nhớ bấm Lưu để ghi vào file).")

    def _xoa_rule(self):
        chon = self.bang_rule.selection()
        if not chon:
            messagebox.showwarning("Chưa chọn", "Vui lòng chọn 1 rule trong bảng để xóa.")
            return
        chi_so = self.bang_rule.index(chon[0])
        del self.rules_hien_tai[chi_so]
        self._ve_lai_bang_rule()

    def _luu_rule(self):
        with open(DUONG_DAN_RULES, "w", encoding="utf-8") as f:
            json.dump(self.rules_hien_tai, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("Đã lưu", "Đã lưu rules.json thành công.")


if __name__ == "__main__":
    root = tk.Tk()
    app = FirewallGUIApp(root)
    root.mainloop()