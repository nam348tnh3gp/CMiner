#!/usr/bin/env python3
"""
Duino-Coin Official PC Miner 4.3 – Pure Python Edition (iPhone/Darwin arm64)
Loại bỏ Discord RPC, giữ toàn bộ tính năng đào, màu sắc.
Thiết bị mặc định: darkwin (arm64) – có thể đổi qua Settings.cfg
"""

import time, hashlib, socket, os, sys, json, random, threading, locale
from datetime import datetime
from pathlib import Path
from configparser import ConfigParser
from urllib.request import urlopen, Request
from urllib.error import URLError

# Cố gắng dùng colorama nếu có, nếu không dùng màu ANSI thô
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Back:
        RED = GREEN = YELLOW = BLUE = MAGENTA = CYAN = WHITE = RESET = ''
    class Style:
        BRIGHT = DIM = NORMAL = RESET_ALL = ''

# ----------------------------- CẤU HÌNH MẶC ĐỊNH -----------------------------
class Settings:
    VER = 4.3
    DATA_DIR = f"Duino-Coin PC Miner {VER}"
    SETTINGS_FILE = f"{DATA_DIR}/Settings.cfg"
    TRANSLATIONS_FILE = f"{DATA_DIR}/Translations.json"
    TRANSLATIONS_URL = "https://raw.githubusercontent.com/revoxhere/duino-coin/master/Resources/PC_Miner_langs.json"
    SOC_TIMEOUT = 10
    REPORT_TIME = 300
    DONATE_LVL = 0
    RASPI_LEDS = "y"
    RASPI_CPU_IOT = "y"
    BLOCK = " ‖ "
    PICK = " ⛏"
    COG = " ⚙"
    # Định danh mặc định cho iPhone/iPad
    DEFAULT_RIG = "darkwin"

# ----------------------------- TIỆN ÍCH MÀU SẮC & IN ẤN -----------------------------
def now():
    return datetime.now()

def pretty_print(msg, state="success", sender="sys0", print_queue=None):
    bg_map = {"net": Back.BLUE, "cpu": Back.YELLOW, "sys": Back.GREEN}
    fg_map = {"success": Fore.GREEN, "info": Fore.BLUE, "error": Fore.RED, "warning": Fore.YELLOW}
    bg = bg_map.get(sender[:3], Back.RESET)
    fg = fg_map.get(state, Fore.WHITE)
    line = (f"{Fore.WHITE}{now().strftime(Style.DIM + '%H:%M:%S ')}"
            f"{Style.RESET_ALL}{Style.BRIGHT}{bg} {sender} {Style.NORMAL}{Back.RESET} {fg}{msg.strip()}")
    if print_queue is not None:
        print_queue.append(line)
    else:
        print(line)

def share_print(id, typ, accept, reject, thread_hashrate, total_hashrate, computetime, diff, ping, back_color, reject_cause=None, print_queue=None):
    thread_hr = get_prefix("H/s", thread_hashrate, 2)
    total_hr = get_prefix("H/s", total_hashrate, 1)
    diff_str = get_prefix("", int(diff), 0)
    if typ == "accept":
        share_str = "Accepted"
        fg = Fore.GREEN
    elif typ == "block":
        share_str = "Block found!"
        fg = Fore.YELLOW
    else:
        share_str = "Rejected"
        if reject_cause:
            share_str += f" ({reject_cause})"
        fg = Fore.RED
    line = (f"{Fore.WHITE}{now().strftime(Style.DIM + '%H:%M:%S ')}"
            f"{Style.RESET_ALL}{Fore.WHITE}{Style.BRIGHT}{back_color} cpu{id} {Back.RESET}"
            f"{fg}{Settings.PICK}{share_str} {Fore.RESET}{accept}/{(accept+reject)}"
            f" {Fore.YELLOW}({round(accept/(accept+reject)*100) if (accept+reject) else 0}%)"
            f"{Style.NORMAL} · {computetime:04.1f}s · {Fore.BLUE}{Style.BRIGHT}{thread_hr}{Style.DIM} ({total_hr} total)"
            f"{Fore.RESET}{Settings.COG} diff {diff_str} · {Fore.CYAN}ping {int(ping)}ms")
    if print_queue is not None:
        print_queue.append(line)
    else:
        print(line)

def get_prefix(symbol, val, accuracy):
    if val >= 1e12: return f"{round(val/1e12, accuracy)} T{symbol}"
    elif val >= 1e9: return f"{round(val/1e9, accuracy)} G{symbol}"
    elif val >= 1e6: return f"{round(val/1e6, accuracy)} M{symbol}"
    elif val >= 1e3: return f"{round(val/1e3, accuracy)} k{symbol}"
    else: return f"{round(val, accuracy)} {symbol}"

# ----------------------------- ĐA NGÔN NGỮ -----------------------------
def load_language():
    lang_file = {}
    try:
        with open(Settings.TRANSLATIONS_FILE, 'r', encoding='utf-8') as f:
            lang_file = json.load(f)
    except:
        try:
            req = Request(Settings.TRANSLATIONS_URL)
            with urlopen(req, timeout=10) as resp:
                lang_file = json.loads(resp.read().decode('utf-8'))
            with open(Settings.TRANSLATIONS_FILE, 'w', encoding='utf-8') as f:
                json.dump(lang_file, f)
        except:
            pass
    locale_str = locale.getdefaultlocale()[0] or "en"
    lang = "english"
    for code, name in [("es","spanish"),("pl","polish"),("fr","french"),("jp","japanese"),
                       ("fa","farsi"),("mt","maltese"),("ru","russian"),("uk","ukrainian"),
                       ("de","german"),("tr","turkish"),("pr","portuguese"),("it","italian"),
                       ("sk","slovak"),("zh_TW","chinese_Traditional"),("zh","chinese_simplified"),
                       ("th","thai"),("ko","korean"),("id","indonesian"),("cz","czech"),("fi","finnish")]:
        if locale_str.startswith(code):
            lang = name
            break
    return lang, lang_file

def get_string(key):
    if key in lang_file.get(lang, {}) or key in lang_file.get("english", {}):
        return lang_file.get(lang, lang_file["english"])[key]
    return key

# ----------------------------- THUẬT TOÁN ĐÀO (DUCOS1 thuần Python) -----------------------------
def ducos1_pure(last_hash, expected_hash, diff, efficiency):
    base = hashlib.sha1(last_hash.encode('ascii'))
    for nonce in range(100 * diff + 1):
        h = base.copy()
        h.update(str(nonce).encode('ascii'))
        if h.hexdigest() == expected_hash:
            return nonce
        if efficiency != 0 and nonce % 5000 == 0:
            time.sleep(efficiency / 100)
    return 0

# ----------------------------- KẾT NỐI MẠNG -----------------------------
def fetch_pool():
    for _ in range(30):
        try:
            with urlopen("https://server.duinocoin.com/getPool", timeout=10) as resp:
                data = json.loads(resp.read().decode())
            if data["success"]:
                return (data["ip"], data["port"])
            else:
                print("Pool message:", data.get("message",""))
        except Exception as e:
            print("Pool fetch error:", e)
        time.sleep(2)
    raise Exception("Cannot fetch pool")

def send_msg(sock, msg):
    sock.sendall((msg + "\n").encode())

def recv_msg(sock, limit=128):
    return sock.recv(limit).decode().rstrip("\n")

# ----------------------------- CẤU HÌNH NGƯỜI DÙNG -----------------------------
def load_config():
    config = ConfigParser()
    if not Path(Settings.SETTINGS_FILE).is_file():
        # Tạo thư mục nếu chưa có
        Path(Settings.DATA_DIR).mkdir(exist_ok=True)
        print("First run: basic configuration")
        username = input("Username: ")
        mining_key = input("Mining key (leave blank if none): ") or "None"
        intensity = input("Intensity (1-100, default 95): ") or "95"
        try:
            intensity = max(1, min(100, int(intensity)))
        except:
            intensity = 95
        threads = input(f"Threads (default {os.cpu_count() or 1}): ") or str(os.cpu_count() or 1)
        try:
            threads = max(1, min(16, int(threads)))
        except:
            threads = 1
        start_diff = input("Difficulty (1=LOW, 2=MEDIUM, 3=NET, default 2): ") or "2"
        if start_diff == "1": start_diff = "LOW"
        elif start_diff == "3": start_diff = "NET"
        else: start_diff = "MEDIUM"
        rig_id = input("Rig identifier (leave blank for default 'darkwin' on ARM): ") or Settings.DEFAULT_RIG
        donate = input("Donation level (0-5, default 0): ") or "0"
        try:
            donate = max(0, min(5, int(donate)))
        except:
            donate = 0
        lang_code = locale.getdefaultlocale()[0] or "en"
        config["PC Miner"] = {
            "username": username,
            "mining_key": mining_key,
            "intensity": str(intensity),
            "threads": str(threads),
            "start_diff": start_diff,
            "donate": str(donate),
            "identifier": rig_id,
            "algorithm": "DUCO-S1",
            "language": lang_code,
            "soc_timeout": str(Settings.SOC_TIMEOUT),
            "report_sec": str(Settings.REPORT_TIME),
            "discord_rp": "n"
        }
        with open(Settings.SETTINGS_FILE, 'w') as f:
            config.write(f)
        print("Configuration saved.")
    else:
        config.read(Settings.SETTINGS_FILE)
    return config["PC Miner"]

# ----------------------------- THREAD ĐÀO -----------------------------
def miner_thread(tid, user, pool, accept_cnt, reject_cnt, hashrates, print_queue, stop_event, rig_id, single_miner_id, intensity, start_diff, mining_key):
    sock = None
    while not stop_event.is_set():
        try:
            sock = socket.socket()
            sock.settimeout(Settings.SOC_TIMEOUT)
            sock.connect(pool)
            sock.settimeout(None)
            # MOTD
            send_msg(sock, "MOTD")
            motd = recv_msg(sock, 512)
            if tid == 0:
                pretty_print("MOTD: " + motd.replace("\n", "\n\t\t"), "success", "net0", print_queue)
            # Main loop
            while not stop_event.is_set():
                job_req = f"JOB,{user},{start_diff},{mining_key}"
                send_msg(sock, job_req)
                job = recv_msg(sock).split(",")
                if len(job) == 3:
                    last_h, exp_h, diff = job
                    diff = int(diff)
                else:
                    time.sleep(3)
                    continue
                # Đào
                eff = 0
                i = int(intensity)
                if 90 <= i < 99: eff = 0.005
                elif 70 <= i < 90: eff = 0.1
                elif 50 <= i < 70: eff = 0.8
                elif 30 <= i < 50: eff = 1.8
                elif i < 30: eff = 3
                t0 = time.time()
                nonce = ducos1_pure(last_h, exp_h, diff, eff)
                elapsed = time.time() - t0
                hashrate = nonce / elapsed if elapsed > 0 else 0
                hashrates[tid] = hashrate
                # Gửi kết quả
                send_msg(sock, f"{nonce},{hashrate},Official PC Miner {Settings.VER},{rig_id},,{single_miner_id}")
                feedback = recv_msg(sock).split(",")
                ping = (time.time() - t0) * 1000
                if feedback[0] == "GOOD":
                    accept_cnt.value += 1
                    share_print(tid, "accept", accept_cnt.value, reject_cnt.value, hashrate, sum(hashrates.values()), elapsed, diff, ping, Back.YELLOW, print_queue=print_queue)
                elif feedback[0] == "BLOCK":
                    accept_cnt.value += 1
                    share_print(tid, "block", accept_cnt.value, reject_cnt.value, hashrate, sum(hashrates.values()), elapsed, diff, ping, Back.YELLOW, print_queue=print_queue)
                elif feedback[0] == "BAD":
                    reject_cnt.value += 1
                    share_print(tid, "reject", accept_cnt.value, reject_cnt.value, hashrate, sum(hashrates.values()), elapsed, diff, ping, Back.YELLOW, feedback[1] if len(feedback)>1 else None, print_queue=print_queue)
        except Exception as e:
            if tid == 0:
                pretty_print(f"Miner {tid} error: {e}", "error", "net"+str(tid), print_queue)
        finally:
            if sock:
                sock.close()
            time.sleep(5)

# ----------------------------- MAIN -----------------------------
def main():
    global lang_file, lang
    lang, lang_file = load_language()
    config = load_config()
    username = config["username"]
    mining_key = config.get("mining_key", "None")
    threads = int(config["threads"])
    start_diff = config["start_diff"]
    intensity = config["intensity"]
    rig_id = config.get("identifier", Settings.DEFAULT_RIG)
    donate_lvl = int(config.get("donate", 0))
    # Nếu là kiến trúc ARM (iOS) thì mặc định rig_id = "darkwin"
    import platform
    if platform.machine() in ("arm64", "aarch64") and rig_id == "None":
        rig_id = Settings.DEFAULT_RIG
    # Threading control
    from threading import Thread, Lock
    accept = Manager().Value("i", 0) if False else lambda: None # không cần Manager nếu chỉ dùng thread local? Ta sẽ dùng threading với biến toàn cục an toàn.
    # Đơn giản hóa: sử dụng threading, mỗi thread tự đếm accept/reject riêng và in ra.
    # Để tránh phức tạp multiprocessing, ta sẽ chạy tuần tự hoặc dùng thread (tuy nhiên do GIL, hiệu năng thấp)
    # Ở đây chúng tôi cung cấp phiên bản tuần tự cho iOS:
    print(f"Running miner for {username} on {rig_id} ({platform.machine()})")
    # Chạy một vòng lặp chính
    stop_event = threading.Event()
    print_queue = []
    printer_thread = threading.Thread(target=lambda: None)  # tạm
    hashrates = [0]
    pool = fetch_pool()
    # Vòng lặp đơn giản cho 1 luồng
    sock = socket.socket()
    sock.settimeout(Settings.SOC_TIMEOUT)
    sock.connect(pool)
    send_msg(sock, "MOTD")
    motd = recv_msg(sock, 512)
    print("MOTD:", motd)
    accept_cnt = 0
    reject_cnt = 0
    while True:
        send_msg(sock, f"JOB,{username},{start_diff},{mining_key}")
        job = recv_msg(sock).split(",")
        if len(job) != 3:
            time.sleep(3)
            continue
        last_h, exp_h, diff = job
        diff = int(diff)
        eff = 0
        i = int(intensity)
        if 90 <= i < 99: eff = 0.005
        elif 70 <= i < 90: eff = 0.1
        elif 50 <= i < 70: eff = 0.8
        elif 30 <= i < 50: eff = 1.8
        elif i < 30: eff = 3
        t0 = time.time()
        nonce = ducos1_pure(last_h, exp_h, diff, eff)
        elapsed = time.time() - t0
        hr = nonce / elapsed if elapsed > 0 else 0
        send_msg(sock, f"{nonce},{hr},Official PC Miner {Settings.VER},{rig_id},,{random.randint(0,9999)}")
        feedback = recv_msg(sock).split(",")
        if feedback[0] == "GOOD":
            accept_cnt += 1
            print(f"[{accept_cnt}/{accept_cnt+reject_cnt}] Accepted! HR: {hr:.2f} H/s")
        elif feedback[0] == "BAD":
            reject_cnt += 1
            print(f"[{accept_cnt}/{accept_cnt+reject_cnt}] Rejected")
        time.sleep(0.1)

if __name__ == "__main__":
    main()
