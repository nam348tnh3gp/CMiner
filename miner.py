#!/usr/bin/env python3
"""
Stratum CPU Miner (SHA-256) – bản Python thuần
Tương thích với unmineable.com và các pool Stratum chuẩn
"""

import socket
import json
import threading
import time
import argparse
import sys
import struct
import random
from queue import Queue, Empty

# Import module băm
from DSHA2 import double_sha256, hash_block_header, hex_to_bin

# ------------------------------------------------------------
# Cấu trúc dữ liệu
# ------------------------------------------------------------
class RawJob:
    def __init__(self, job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean):
        self.job_id = job_id
        self.prevhash = prevhash
        self.coinb1 = coinb1
        self.coinb2 = coinb2
        self.merkle_branch = merkle_branch
        self.version = version
        self.nbits = nbits
        self.ntime = ntime
        self.clean = clean

class Work:
    def __init__(self, job_id, nbits, target, difficulty, clean):
        self.job_id = job_id
        self.nbits = nbits
        self.target = target
        self.difficulty = difficulty
        self.clean = clean

# ------------------------------------------------------------
# Hàm tiện ích
# ------------------------------------------------------------
def compute_target_from_nbits(nbits_hex):
    """Chuyển nbits (hex, big‑endian) thành target 32 byte (big‑endian)"""
    nbits = int(nbits_hex, 16)
    exp = nbits >> 24
    mant = nbits & 0x00FFFFFF
    target = bytearray(32)
    if exp <= 32:
        shift = 32 - exp
        target[shift]   = (mant >> 16) & 0xFF
        target[shift+1] = (mant >> 8) & 0xFF
        target[shift+2] = mant & 0xFF
    return bytes(target)

def difficulty_from_nbits(nbits_hex):
    nbits = int(nbits_hex, 16)
    return 0xFFFF000000000000 / (nbits if nbits != 0 else 1)

# ------------------------------------------------------------
# Lớp StratumClient
# ------------------------------------------------------------
class StratumClient:
    def __init__(self, host, port, username, password, num_threads):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.num_threads = num_threads
        self.socket = None
        self.running = False
        self.send_queue = Queue()
        self.recv_buffer = bytearray()

        # Stratum state
        self.extranonce1 = None
        self.extranonce2_size = 4
        self.extranonce2_counter = 0
        self.extranonce2_lock = threading.Lock()

        self.current_job = None
        self.current_work = None
        self.work_cond = threading.Condition()

        # Các luồng
        self.io_thread = None
        self.miner_threads = []
        self.stats_thread = None

        # Thống kê
        self.total_hashes = 0
        self.hashrate_lock = threading.Lock()
        self.last_report_time = time.time()
        self.last_total_hashes = 0
        self.accepted_shares = 0
        self.rejected_shares = 0
        self.subscribed = False
        self.authorized = False

    def start(self):
        self.running = True
        self.io_thread = threading.Thread(target=self._io_loop, name="IOThread")
        self.io_thread.start()
        for i in range(self.num_threads):
            t = threading.Thread(target=self._miner_loop, args=(i,), name=f"Miner-{i}")
            t.start()
            self.miner_threads.append(t)
        self.stats_thread = threading.Thread(target=self._stats_loop, name="StatsThread")
        self.stats_thread.start()

    def stop(self):
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        if self.io_thread:
            self.io_thread.join(timeout=2)
        for t in self.miner_threads:
            t.join(timeout=1)
        if self.stats_thread:
            self.stats_thread.join(timeout=1)

    def send(self, message):
        self.send_queue.put(message + "\n")

    # --------------------------------------------------------
    # Xử lý mạng
    # --------------------------------------------------------
    def _io_loop(self):
        while self.running:
            try:
                self._connect()
                self._handshake()
                self._main_loop()
            except Exception as e:
                print(f"[IO] Lỗi: {e}. Kết nối lại sau 5s...")
                time.sleep(5)

    def _connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect((self.host, self.port))
        print(f"[NET] Đã kết nối tới {self.host}:{self.port}")

    def _handshake(self):
        # mining.subscribe
        sub_id = random.randint(1, 100000)
        sub_msg = json.dumps({"id": sub_id, "method": "mining.subscribe", "params": ["cpuminer-py/1.0"]})
        self.socket.sendall((sub_msg + "\n").encode())
        print("[STRATUM] Sent subscribe")

    def _main_loop(self):
        self.socket.settimeout(1)
        last_ping = time.time()
        while self.running:
            # Gửi tin nhắn trong hàng đợi
            try:
                while True:
                    msg = self.send_queue.get_nowait()
                    self.socket.sendall(msg.encode())
            except Empty:
                pass

            # Nhận dữ liệu
            try:
                data = self.socket.recv(4096)
                if not data:
                    print("[NET] Socket đóng")
                    break
                self.recv_buffer.extend(data)
                while b'\n' in self.recv_buffer:
                    line, self.recv_buffer = self.recv_buffer.split(b'\n', 1)
                    if line:
                        self._process_line(line.decode().strip())
            except socket.timeout:
                pass
            except Exception as e:
                print(f"[NET] Lỗi đọc: {e}")
                break

            # Ping mỗi 30 giây
            if time.time() - last_ping > 30:
                ping_msg = json.dumps({"id": 0, "method": "mining.ping", "params": []})
                self.socket.sendall((ping_msg + "\n").encode())
                last_ping = time.time()

            time.sleep(0.01)

    def _process_line(self, line):
        try:
            msg = json.loads(line)
            # Xử lý theo method
            if "method" in msg:
                method = msg["method"]
                if method == "mining.notify":
                    self._handle_notify(msg["params"])
                elif method == "mining.set_difficulty":
                    diff = msg["params"][0]
                    print(f"[DIFF] Độ khó set thành {diff}")
                elif method == "mining.set_extranonce":
                    self.extranonce1 = msg["params"][0]
                    self.extranonce2_size = msg["params"][1]
                    print(f"[EXTRANONCE] set: {self.extranonce1} size={self.extranonce2_size}")
                else:
                    print(f"[POOL] Method chưa xử lý: {method}")
            # Xử lý phản hồi (có id)
            elif "id" in msg:
                # Phản hồi mining.subscribe: result có dạng [[...], extranonce1, extranonce2_size]
                if "result" in msg and isinstance(msg["result"], list) and len(msg["result"]) >= 3:
                    # Kiểm tra nếu phần tử thứ hai là string (extranonce1) và thứ ba là int (extranonce2_size)
                    if isinstance(msg["result"][1], str) and isinstance(msg["result"][2], int):
                        self.extranonce1 = msg["result"][1]
                        self.extranonce2_size = msg["result"][2]
                        print(f"[SUBSCRIBE] OK, extranonce1={self.extranonce1} size={self.extranonce2_size}")
                        # Gửi authorize ngay
                        auth_msg = json.dumps({"id": 2, "method": "mining.authorize", "params": [self.username, self.password]})
                        self.socket.sendall((auth_msg + "\n").encode())
                        print(f"[STRATUM] Sent authorize for {self.username}")
                        self.subscribed = True
                        return
                # Phản hồi mining.authorize (id=2)
                if msg.get("id") == 2:
                    if msg.get("result") is True:
                        self.authorized = True
                        print("[AUTH] Authorized successfully")
                    else:
                        print("[AUTH] FAILED!")
                    return
                # Phản hồi mining.submit (id=4)
                if msg.get("id") == 4:
                    if msg.get("result") is True:
                        self.accepted_shares += 1
                        print("[SHARE] ACCEPTED")
                    else:
                        self.rejected_shares += 1
                        print(f"[SHARE] REJECTED: {msg.get('error')}")
                    return
                # Ping response (id=0)
                if msg.get("id") == 0:
                    return
                # Các message khác có id
                print(f"[POOL] Unknown message id {msg['id']}: {msg}")
            else:
                print(f"[POOL] Cannot parse: {line}")
        except Exception as e:
            print(f"[PARSE] Error: {e} | line: {line}")

    def _handle_notify(self, params):
        if len(params) < 9:
            return
        job_id = params[0]
        prevhash = params[1]
        coinb1 = params[2]
        coinb2 = params[3]
        merkle_branch = params[4] if isinstance(params[4], list) else []
        version = params[5]
        nbits = params[6]
        ntime = params[7]
        clean = params[8]

        job = RawJob(job_id, prevhash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean)
        target = compute_target_from_nbits(nbits)
        difficulty = difficulty_from_nbits(nbits)
        work = Work(job_id, nbits, target, difficulty, clean)

        with self.work_cond:
            self.current_job = job
            self.current_work = work
            self.work_cond.notify_all()
        print(f"[JOB] New work #{job_id} diff={difficulty:.2f} clean={clean}")
        if clean:
            with self.extranonce2_lock:
                self.extranonce2_counter = 0

    # --------------------------------------------------------
    # Xây dựng header và đào
    # --------------------------------------------------------
    def _build_merkle_root(self, coinbase_bin, merkle_branch):
        h = double_sha256(coinbase_bin)
        for branch_hex in merkle_branch:
            branch_bin = hex_to_bin(branch_hex)
            combined = h + branch_bin
            h = double_sha256(combined)
        return h

    def _build_header(self, job, extranonce2_val):
        extranonce2_hex = format(extranonce2_val, f'0{self.extranonce2_size*2}x')
        coinbase_hex = job.coinb1 + self.extranonce1 + extranonce2_hex + job.coinb2
        coinbase_bin = hex_to_bin(coinbase_hex)

        merkle_root = self._build_merkle_root(coinbase_bin, job.merkle_branch)

        version = int(job.version, 16)
        version_le = struct.pack('<I', version)

        prevhash_bin = hex_to_bin(job.prevhash)
        prevhash_rev = prevhash_bin[::-1]

        merkle_root_rev = merkle_root[::-1]

        ntime_val = int(job.ntime, 16)
        ntime_le = struct.pack('<I', ntime_val)

        nbits_val = int(job.nbits, 16)
        nbits_le = struct.pack('<I', nbits_val)

        # Header 80 bytes, nonce cuối cùng sẽ được ghi đè
        header = version_le + prevhash_rev + merkle_root_rev + ntime_le + nbits_le + b'\x00\x00\x00\x00'
        return header

    def _miner_loop(self, thread_id):
        step = 65536
        nonce_start = thread_id * step
        nonce_end = nonce_start + step - 1

        while self.running:
            with self.work_cond:
                while self.current_work is None and self.running:
                    self.work_cond.wait(timeout=1)
                if not self.running:
                    break
                work = self.current_work
                job = self.current_job

            with self.extranonce2_lock:
                extranonce2 = self.extranonce2_counter
                self.extranonce2_counter += 1

            header80 = self._build_header(job, extranonce2)
            nonce = nonce_start
            while nonce <= nonce_end and self.running:
                # Ghi nonce vào 4 byte cuối (little-endian)
                header = header80[:76] + struct.pack('<I', nonce)
                hash_result = hash_block_header(header)

                with self.hashrate_lock:
                    self.total_hashes += 1

                # So sánh target (big-endian)
                if hash_result <= work.target:
                    print(f"[FOUND] Thread {thread_id} nonce=0x{nonce:08x} extranonce2={extranonce2}")
                    submit_params = [
                        self.username,
                        work.job_id,
                        format(extranonce2, f'0{self.extranonce2_size*2}x'),
                        job.ntime,
                        format(nonce, '08x')
                    ]
                    submit_msg = json.dumps({"id": 4, "method": "mining.submit", "params": submit_params})
                    self.send(submit_msg)
                    break
                nonce += 1

    # --------------------------------------------------------
    # Thống kê
    # --------------------------------------------------------
    def _stats_loop(self):
        while self.running:
            time.sleep(2)
            with self.hashrate_lock:
                now = time.time()
                elapsed = now - self.last_report_time
                hashes = self.total_hashes - self.last_total_hashes
                rate = hashes / elapsed if elapsed > 0 else 0
                print(f"[STATS] {rate/1e6:.2f} MH/s | Total: {self.total_hashes} | Accept/Rej: {self.accepted_shares}/{self.rejected_shares}")
                self.last_report_time = now
                self.last_total_hashes = self.total_hashes

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Stratum CPU Miner (SHA-256) - Python version")
    parser.add_argument("-a", "--address", required=True, help="BTC address or wallet")
    parser.add_argument("-w", "--worker", required=True, help="Worker name")
    parser.add_argument("-o", "--pool", default="stratum.slushpool.com", help="Pool host")
    parser.add_argument("-p", "--port", type=int, default=3333, help="Pool port")
    parser.add_argument("-t", "--threads", type=int, default=0, help="Number of threads (auto = CPU cores)")
    args = parser.parse_args()

    username = f"{args.address}.{args.worker}"
    if args.threads <= 0:
        args.threads = max(1, threading.active_count() * 2)

    print("=== Stratum CPU Miner (SHA-256) ===\n"
          f"Pool: {args.pool}:{args.port}\n"
          f"User: {username}\n"
          f"Threads: {args.threads}\n")

    client = StratumClient(args.pool, args.port, username, "x", args.threads)
    try:
        client.start()
        while client.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping miner...")
        client.stop()
        sys.exit(0)

if __name__ == "__main__":
    main()
