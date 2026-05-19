#!/usr/bin/env python3
"""
Stratum CPU Miner (SHA-256) – Đa tiến trình thực sự
Hỗ trợ threading fallback nếu multiprocessing không khả dụng
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
import multiprocessing as mp
from multiprocessing import Process, Queue as MPQueue, Value, Lock

# Import module băm
from DSHA2 import double_sha256, hash_block_header, hex_to_bin

# ... (các lớp RawJob, Work, hàm compute_target_from_nbits, difficulty_from_nbits giữ nguyên) ...

class StratumClientMP:
    """Phiên bản dùng multiprocessing để chạy thực sự đa nhân"""
    def __init__(self, host, port, username, password, num_processes):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.num_processes = num_processes
        self.socket = None
        self.running = Value('b', True)  # shared flag
        self.send_queue = MPQueue()
        self.recv_buffer = bytearray()
        self.recv_lock = threading.Lock()  # chỉ dùng trong luồng IO

        # Stratum state (shared)
        self.extranonce1 = mp.Array('c', 64)  # chuỗi tối đa 64 byte
        self.extranonce2_size = Value('i', 4)
        self.extranonce2_counter = Value('Q', 0)  # unsigned long long
        self.extranonce2_lock = Lock()

        # Work state (shared)
        self.current_job = None  # sẽ dùng Manager dict
        self.current_work = None
        self.work_available = Value('b', False)
        self.work_cond = threading.Condition()  # chỉ dùng trong luồng IO

        self.io_thread = None
        self.miner_processes = []
        self.stats_thread = None

        # Thống kê (shared)
        self.total_hashes = Value('Q', 0)
        self.accepted_shares = Value('Q', 0)
        self.rejected_shares = Value('Q', 0)
        self.last_report_time = time.time()
        self.last_total_hashes = 0

        # Dùng Manager để share job/work (vì chứa list, string)
        self.manager = mp.Manager()
        self.shared_job = self.manager.dict()
        self.shared_work = self.manager.dict()

    def start(self):
        self.io_thread = threading.Thread(target=self._io_loop, name="IOThread")
        self.io_thread.start()
        for i in range(self.num_processes):
            p = Process(target=self._miner_process, args=(i,))
            p.start()
            self.miner_processes.append(p)
        self.stats_thread = threading.Thread(target=self._stats_loop, name="StatsThread")
        self.stats_thread.start()

    def stop(self):
        with self.running.get_lock():
            self.running.value = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        if self.io_thread:
            self.io_thread.join(timeout=2)
        for p in self.miner_processes:
            p.join(timeout=2)
        if self.stats_thread:
            self.stats_thread.join(timeout=2)

    def send(self, message):
        self.send_queue.put(message + "\n")

    # --------------------------------------------------------
    # Xử lý mạng (giữ nguyên gần như cũ, chỉ sửa shared state)
    # --------------------------------------------------------
    def _io_loop(self):
        while self.running.value:
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
        sub_id = random.randint(1, 100000)
        sub_msg = json.dumps({"id": sub_id, "method": "mining.subscribe", "params": ["cpuminer-py/1.0"]})
        self.socket.sendall((sub_msg + "\n").encode())
        print("[STRATUM] Sent subscribe")

    def _main_loop(self):
        self.socket.settimeout(1)
        last_ping = time.time()
        while self.running.value:
            try:
                while True:
                    msg = self.send_queue.get_nowait()
                    self.socket.sendall(msg.encode())
            except Empty:
                pass

            try:
                data = self.socket.recv(4096)
                if not data:
                    print("[NET] Socket đóng")
                    break
                with self.recv_lock:
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

            if time.time() - last_ping > 30:
                ping_msg = json.dumps({"id": 0, "method": "mining.ping", "params": []})
                self.socket.sendall((ping_msg + "\n").encode())
                last_ping = time.time()

            time.sleep(0.01)

    def _process_line(self, line):
        try:
            msg = json.loads(line)
            if "method" in msg:
                method = msg["method"]
                if method == "mining.notify":
                    self._handle_notify(msg["params"])
                elif method == "mining.set_difficulty":
                    diff = msg["params"][0]
                    print(f"[DIFF] Độ khó set thành {diff}")
                elif method == "mining.set_extranonce":
                    ext1 = msg["params"][0]
                    with self.extranonce1.get_lock():
                        self.extranonce1.value = ext1.encode()[:64]
                    self.extranonce2_size.value = msg["params"][1]
                    print(f"[EXTRANONCE] set: {ext1} size={self.extranonce2_size.value}")
                else:
                    print(f"[POOL] Method chưa xử lý: {method}")
            elif "id" in msg:
                if "result" in msg and isinstance(msg["result"], list) and len(msg["result"]) >= 3:
                    if isinstance(msg["result"][1], str) and isinstance(msg["result"][2], int):
                        ext1 = msg["result"][1]
                        with self.extranonce1.get_lock():
                            self.extranonce1.value = ext1.encode()[:64]
                        self.extranonce2_size.value = msg["result"][2]
                        print(f"[SUBSCRIBE] OK, extranonce1={ext1} size={self.extranonce2_size.value}")
                        auth_msg = json.dumps({"id": 2, "method": "mining.authorize", "params": [self.username, self.password]})
                        self.socket.sendall((auth_msg + "\n").encode())
                        print(f"[STRATUM] Sent authorize for {self.username}")
                        return
                if msg.get("id") == 2:
                    if msg.get("result") is True:
                        print("[AUTH] Authorized successfully")
                    else:
                        print("[AUTH] FAILED!")
                    return
                if msg.get("id") == 4:
                    if msg.get("result") is True:
                        with self.accepted_shares.get_lock():
                            self.accepted_shares.value += 1
                        print("[SHARE] ACCEPTED")
                    else:
                        with self.rejected_shares.get_lock():
                            self.rejected_shares.value += 1
                        print(f"[SHARE] REJECTED: {msg.get('error')}")
                    return
                if msg.get("id") == 0:
                    return
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

        target = compute_target_from_nbits(nbits)
        difficulty = difficulty_from_nbits(nbits)

        # Cập nhật shared job và work
        self.shared_job.clear()
        self.shared_job.update({
            'job_id': job_id,
            'prevhash': prevhash,
            'coinb1': coinb1,
            'coinb2': coinb2,
            'merkle_branch': merkle_branch,
            'version': version,
            'nbits': nbits,
            'ntime': ntime,
            'clean': clean
        })
        self.shared_work.clear()
        self.shared_work.update({
            'job_id': job_id,
            'nbits': nbits,
            'target': target,
            'difficulty': difficulty,
            'clean': clean
        })
        with self.work_cond:
            self.work_available.value = True
            self.work_cond.notify_all()
        print(f"[JOB] New work #{job_id} diff={difficulty:.2f} clean={clean}")
        if clean:
            with self.extranonce2_lock:
                self.extranonce2_counter.value = 0

    # --------------------------------------------------------
    # Tiến trình đào (mỗi tiến trình chạy độc lập, đọc shared state)
    # --------------------------------------------------------
    def _miner_process(self, process_id):
        # Mỗi process có random nonce start riêng
        step = 65536
        nonce_start = process_id * step
        nonce_end = nonce_start + step - 1
        local_hash_count = 0

        while self.running.value:
            # Chờ work có sẵn (không dùng condition variable giữa các process, dùng busy wait + sleep)
            while not self.work_available.value and self.running.value:
                time.sleep(0.1)
            if not self.running.value:
                break

            # Lấy job và work hiện tại (copy từ shared dict)
            job_data = self.shared_job.copy()
            work_data = self.shared_work.copy()
            if not job_data or not work_data:
                continue

            # Lấy extranonce2 (atomic increment)
            with self.extranonce2_lock:
                extranonce2 = self.extranonce2_counter.value
                self.extranonce2_counter.value += 1

            # Build header (cần extranonce1 và extranonce2_size)
            extranonce1_str = self.extranonce1.value.decode().strip('\x00')
            extranonce2_hex = format(extranonce2, f'0{self.extranonce2_size.value*2}x')
            coinbase_hex = job_data['coinb1'] + extranonce1_str + extranonce2_hex + job_data['coinb2']
            coinbase_bin = hex_to_bin(coinbase_hex)
            merkle_root = self._build_merkle_root(coinbase_bin, job_data['merkle_branch'])
            version = int(job_data['version'], 16)
            version_le = struct.pack('<I', version)
            prevhash_bin = hex_to_bin(job_data['prevhash'])
            prevhash_rev = prevhash_bin[::-1]
            merkle_root_rev = merkle_root[::-1]
            ntime_val = int(job_data['ntime'], 16)
            ntime_le = struct.pack('<I', ntime_val)
            nbits_val = int(job_data['nbits'], 16)
            nbits_le = struct.pack('<I', nbits_val)
            header80 = version_le + prevhash_rev + merkle_root_rev + ntime_le + nbits_le + b'\x00\x00\x00\x00'

            nonce = nonce_start
            while nonce <= nonce_end and self.running.value:
                header = header80[:76] + struct.pack('<I', nonce)
                hash_result = hash_block_header(header)
                with self.total_hashes.get_lock():
                    self.total_hashes.value += 1
                local_hash_count += 1

                if hash_result <= work_data['target']:
                    print(f"\n[FOUND] Process {process_id} nonce=0x{nonce:08x} extranonce2={extranonce2}")
                    submit_params = [
                        self.username,
                        work_data['job_id'],
                        format(extranonce2, f'0{self.extranonce2_size.value*2}x'),
                        job_data['ntime'],
                        format(nonce, '08x')
                    ]
                    submit_msg = json.dumps({"id": 4, "method": "mining.submit", "params": submit_params})
                    self.send(submit_msg)
                    break
                nonce += 1

    def _build_merkle_root(self, coinbase_bin, merkle_branch):
        h = double_sha256(coinbase_bin)
        for branch_hex in merkle_branch:
            branch_bin = hex_to_bin(branch_hex)
            combined = h + branch_bin
            h = double_sha256(combined)
        return h

    def _stats_loop(self):
        while self.running.value:
            time.sleep(2)
            now = time.time()
            elapsed = now - self.last_report_time
            with self.total_hashes.get_lock():
                cur = self.total_hashes.value
            hashes = cur - self.last_total_hashes
            rate = hashes / elapsed if elapsed > 0 else 0
            with self.accepted_shares.get_lock():
                acc = self.accepted_shares.value
            with self.rejected_shares.get_lock():
                rej = self.rejected_shares.value
            print(f"[STATS] {rate/1e6:.2f} MH/s | Total: {cur} | Accept/Rej: {acc}/{rej}")
            self.last_total_hashes = cur
            self.last_report_time = now


# ------------------------------------------------------------
# Main: chọn phương thức (multiprocessing hoặc threading fallback)
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Stratum CPU Miner (SHA-256)")
    parser.add_argument("-a", "--address", required=True, help="Wallet address (e.g., XNO:... or BTC:...)")
    parser.add_argument("-w", "--worker", required=True, help="Worker name")
    parser.add_argument("-o", "--pool", default="stratum.slushpool.com", help="Pool host")
    parser.add_argument("-p", "--port", type=int, default=3333, help="Pool port")
    parser.add_argument("-t", "--threads", type=int, default=0, help="Number of processes/threads")
    parser.add_argument("--use-multiprocessing", action="store_true", help="Force use multiprocessing (true parallelism)")
    args = parser.parse_args()

    username = f"{args.address}.{args.worker}"
    if args.threads <= 0:
        try:
            args.threads = mp.cpu_count()
        except:
            args.threads = 2

    # Kiểm tra khả năng dùng multiprocessing
    use_mp = args.use_multiprocessing
    if use_mp:
        try:
            test = mp.Process(target=lambda: None)
            test.start()
            test.join()
            print(f"[INFO] Using multiprocessing with {args.threads} processes")
        except Exception as e:
            print(f"[WARN] Multiprocessing not available ({e}), falling back to threading")
            use_mp = False

    if use_mp:
        client = StratumClientMP(args.pool, args.port, username, "x", args.threads)
    else:
        # Fallback về phiên bản threading cũ (đã có trong code của bạn)
        print(f"[INFO] Using threading (GIL limited) with {args.threads} threads")
        # Ở đây import hoặc định nghĩa lại StratumClient threading cũ
        # Để tránh trùng tên, tôi giả sử bạn có lớp StratumClient cũ
        # Nếu không, bạn có thể đặt lại tên class cũ là StratumClientThreading
        from miner_old import StratumClient as StratumClientThreading
        client = StratumClientThreading(args.pool, args.port, username, "x", args.threads)

    print("=== Stratum CPU Miner (SHA-256) ===\n"
          f"Pool: {args.pool}:{args.port}\n"
          f"User: {username}\n"
          f"Processes/Threads: {args.threads}\n")

    try:
        client.start()
        while client.running.value if use_mp else client.running:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping miner...")
        client.stop()
        sys.exit(0)

if __name__ == "__main__":
    # Hỗ trợ multiprocessing trên Windows/macOS
    mp.freeze_support()
    main()
