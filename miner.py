#!/usr/bin/env python3
"""
Stratum CPU Miner (SHA-256) – Hỗ trợ threading (fallback) hoặc multiprocessing (nếu khả thi)
Tự động chọn chế độ phù hợp với a-Shell mini
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
from multiprocessing import Process, Value, Lock, Array

# Import module băm
from DSHA2 import double_sha256, hash_block_header, hex_to_bin

# ------------------------------------------------------------
# Cấu trúc dữ liệu chung
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

def compute_target_from_nbits(nbits_hex: str) -> bytes:
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

def difficulty_from_nbits(nbits_hex: str) -> float:
    nbits = int(nbits_hex, 16)
    return 0xFFFF000000000000 / (nbits if nbits != 0 else 1)

# ------------------------------------------------------------
# Phiên bản THREADING (fallback, chạy được nhưng chỉ 1 core)
# ------------------------------------------------------------
class StratumClientThreading:
    """Phiên bản dùng threading (GIL giới hạn) – code gốc đã được tối ưu"""
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
        self.recv_lock = threading.Lock()

        self.extranonce1 = None
        self.extranonce2_size = 4
        self.extranonce2_counter = 0
        self.extranonce2_lock = threading.Lock()

        self.current_job = None
        self.current_work = None
        self.work_cond = threading.Condition()

        self.io_thread = None
        self.miner_threads = []
        self.stats_thread = None

        self.total_hashes = 0
        self.hashrate_lock = threading.Lock()
        self.last_report_time = time.time()
        self.last_total_hashes = 0
        self.accepted_shares = 0
        self.rejected_shares = 0
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
        sub_id = random.randint(1, 100000)
        sub_msg = json.dumps({"id": sub_id, "method": "mining.subscribe", "params": ["cpuminer-py/1.0"]})
        self.socket.sendall((sub_msg + "\n").encode())
        print("[STRATUM] Sent subscribe")

    def _main_loop(self):
        self.socket.settimeout(1)
        last_ping = time.time()
        while self.running:
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
                    self.extranonce1 = msg["params"][0]
                    self.extranonce2_size = msg["params"][1]
                    print(f"[EXTRANONCE] set: {self.extranonce1} size={self.extranonce2_size}")
                else:
                    print(f"[POOL] Method chưa xử lý: {method}")
            elif "id" in msg:
                if "result" in msg and isinstance(msg["result"], list) and len(msg["result"]) >= 3:
                    if isinstance(msg["result"][1], str) and isinstance(msg["result"][2], int):
                        self.extranonce1 = msg["result"][1]
                        self.extranonce2_size = msg["result"][2]
                        print(f"[SUBSCRIBE] OK, extranonce1={self.extranonce1} size={self.extranonce2_size}")
                        auth_msg = json.dumps({"id": 2, "method": "mining.authorize", "params": [self.username, self.password]})
                        self.socket.sendall((auth_msg + "\n").encode())
                        print(f"[STRATUM] Sent authorize for {self.username}")
                        return
                if msg.get("id") == 2:
                    if msg.get("result") is True:
                        self.authorized = True
                        print("[AUTH] Authorized successfully")
                    else:
                        print("[AUTH] FAILED!")
                    return
                if msg.get("id") == 4:
                    if msg.get("result") is True:
                        self.accepted_shares += 1
                        print("[SHARE] ACCEPTED")
                    else:
                        self.rejected_shares += 1
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
                header = header80[:76] + struct.pack('<I', nonce)
                hash_result = hash_block_header(header)
                with self.hashrate_lock:
                    self.total_hashes += 1
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
# Phiên bản MULTIPROCESSING (cố gắng dùng đa nhân)
# ------------------------------------------------------------
class StratumClientMP:
    def __init__(self, host, port, username, password, num_procs):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.num_procs = num_procs
        self.socket = None
        self.running = Value('b', True)
        self.send_queue = mp.Queue()
        self.recv_buffer = bytearray()
        self.recv_lock = threading.Lock()

        self.extranonce1 = Array('c', 64)
        self.extranonce2_size = Value('i', 4)
        self.extranonce2_counter = Value('Q', 0)
        self.extranonce2_lock = Lock()

        self.work_available = Value('b', False)
        self.work_cond = threading.Condition()

        self.io_thread = None
        self.miner_procs = []
        self.stats_thread = None

        self.total_hashes = Value('Q', 0)
        self.accepted_shares = Value('Q', 0)
        self.rejected_shares = Value('Q', 0)
        self.last_report_time = time.time()
        self.last_total_hashes = 0

        self.manager = mp.Manager()
        self.shared_job = self.manager.dict()
        self.shared_work = self.manager.dict()

    def start(self):
        self.io_thread = threading.Thread(target=self._io_loop, name="IOThread")
        self.io_thread.start()
        for i in range(self.num_procs):
            p = Process(target=self._miner_process, args=(i,))
            p.start()
            self.miner_procs.append(p)
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
        for p in self.miner_procs:
            p.join(timeout=2)
        if self.stats_thread:
            self.stats_thread.join(timeout=2)

    def send(self, message):
        self.send_queue.put(message + "\n")

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
            except:
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
                    print(f"[DIFF] Độ khó set thành {msg['params'][0]}")
                elif method == "mining.set_extranonce":
                    ext1 = msg["params"][0]
                    with self.extranonce1.get_lock():
                        self.extranonce1.value = ext1.encode()[:64]
                    self.extranonce2_size.value = msg["params"][1]
                    print(f"[EXTRANONCE] set: {ext1} size={self.extranonce2_size.value}")
                else:
                    print(f"[POOL] Method: {method}")
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
                print(f"[POOL] Unknown id {msg['id']}: {msg}")
            else:
                print(f"[POOL] Cannot parse: {line}")
        except Exception as e:
            print(f"[PARSE] Error: {e} | line: {line}")

    def _handle_notify(self, params):
        if len(params) < 9:
            return
        job_id, prevhash, coinb1, coinb2 = params[0], params[1], params[2], params[3]
        merkle_branch = params[4] if isinstance(params[4], list) else []
        version, nbits, ntime, clean = params[5], params[6], params[7], params[8]
        target = compute_target_from_nbits(nbits)
        difficulty = difficulty_from_nbits(nbits)
        self.shared_job.clear()
        self.shared_job.update({
            'job_id': job_id, 'prevhash': prevhash, 'coinb1': coinb1, 'coinb2': coinb2,
            'merkle_branch': merkle_branch, 'version': version, 'nbits': nbits,
            'ntime': ntime, 'clean': clean
        })
        self.shared_work.clear()
        self.shared_work.update({
            'job_id': job_id, 'nbits': nbits, 'target': target,
            'difficulty': difficulty, 'clean': clean
        })
        with self.work_cond:
            self.work_available.value = True
            self.work_cond.notify_all()
        print(f"[JOB] New work #{job_id} diff={difficulty:.2f} clean={clean}")
        if clean:
            with self.extranonce2_lock:
                self.extranonce2_counter.value = 0

    def _build_merkle_root(self, coinbase_bin, merkle_branch):
        h = double_sha256(coinbase_bin)
        for branch_hex in merkle_branch:
            combined = h + hex_to_bin(branch_hex)
            h = double_sha256(combined)
        return h

    def _miner_process(self, proc_id):
        step = 65536
        nonce_start = proc_id * step
        nonce_end = nonce_start + step - 1
        while self.running.value:
            if not self.work_available.value:
                time.sleep(0.1)
                continue
            # Lấy dữ liệu công việc (copy)
            job = self.shared_job.copy()
            work = self.shared_work.copy()
            if not job or not work:
                continue
            with self.extranonce2_lock:
                ext2 = self.extranonce2_counter.value
                self.extranonce2_counter.value += 1
            # Lấy extranonce1
            ext1 = self.extranonce1.value.decode().strip('\x00')
            ext2_hex = format(ext2, f'0{self.extranonce2_size.value*2}x')
            coinbase_hex = job['coinb1'] + ext1 + ext2_hex + job['coinb2']
            coinbase_bin = hex_to_bin(coinbase_hex)
            merkle_root = self._build_merkle_root(coinbase_bin, job['merkle_branch'])
            version_le = struct.pack('<I', int(job['version'], 16))
            prevhash_rev = hex_to_bin(job['prevhash'])[::-1]
            merkle_root_rev = merkle_root[::-1]
            ntime_le = struct.pack('<I', int(job['ntime'], 16))
            nbits_le = struct.pack('<I', int(job['nbits'], 16))
            header80 = version_le + prevhash_rev + merkle_root_rev + ntime_le + nbits_le + b'\x00\x00\x00\x00'
            nonce = nonce_start
            target = work['target']
            while nonce <= nonce_end and self.running.value:
                header = header80[:76] + struct.pack('<I', nonce)
                h = hash_block_header(header)
                with self.total_hashes.get_lock():
                    self.total_hashes.value += 1
                if h <= target:
                    print(f"\n[FOUND] Process {proc_id} nonce=0x{nonce:08x} ext2={ext2}")
                    submit_params = [
                        self.username,
                        work['job_id'],
                        format(ext2, f'0{self.extranonce2_size.value*2}x'),
                        job['ntime'],
                        format(nonce, '08x')
                    ]
                    self.send(json.dumps({"id": 4, "method": "mining.submit", "params": submit_params}))
                    break
                nonce += 1

    def _stats_loop(self):
        while self.running.value:
            time.sleep(2)
            now = time.time()
            elapsed = now - self.last_report_time
            cur = self.total_hashes.value
            hashes = cur - self.last_total_hashes
            rate = hashes / elapsed if elapsed > 0 else 0
            print(f"[STATS] {rate/1e6:.2f} MH/s | Total: {cur} | Accept/Rej: {self.accepted_shares.value}/{self.rejected_shares.value}")
            self.last_total_hashes = cur
            self.last_report_time = now

# ------------------------------------------------------------
# Main: Tự động chọn chế độ
# ------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="Stratum CPU Miner (SHA-256) - Auto multiprocessing/threading")
    parser.add_argument("-a", "--address", required=True, help="Wallet address (e.g., XNO:... or BTC:...)")
    parser.add_argument("-w", "--worker", required=True, help="Worker name")
    parser.add_argument("-o", "--pool", default="stratum.slushpool.com", help="Pool host")
    parser.add_argument("-p", "--port", type=int, default=3333, help="Pool port")
    parser.add_argument("-t", "--threads", type=int, default=0, help="Number of processes/threads")
    parser.add_argument("--force-mp", action="store_true", help="Force multiprocessing (may fail)")
    args = parser.parse_args()

    username = f"{args.address}.{args.worker}"
    if args.threads <= 0:
        try:
            args.threads = mp.cpu_count()
        except:
            args.threads = 2

    use_mp = args.force_mp
    if use_mp:
        try:
            # Kiểm tra multiprocessing có khả dụng không
            q = mp.Queue()
            p = mp.Process(target=lambda: None)
            p.start()
            p.join()
            print(f"[INFO] Using multiprocessing with {args.threads} processes")
            client = StratumClientMP(args.pool, args.port, username, "x", args.threads)
        except Exception as e:
            print(f"[WARN] Multiprocessing not available ({e}), falling back to threading")
            use_mp = False

    if not use_mp:
        print(f"[INFO] Using threading (GIL limited) with {args.threads} threads")
        client = StratumClientThreading(args.pool, args.port, username, "x", args.threads)

    print("=== Stratum CPU Miner (SHA-256) ===\n"
          f"Pool: {args.pool}:{args.port}\n"
          f"User: {username}\n"
          f"Workers: {args.threads}\n")

    try:
        client.start()
        while client.running if isinstance(client, StratumClientThreading) else client.running.value:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nStopping miner...")
        client.stop()
        sys.exit(0)

if __name__ == "__main__":
    mp.freeze_support()
    main()
