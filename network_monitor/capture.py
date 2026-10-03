import os
import math
import queue
import signal
import shutil
import subprocess
import threading
import time
from collections import deque
from pathlib import Path
from .features import FIELDS, Window, parse_packet

def tshark_path(explicit=None):
    candidate = explicit or shutil.which('tshark')
    if not candidate and os.name == 'nt':
        standard = Path(os.environ.get('ProgramFiles', r'C:\Program Files')) / 'Wireshark' / 'tshark.exe'
        if standard.is_file():
            candidate = str(standard)
    if not candidate or not Path(candidate).is_file():
        raise ValueError('TShark not found. Install Wireshark with TShark and Npcap, or pass --tshark PATH.')
    return str(candidate)

def interfaces(explicit=None):
    result = subprocess.run([tshark_path(explicit), '-D'], text=True, capture_output=True)
    if result.returncode:
        raise ValueError(result.stderr.strip() or 'TShark could not list interfaces.')
    return result.stdout.strip()

class TsharkReader:
    def __init__(self, arguments):
        self.arguments = arguments
        self.items = queue.Queue(maxsize=8192)
        self.errors = deque(maxlen=25)
        self.stop = threading.Event()

    def __enter__(self):
        self.process = subprocess.Popen(self.arguments, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, text=True, encoding='utf-8', errors='replace',
                        bufsize=1, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0)
        def read_stdout():
            for line in self.process.stdout:
                if self.stop.is_set():
                    break
                event = (time.monotonic(), line)
                while not self.stop.is_set():
                    try:
                        self.items.put(event, timeout=.2)
                        break
                    except queue.Full:
                        continue
        def read_stderr():
            for line in self.process.stderr:
                self.errors.append(line.strip())
        self.threads = [threading.Thread(target=read_stdout, daemon=True),
                        threading.Thread(target=read_stderr, daemon=True)]
        for thread in self.threads:
            thread.start()
        return self

    def __exit__(self, *unused):
        self.stop.set()
        if self.process.poll() is None:
            if os.name == 'nt':
                try:
                    self.process.send_signal(signal.CTRL_BREAK_EVENT)
                except OSError:
                    self.process.terminate()
            else:
                self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=3)
        for thread in self.threads:
            thread.join(timeout=2)
        self.process.stdout.close(); self.process.stderr.close()

    def failure(self):
        return '\n'.join(self.errors) or 'TShark exited. Check the interface and capture permissions.'

def field_arguments(explicit):
    args = [tshark_path(explicit), '-n', '-l', '-T', 'fields',
            '-E', 'separator=/t', '-E', 'occurrence=f', '-Y', 'ip or ipv6']
    for field in FIELDS:
        args.extend(['-e', field])
    return args

def live_windows(interface, seconds, duration, explicit=None, on_window=None):
    if not math.isfinite(seconds) or not math.isfinite(duration) or seconds <= 0 or duration < seconds:
        raise ValueError('Use a positive window and seconds >= window.')
    args = field_arguments(explicit) + ['-p', '-i', str(interface)]
    with TsharkReader(args) as reader:
        started, wall_start = time.monotonic(), time.time()
        end = started + duration
        index, current = 0, Window()
        print('Capture started. Waiting for completed windows; Ctrl+C stops safely.', flush=True)
        while True:
            boundary = started + (index+1)*seconds
            try:
                observed, line = reader.items.get(timeout=max(.001, min(.2, boundary-time.monotonic())))
            except queue.Empty:
                if reader.process.poll() is not None:
                    raise ValueError(reader.failure())
                if time.monotonic() >= boundary:
                    row = current.row(wall_start + index*seconds, seconds)
                    if on_window:
                        on_window(row)
                    else:
                        print(f'Window {index+1}: {current.count} packets', flush=True)
                    yield row
                    index += 1; current = Window()
                    if started + (index+1)*seconds > end + 1e-6:
                        return
                continue
            if observed < started + index*seconds:
                if index == 0:
                    continue  # Ignore packets arriving before the measurement clock starts.
                raise ValueError('Capture processing fell behind. Use a longer window or lower traffic volume.')
            while observed >= boundary:
                row = current.row(wall_start + index*seconds, seconds)
                if on_window:
                    on_window(row)
                else:
                    print(f'Window {index+1}: {current.count} packets', flush=True)
                yield row
                index += 1; current = Window()
                if started + (index+1)*seconds > end + 1e-6:
                    return
                boundary = started + (index+1)*seconds
            current.add(parse_packet(line))

def pcap_windows(path, seconds, explicit=None):
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError('Window duration must be positive.')
    if not Path(path).is_file():
        raise FileNotFoundError(path)
    args = field_arguments(explicit) + ['-r', str(path)]
    with TsharkReader(args) as reader:
        started = previous = None
        index, current = 0, Window()
        while True:
            try:
                _, line = reader.items.get(timeout=.1)
            except queue.Empty:
                if reader.process.poll() is not None and not reader.threads[0].is_alive():
                    if reader.process.returncode:
                        raise ValueError(reader.failure())
                    break
                continue
            packet = parse_packet(line)
            if started is None:
                started = previous = packet.timestamp
            if packet.timestamp < previous:
                raise ValueError('PCAP timestamps are not ordered. Sort the capture before using it.')
            previous = packet.timestamp
            while packet.timestamp >= started + (index+1)*seconds:
                yield current.row(started + index*seconds, seconds)
                current, index = Window(), index+1
            current.add(packet)
        # A final partially observed window is deliberately omitted.
