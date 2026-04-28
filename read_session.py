"""
Read and display a HoneySSH ttylog session file.

Usage:
    python read_session.py                        # list all sessions
    python read_session.py <filename_or_number>   # print one session
    python read_session.py --commands             # list commands from all sessions
"""

import struct
import sys
import os
from datetime import datetime
from pathlib import Path

TTY_DIR = Path("var/lib/cowrie/tty")
TTYSTRUCT = "<iLiiLL"
STRUCT_SIZE = struct.calcsize(TTYSTRUCT)

OP_OPEN, OP_CLOSE, OP_WRITE = 1, 2, 3
TYPE_INPUT, TYPE_OUTPUT = 1, 2


def read_ttylog(path: Path) -> list:
    """Parse a ttylog file into a list of (timestamp, direction, data) tuples."""
    events = []
    with open(path, "rb") as f:
        while True:
            header = f.read(STRUCT_SIZE)
            if len(header) < STRUCT_SIZE:
                break
            op, _tty, length, direction, sec, usec = struct.unpack(TTYSTRUCT, header)
            data = f.read(length) if length > 0 else b""
            ts = sec + usec / 1_000_000
            if op == OP_WRITE:
                events.append((ts, direction, data))
    return events


def extract_commands(events: list) -> list:
    """Pull typed commands (TYPE_OUTPUT = attacker keystrokes) from events."""
    cmds = []
    buf = b""
    for _ts, direction, data in events:
        if direction != TYPE_OUTPUT:
            continue
        for byte in [bytes([b]) for b in data]:
            if byte in (b"\r", b"\n", b"\x0d", b"\x0a"):
                line = buf.decode("utf-8", errors="replace").strip()
                if line and line not in ("^C",):
                    cmds.append(line)
                buf = b""
            elif byte == b"\x7f" and buf:
                buf = buf[:-1]
            elif byte >= b" ":
                buf += byte
    return cmds


def list_sessions():
    files = sorted(TTY_DIR.glob("*-0i.log"))
    if not files:
        print("No sessions recorded yet.")
        return
    print(f"{'#':<4} {'Date/Time':<22} {'Size':>6}  File")
    print("-" * 60)
    for i, f in enumerate(files, 1):
        ts_str = f.name[:15]
        try:
            dt = datetime.strptime(ts_str, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            dt = ts_str
        print(f"{i:<4} {dt:<22} {f.stat().st_size:>6}  {f.name}")


def print_session(path: Path):
    events = read_ttylog(path)
    cmds = extract_commands(events)
    dt = path.name[:15]
    try:
        dt = datetime.strptime(dt, "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        pass

    print(f"\n{'='*60}")
    print(f"Session : {path.name}")
    print(f"Time    : {dt}")
    print(f"Events  : {len(events)}")
    print(f"{'='*60}\n")

    if cmds:
        print("Commands typed:")
        for i, cmd in enumerate(cmds, 1):
            print(f"  {i:>3}.  {cmd}")
    else:
        print("(no commands recorded)")

    print("\nFull terminal output:")
    print("-" * 60)
    for _ts, direction, data in events:
        if direction == TYPE_INPUT:
            try:
                sys.stdout.write(data.decode("utf-8", errors="replace"))
            except Exception:
                pass
    print("\n" + "-" * 60)


def all_commands():
    files = sorted(TTY_DIR.glob("*-0i.log"))
    for f in files:
        events = read_ttylog(f)
        cmds = extract_commands(events)
        if not cmds:
            continue
        try:
            dt = datetime.strptime(f.name[:15], "%Y%m%d-%H%M%S").strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            dt = f.name[:15]
        print(f"\n[{dt}]  {f.name}")
        for cmd in cmds:
            print(f"  $ {cmd}")


if __name__ == "__main__":
    if not TTY_DIR.exists():
        print(f"TTY log directory not found: {TTY_DIR}")
        sys.exit(1)

    if len(sys.argv) == 1:
        list_sessions()

    elif sys.argv[1] == "--commands":
        all_commands()

    else:
        arg = sys.argv[1]
        files = sorted(TTY_DIR.glob("*-0i.log"))

        # Accept number (1-based index) or filename
        if arg.isdigit():
            idx = int(arg) - 1
            if 0 <= idx < len(files):
                print_session(files[idx])
            else:
                print(f"No session #{arg}. Run with no args to list sessions.")
        else:
            path = TTY_DIR / arg if not arg.startswith("var") else Path(arg)
            if path.exists():
                print_session(path)
            else:
                print(f"File not found: {path}")
