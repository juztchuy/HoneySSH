"""
Simple fake filesystem + command handler for HoneySSH

Handles basic Linux commands locally so we don't rely on the LLM
for everything (faster + more consistent).
"""

from datetime import datetime

# --------------------------------------------------
# Fake filesystem structure
# --------------------------------------------------

FAKE_FS = {
    "/": {
        "dirs": ["home", "etc", "var", "tmp", "proc", "sys", "dev", "bin", "usr", "opt"],
        "files": []
    },
    "/home": {
        "dirs": ["ubuntu"],
        "files": []
    },
    "/home/ubuntu": {
        "dirs": [".ssh", ".cache", ".local"],
        "files": [".bashrc", ".bash_history", ".profile"]
    },
    "/home/ubuntu/.ssh": {
        "dirs": [],
        "files": ["authorized_keys", "known_hosts"]
    },
    "/tmp": {
        "dirs": [],
        "files": []
    },
    "/etc": {
        "dirs": ["ssh", "nginx", "systemd"],
        "files": ["passwd", "shadow", "hosts", "hostname", "os-release"]
    },
}

# --------------------------------------------------
# Command handlers
# --------------------------------------------------

def fake_ls(path):
    if path not in FAKE_FS:
        return f"ls: cannot access '{path}': No such file or directory"

    entry = FAKE_FS[path]
    items = entry["dirs"] + entry["files"]
    return "  ".join(items)


def fake_ls_la(path, username):
    if path not in FAKE_FS:
        return f"ls: cannot access '{path}': No such file or directory"

    entry = FAKE_FS[path]
    lines = []

    # total line (fake)
    lines.append("total 12")

    # . and ..
    lines.append(f"drwxr-xr-x 3 {username} {username} 4096 Apr  1 12:00 .")
    lines.append(f"drwxr-xr-x 5 root root 4096 Apr  1 12:00 ..")

    for d in entry["dirs"]:
        lines.append(f"drwxr-xr-x 2 {username} {username} 4096 Apr  1 12:00 {d}")

    for f in entry["files"]:
        lines.append(f"-rw-r--r-- 1 {username} {username}  123 Apr  1 12:00 {f}")

    return "\n".join(lines)


def fake_cd(command, cwd):
    target = command.split(" ", 1)[1].strip()

    if target == "~":
        return "/home/ubuntu", ""

    if target == "/":
        return "/", ""

    if target.startswith("/"):
        if target in FAKE_FS:
            return target, ""
        else:
            return cwd, f"bash: cd: {target}: No such file or directory"

    # relative path
    new_path = cwd.rstrip("/") + "/" + target
    if new_path in FAKE_FS:
        return new_path, ""

    return cwd, f"bash: cd: {target}: No such file or directory"


def fake_passwd():
    return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
"""


def fake_os_release():
    return """NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
PRETTY_NAME="Ubuntu 22.04.3 LTS"
"""


# --------------------------------------------------
# Main handler
# --------------------------------------------------

def handle_command(command, cwd, username="ubuntu"):
    command = command.strip()

    if command == "whoami":
        return username, cwd, True

    if command == "pwd":
        return cwd, cwd, True

    if command == "ls":
        return fake_ls(cwd), cwd, True

    if command == "ls -la":
        return fake_ls_la(cwd, username), cwd, True

    if command.startswith("cd "):
        new_cwd, output = fake_cd(command, cwd)
        return output, new_cwd, True

    if command == "cat /etc/passwd":
        return fake_passwd(), cwd, True

    if command == "cat /etc/os-release":
        return fake_os_release(), cwd, True

    # Not handled → send to LLM
    return "", cwd, False