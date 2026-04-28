"""
Simple fake filesystem + command handler for HoneySSH

Handles basic Linux commands locally so we don't rely on the LLM
for everything (faster + more consistent).
"""

import os

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
    parts = command.split(" ", 1)

    if len(parts) == 1 or parts[1].strip() in ["", "~"]:
        return "/home/ubuntu", ""

    target = parts[1].strip()

    if target == ".":
        return cwd, ""

    if target == "..":
        if cwd == "/":
            return "/", ""
        new_path = os.path.dirname(cwd.rstrip("/"))
        return new_path if new_path else "/", ""

    if target.startswith("/"):
        new_path = os.path.normpath(target)
    else:
        new_path = os.path.normpath(cwd.rstrip("/") + "/" + target)

    if new_path in FAKE_FS:
        return new_path, ""

    return cwd, f"bash: cd: {target}: No such file or directory"



def fake_mkdir(command, cwd):
    name = command.split(" ", 1)[1].strip()

    if "/" in name:
        parent = os.path.normpath(cwd.rstrip("/") + "/" + os.path.dirname(name))
        dirname = os.path.basename(name)
    else:
        parent = cwd
        dirname = name

    new_path = os.path.normpath(parent.rstrip("/") + "/" + dirname)

    if parent not in FAKE_FS:
        return f"mkdir: cannot create directory '{name}': No such file or directory"

    if new_path in FAKE_FS:
        return f"mkdir: cannot create directory '{name}': File exists"

    FAKE_FS[parent]["dirs"].append(dirname)
    FAKE_FS[new_path] = {"dirs": [], "files": []}
    return ""


def fake_touch(command, cwd):
    name = command.split(" ", 1)[1].strip()

    if "/" in name:
        parent = os.path.normpath(cwd.rstrip("/") + "/" + os.path.dirname(name))
        filename = os.path.basename(name)
    else:
        parent = cwd
        filename = name

    if parent not in FAKE_FS:
        return f"touch: cannot touch '{name}': No such file or directory"

    if filename not in FAKE_FS[parent]["files"]:
        FAKE_FS[parent]["files"].append(filename)

    return ""




def fake_ls_recursive(path):
    path = os.path.normpath(path)

    if path not in FAKE_FS:
        return f"ls: cannot access '{path}': No such file or directory"

    lines = [f"{path}:"]
    entry = FAKE_FS[path]
    items = entry["dirs"] + entry["files"]

    if items:
        lines.append("\n".join(items))

    for d in entry["dirs"]:
        child_path = os.path.normpath(path.rstrip("/") + "/" + d)
        lines.append("")
        lines.append(fake_ls_recursive(child_path))

    return "\n".join(lines)

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

    if command.startswith("mkdir "):
        return fake_mkdir(command, cwd), cwd, True

    if command.startswith("touch "):
        return fake_touch(command, cwd), cwd, True

    if command.startswith("ls -R "):
        target = command.split(" ", 2)[2].strip()
        if target.startswith("/"):
            path = os.path.normpath(target)
        else:
            path = os.path.normpath(cwd.rstrip("/") + "/" + target)
        return fake_ls_recursive(path), cwd, True

    if command == "cat /etc/passwd":
        return fake_passwd(), cwd, True

    if command == "cat /etc/os-release":
        return fake_os_release(), cwd, True

    # Not handled → send to LLM
    return "", cwd, False