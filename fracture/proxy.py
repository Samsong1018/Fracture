"""
Intercepting HTTP/HTTPS proxy core.

Runs a TCP server on 127.0.0.1:8080. HTTP requests are handled directly;
HTTPS is handled via CONNECT tunneling with per-domain MITM certs.

Intercepted requests are placed in `intercept_queue` (if intercept is enabled)
and forwarded only after being released via `release_request()`.
"""

import dataclasses
import queue
import select
import socket
import ssl
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .certs import ensure_ca, get_domain_cert
from .match_replace import MatchReplaceManager
from . import ws_handler
from .plugins import PluginManager
from .scope import ScopeManager

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 8080
BUFFER = 65536


@dataclass
class HttpRequest:
    id: int
    method: str
    host: str
    port: int
    path: str
    version: str
    headers: dict[str, str]
    body: bytes
    is_https: bool
    timestamp: datetime = field(default_factory=datetime.now)
    raw: bytes = b""

    def __str__(self) -> str:
        return f"{self.method} {self.path} HTTP/{self.version}"


@dataclass
class HttpResponse:
    request_id: int
    status_code: int
    status_text: str
    headers: dict[str, str]
    body: bytes
    raw: bytes = b""


class ProxyServer:
    def __init__(self):
        self.ca_cert, self.ca_key = ensure_ca()
        self.intercept_enabled = False
        self.response_intercept_enabled = False
        self.history: list[tuple[HttpRequest, Optional[HttpResponse]]] = []
        self.intercept_queue: queue.Queue[HttpRequest] = queue.Queue()
        self.response_intercept_queue: queue.Queue[HttpResponse] = queue.Queue()
        self._pending: dict[int, queue.Queue[HttpRequest]] = {}
        self._pending_resp: dict[int, queue.Queue[HttpResponse]] = {}
        self._req_counter = 0
        self._counter_lock = threading.Lock()
        self._running = False
        self._server_sock: Optional[socket.socket] = None
        self._history_callbacks: list = []
        self.scope: ScopeManager = ScopeManager()
        self.match_replace: MatchReplaceManager = MatchReplaceManager()
        self.plugin_manager: PluginManager = PluginManager()
        self.plugin_manager.load_all()
        # Upstream proxy
        self.upstream_host: Optional[str] = None
        self.upstream_port: Optional[int] = None
        self.upstream_type: str = "http"  # "http" or "socks5"
        # TLS passthrough (skip MITM for these hosts)
        self.tls_passthrough_hosts: set[str] = set()
        # Multi-listener registry (primary listener is index 0)
        self._listeners: list[dict] = []

    def add_history_callback(self, cb):
        self._history_callbacks.append(cb)

    def _next_id(self) -> int:
        with self._counter_lock:
            self._req_counter += 1
            return self._req_counter

    def start(self):
        self._running = True
        t = threading.Thread(target=self._serve, daemon=True)
        t.start()
        self._listeners = [{"host": LISTEN_HOST, "port": LISTEN_PORT, "running": True, "transparent": False}]
        print(f"[proxy] Listening on {LISTEN_HOST}:{LISTEN_PORT}")

    def stop(self):
        self._running = False
        if self._server_sock:
            self._server_sock.close()

    # ------------------------------------------------------------------
    # Upstream proxy configuration
    # ------------------------------------------------------------------

    def set_upstream_proxy(self, host: str, port: int, proxy_type: str = "http") -> None:
        self.upstream_host = host
        self.upstream_port = port
        self.upstream_type = proxy_type.lower()

    def clear_upstream_proxy(self) -> None:
        self.upstream_host = None
        self.upstream_port = None
        self.upstream_type = "http"

    # ------------------------------------------------------------------
    # TLS passthrough
    # ------------------------------------------------------------------

    def add_tls_passthrough(self, host: str) -> None:
        self.tls_passthrough_hosts.add(host.lower())

    def remove_tls_passthrough(self, host: str) -> None:
        self.tls_passthrough_hosts.discard(host.lower())

    def is_tls_passthrough(self, host: str) -> bool:
        return host.lower() in self.tls_passthrough_hosts

    # ------------------------------------------------------------------
    # Multi-listener management
    # ------------------------------------------------------------------

    def add_listener(self, host: str, port: int, transparent: bool = False) -> bool:
        """Start an additional proxy listener on host:port. Returns True on success."""
        entry: dict = {"host": host, "port": port, "running": False, "transparent": transparent}
        try:
            t = threading.Thread(
                target=self._serve_extra,
                args=(host, port, entry, transparent),
                daemon=True,
            )
            entry["running"] = True
            self._listeners.append(entry)
            t.start()
            return True
        except Exception as e:
            print(f"[proxy] add_listener error: {e}")
            return False

    def remove_listener(self, host: str, port: int) -> bool:
        for entry in self._listeners[1:]:  # never remove primary
            if entry["host"] == host and entry["port"] == port:
                entry["running"] = False
                self._listeners.remove(entry)
                return True
        return False

    def list_listeners(self) -> list[dict]:
        return [dict(e) for e in self._listeners]

    def add_transparent_listener(self, host: str, port: int) -> bool:
        """Start a transparent (non-CONNECT) listener for iptables REDIRECT setups.

        Traffic must be redirected to this port via iptables PREROUTING REDIRECT.
        The Host header is used to determine the target.
        """
        return self.add_listener(host, port, transparent=True)

    def release_request(self, req: HttpRequest):
        """Forward an intercepted request that was held in the queue."""
        if req.id in self._pending:
            self._pending[req.id].put(req)

    def release_response(self, resp: HttpResponse):
        """Forward an intercepted response that was held in the queue."""
        if resp.request_id in self._pending_resp:
            self._pending_resp[resp.request_id].put(resp)

    def drop_request(self, req: HttpRequest):
        """Drop an intercepted request — synthesizes a 503 response back."""
        if req.id in self._pending:
            # Marker request: empty path tells the handler to send a 503
            req.headers["X-Fracture-Drop"] = "1"
            self._pending[req.id].put(req)

    def drop_response(self, resp: HttpResponse):
        """Drop an intercepted response — synthesizes an empty 502 to the client."""
        if resp.request_id in self._pending_resp:
            resp.status_code = 502
            resp.status_text = "Dropped by Fracture"
            resp.body = b""
            resp.headers["X-Fracture-Drop"] = "1"
            resp.raw = (
                f"HTTP/1.1 {resp.status_code} {resp.status_text}\r\n"
                "Content-Length: 0\r\n"
                "X-Fracture-Drop: 1\r\n\r\n"
            ).encode()
            self._pending_resp[resp.request_id].put(resp)

    def _serve(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            self._server_sock = s
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((LISTEN_HOST, LISTEN_PORT))
            s.listen(100)
            s.settimeout(1.0)
            while self._running:
                try:
                    conn, addr = s.accept()
                    threading.Thread(
                        target=self._handle_client, args=(conn,), daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except OSError:
                    break

    def _serve_extra(self, host: str, port: int, entry: dict, transparent: bool):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((host, port))
                s.listen(100)
                s.settimeout(1.0)
                while entry.get("running"):
                    try:
                        conn, addr = s.accept()
                        handler = self._handle_transparent if transparent else self._handle_client
                        threading.Thread(target=handler, args=(conn,), daemon=True).start()
                    except socket.timeout:
                        continue
                    except OSError:
                        break
        except Exception as e:
            print(f"[proxy] extra listener {host}:{port} error: {e}")
            entry["running"] = False

    def _handle_transparent(self, conn: socket.socket):
        """Handle a non-CONNECT transparent request (for iptables REDIRECT)."""
        try:
            data = conn.recv(BUFFER)
            if data:
                self._handle_http(conn, data, is_https=False)
        except Exception as e:
            print(f"[proxy] transparent handler error: {e}")
        finally:
            conn.close()

    def _handle_client(self, conn: socket.socket):
        try:
            data = conn.recv(BUFFER)
            if not data:
                return
            first_line = data.split(b"\r\n")[0].decode(errors="replace")
            parts = first_line.split()
            if len(parts) < 3:
                return

            if parts[0] == "CONNECT":
                self._handle_connect(conn, parts[1], data)
            else:
                self._handle_http(conn, data, is_https=False)
        except Exception as e:
            print(f"[proxy] client error: {e}")
        finally:
            conn.close()

    def _handle_connect(self, conn: socket.socket, target: str, _initial: bytes):
        if ":" in target:
            host, port = target.rsplit(":", 1)
            port = int(port)
        else:
            host, port = target, 443

        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # TLS passthrough: pipe raw bytes without MITM
        if self.is_tls_passthrough(host):
            try:
                srv = self._connect_upstream(host, port, tls=False)
                self._pipe(conn, srv)
            except Exception as e:
                print(f"[proxy] passthrough pipe error for {host}: {e}")
            return

        cert_path, key_path = get_domain_cert(host, self.ca_cert, self.ca_key)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))

        try:
            tls_conn = ctx.wrap_socket(conn, server_side=True)
        except ssl.SSLError as e:
            print(f"[proxy] TLS handshake failed for {host}: {e}")
            return

        try:
            data = tls_conn.recv(BUFFER)
            if data:
                self._handle_http(tls_conn, data, is_https=True, host=host, port=port)
        finally:
            tls_conn.close()

    def _handle_http(
        self,
        conn: socket.socket,
        data: bytes,
        is_https: bool,
        host: str = "",
        port: int = 80,
    ):
        req = self._parse_request(data, is_https, host, port)
        if req is None:
            return

        if self.intercept_enabled:
            release_q: queue.Queue[HttpRequest] = queue.Queue()
            self._pending[req.id] = release_q
            self.intercept_queue.put(req)
            req = release_q.get()
            del self._pending[req.id]

        if self.match_replace.rules():
            req = dataclasses.replace(req, raw=self.match_replace.apply_to_request(req.raw))

        req = self.plugin_manager.call_on_request(req)

        # WebSocket upgrade — hand off to relay loop
        if req.headers.get("upgrade", "").lower() == "websocket":
            self._handle_websocket(conn, req)
            return

        resp = self._forward(req)

        if resp is not None and self.match_replace.rules():
            resp = dataclasses.replace(resp, raw=self.match_replace.apply_to_response(resp.raw))

        if resp is not None:
            resp = self.plugin_manager.call_on_response(req, resp)

        if self.response_intercept_enabled and resp is not None:
            release_resp_q: queue.Queue[HttpResponse] = queue.Queue()
            self._pending_resp[resp.request_id] = release_resp_q
            self.response_intercept_queue.put(resp)
            resp = release_resp_q.get()
            del self._pending_resp[resp.request_id]

        self._record(req, resp)

        if resp:
            conn.sendall(resp.raw)

    def _handle_websocket(self, client_conn: socket.socket, req: HttpRequest):
        try:
            server_sock = socket.create_connection((req.host, req.port), timeout=10)
            if req.is_https:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                server_sock = ctx.wrap_socket(server_sock, server_hostname=req.host)

            server_sock.sendall(self._rebuild_request(req))

            upgrade_resp = b""
            server_sock.settimeout(5)
            while b"\r\n\r\n" not in upgrade_resp:
                chunk = server_sock.recv(BUFFER)
                if not chunk:
                    break
                upgrade_resp += chunk
            server_sock.settimeout(None)

            client_conn.sendall(upgrade_resp)

            session = ws_handler._new_session(
                host=req.host,
                port=req.port,
                is_wss=req.is_https,
                upgrade_req=req.raw,
                upgrade_resp=upgrade_resp,
            )
            ws_handler.relay_websocket(client_conn, server_sock, session)
        except Exception as e:
            print(f"[proxy] websocket relay error for {req.host}: {e}")

    def _parse_request(
        self, data: bytes, is_https: bool, default_host: str, default_port: int
    ) -> Optional[HttpRequest]:
        try:
            header_end = data.find(b"\r\n\r\n")
            header_bytes = data[:header_end] if header_end != -1 else data
            body = data[header_end + 4:] if header_end != -1 else b""

            lines = header_bytes.decode(errors="replace").split("\r\n")
            first = lines[0].split()
            if len(first) < 3:
                return None

            method, raw_path, version = first[0], first[1], first[2].replace("HTTP/", "")
            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            host_hdr = headers.get("host", default_host)
            if ":" in host_hdr:
                host, port = host_hdr.rsplit(":", 1)
                port = int(port)
            else:
                host, port = host_hdr, default_port

            if raw_path.startswith("http://"):
                path = "/" + raw_path.split("/", 3)[-1]
            else:
                path = raw_path

            return HttpRequest(
                id=self._next_id(),
                method=method,
                host=host,
                port=port,
                path=path,
                version=version,
                headers=headers,
                body=body,
                is_https=is_https,
                raw=data,
            )
        except Exception as e:
            print(f"[proxy] parse error: {e}")
            return None

    def _connect_upstream(self, host: str, port: int, tls: bool = False) -> socket.socket:
        """Open a socket to host:port, routing through upstream proxy if configured."""
        if self.upstream_host and self.upstream_type == "socks5":
            try:
                import socks  # type: ignore[import]
                sock = socks.create_connection(
                    (host, port),
                    proxy_type=socks.SOCKS5,
                    proxy_addr=self.upstream_host,
                    proxy_port=self.upstream_port,
                    timeout=10,
                )
            except ImportError:
                print("[proxy] PySocks not installed; falling back to direct connection")
                sock = socket.create_connection((host, port), timeout=10)
        elif self.upstream_host and self.upstream_type == "http":
            # Chain through an HTTP CONNECT proxy
            sock = socket.create_connection((self.upstream_host, self.upstream_port), timeout=10)
            connect_req = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n"
            sock.sendall(connect_req.encode())
            resp = b""
            while b"\r\n\r\n" not in resp:
                chunk = sock.recv(BUFFER)
                if not chunk:
                    break
                resp += chunk
        else:
            sock = socket.create_connection((host, port), timeout=10)
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)
        return sock

    def _pipe(self, a: socket.socket, b: socket.socket) -> None:
        """Bidirectional raw byte forwarding between two sockets."""
        a.setblocking(False)
        b.setblocking(False)
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 5.0)
                if not r:
                    break
                for src, dst in ((a, b), (b, a)):
                    if src in r:
                        try:
                            data = src.recv(BUFFER)
                            if not data:
                                return
                            dst.sendall(data)
                        except Exception:
                            return
        finally:
            for s in (a, b):
                try:
                    s.close()
                except Exception:
                    pass

    def _forward(self, req: HttpRequest) -> Optional[HttpResponse]:
        try:
            sock = self._connect_upstream(req.host, req.port, tls=req.is_https)

            rebuilt = self._rebuild_request(req)
            sock.sendall(rebuilt)

            response_data = b""
            sock.settimeout(5)
            while True:
                try:
                    chunk = sock.recv(BUFFER)
                    if not chunk:
                        break
                    response_data += chunk
                except socket.timeout:
                    break
            sock.close()

            return self._parse_response(req.id, response_data)
        except Exception as e:
            print(f"[proxy] forward error for {req.host}: {e}")
            return None

    def _rebuild_request(self, req: HttpRequest) -> bytes:
        lines = [f"{req.method} {req.path} HTTP/{req.version}"]
        for k, v in req.headers.items():
            lines.append(f"{k}: {v}")
        header = "\r\n".join(lines) + "\r\n\r\n"
        return header.encode() + req.body

    def _parse_response(self, req_id: int, data: bytes) -> Optional[HttpResponse]:
        if not data:
            return None
        try:
            header_end = data.find(b"\r\n\r\n")
            header_bytes = data[:header_end] if header_end != -1 else data
            body = data[header_end + 4:] if header_end != -1 else b""

            lines = header_bytes.decode(errors="replace").split("\r\n")
            status_parts = lines[0].split(" ", 2)
            code = int(status_parts[1]) if len(status_parts) > 1 else 0
            text = status_parts[2] if len(status_parts) > 2 else ""

            headers = {}
            for line in lines[1:]:
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()

            return HttpResponse(
                request_id=req_id,
                status_code=code,
                status_text=text,
                headers=headers,
                body=body,
                raw=data,
            )
        except Exception as e:
            print(f"[proxy] response parse error: {e}")
            return None

    def _record(self, req: HttpRequest, resp: Optional[HttpResponse]):
        if not self.scope.in_scope(req.host):
            return
        entry = (req, resp)
        self.history.append(entry)
        for cb in self._history_callbacks:
            try:
                cb(entry)
            except Exception:
                pass
