"""
WebSocket frame relay logic and session data models for Fracture.

Provides:
  - WsDirection, WsOpcode, WsFrame  — data models
  - WebSocketSession                — session with frame log and callbacks
  - relay_websocket()               — bidirectional frame relay using select()
  - Global session registry         — get_sessions(), add_session_callback()
"""

import select
import socket
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class WsDirection(Enum):
    CLIENT_TO_SERVER = "→"
    SERVER_TO_CLIENT = "←"


class WsOpcode(Enum):
    CONTINUATION = 0x0
    TEXT = 0x1
    BINARY = 0x2
    CLOSE = 0x8
    PING = 0x9
    PONG = 0xA


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class WsFrame:
    session_id: int
    direction: WsDirection
    opcode: WsOpcode
    payload: bytes
    timestamp: datetime = field(default_factory=datetime.now)
    masked: bool = False


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class WebSocketSession:
    """Tracks a single WebSocket connection including all frames."""

    def __init__(
        self,
        session_id: int,
        host: str,
        port: int,
        is_wss: bool,
        upgrade_req: bytes,
        upgrade_resp: bytes,
    ) -> None:
        self.session_id = session_id
        self.host = host
        self.port = port
        self.is_wss = is_wss
        self.upgrade_request = upgrade_req
        self.upgrade_response = upgrade_resp
        self.frames: list[WsFrame] = []
        self.callbacks: list[Callable[[WsFrame], None]] = []
        # Store server socket for replay support
        self.server_sock: socket.socket | None = None

    def add_frame_callback(self, cb: Callable[[WsFrame], None]) -> None:
        """Register a callable that will be invoked with every new WsFrame."""
        self.callbacks.append(cb)

    def _record_frame(self, frame: WsFrame) -> None:
        """Append frame to history and fire all registered callbacks."""
        self.frames.append(frame)
        for cb in self.callbacks:
            try:
                cb(frame)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Frame parsing
# ---------------------------------------------------------------------------

def _parse_frame(data: bytes) -> tuple[WsFrame | None, bytes]:
    """
    Parse one WebSocket frame from *data*.

    Returns (WsFrame, remaining_bytes) when a complete frame is present,
    or (None, data) if more data is needed.
    The returned WsFrame has session_id=0 and direction=CLIENT_TO_SERVER as
    placeholders; callers must set the correct values before storing.
    """
    if len(data) < 2:
        return None, data

    b0, b1 = data[0], data[1]
    # fin  = (b0 >> 7) & 1  # not used for relay — we pass raw bytes through
    opcode_val = b0 & 0x0F
    masked = (b1 >> 7) & 1
    payload_len = b1 & 0x7F
    offset = 2

    if payload_len == 126:
        if len(data) < 4:
            return None, data
        payload_len = int.from_bytes(data[2:4], "big")
        offset = 4
    elif payload_len == 127:
        if len(data) < 10:
            return None, data
        payload_len = int.from_bytes(data[2:10], "big")
        offset = 10

    mask_key = b""
    if masked:
        if len(data) < offset + 4:
            return None, data
        mask_key = data[offset : offset + 4]
        offset += 4

    if len(data) < offset + payload_len:
        return None, data

    raw_payload = data[offset : offset + payload_len]
    if masked:
        payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(raw_payload))
    else:
        payload = raw_payload

    remaining = data[offset + payload_len :]

    try:
        op = WsOpcode(opcode_val)
    except ValueError:
        op = WsOpcode.CONTINUATION

    frame = WsFrame(
        session_id=0,
        direction=WsDirection.CLIENT_TO_SERVER,
        opcode=op,
        payload=payload,
        masked=bool(masked),
    )
    return frame, remaining


def _recv_all(sock: socket.socket, buf_size: int = 65536) -> bytes:
    """Non-blocking read of whatever is available on *sock*."""
    try:
        return sock.recv(buf_size)
    except (BlockingIOError, OSError):
        return b""


# ---------------------------------------------------------------------------
# Relay
# ---------------------------------------------------------------------------

def relay_websocket(
    client_sock: socket.socket,
    server_sock: socket.socket,
    session: WebSocketSession,
) -> None:
    """
    Relay WebSocket frames bidirectionally between *client_sock* and
    *server_sock*.

    Parses each frame, logs it to *session*, fires frame callbacks, then
    forwards the **raw** bytes (including masking) to the other side so the
    wire format is preserved.

    Runs until either socket closes or a CLOSE frame is seen from either side.
    Uses select() with a 1-second timeout for non-blocking I/O.
    """
    # Attach server socket to session so UI can replay frames.
    session.server_sock = server_sock

    client_buf: bytes = b""
    server_buf: bytes = b""

    while True:
        try:
            readable, _, exceptional = select.select(
                [client_sock, server_sock],
                [],
                [client_sock, server_sock],
                1.0,
            )
        except (OSError, ValueError):
            # One of the sockets was closed externally.
            break

        if exceptional:
            break

        for sock in readable:
            data = _recv_all(sock)
            if not data:
                # Socket closed.
                return

            if sock is client_sock:
                client_buf += data
                direction = WsDirection.CLIENT_TO_SERVER
                dest = server_sock
                buf_ref = "client"
            else:
                server_buf += data
                direction = WsDirection.SERVER_TO_CLIENT
                dest = client_sock
                buf_ref = "server"

            # Forward raw bytes immediately to preserve masking.
            try:
                dest.sendall(data)
            except OSError:
                return

            # Parse frames from the accumulated buffer for logging.
            if buf_ref == "client":
                while True:
                    frame, client_buf = _parse_frame(client_buf)
                    if frame is None:
                        break
                    frame.session_id = session.session_id
                    frame.direction = direction
                    session._record_frame(frame)
                    if frame.opcode == WsOpcode.CLOSE:
                        return
            else:
                while True:
                    frame, server_buf = _parse_frame(server_buf)
                    if frame is None:
                        break
                    frame.session_id = session.session_id
                    frame.direction = direction
                    session._record_frame(frame)
                    if frame.opcode == WsOpcode.CLOSE:
                        return


# ---------------------------------------------------------------------------
# Global session registry
# ---------------------------------------------------------------------------

_sessions: list[WebSocketSession] = []
_session_callbacks: list[Callable[[WebSocketSession], None]] = []
_session_counter: int = 0


def get_sessions() -> list[WebSocketSession]:
    """Return all registered WebSocket sessions (newest last)."""
    return list(_sessions)


def add_session_callback(cb: Callable[[WebSocketSession], None]) -> None:
    """Register a callable invoked whenever a new WebSocketSession is created."""
    _session_callbacks.append(cb)


def _new_session(
    host: str,
    port: int,
    is_wss: bool,
    upgrade_req: bytes,
    upgrade_resp: bytes,
) -> WebSocketSession:
    """
    Create and register a new WebSocketSession.  Returns the session so the
    caller can store the server socket and start relay_websocket().
    """
    global _session_counter
    _session_counter += 1
    session = WebSocketSession(
        session_id=_session_counter,
        host=host,
        port=port,
        is_wss=is_wss,
        upgrade_req=upgrade_req,
        upgrade_resp=upgrade_resp,
    )
    _sessions.append(session)
    for cb in _session_callbacks:
        try:
            cb(session)
        except Exception:
            pass
    return session
