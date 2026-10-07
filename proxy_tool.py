#!/usr/bin/env python3
"""Windows Local Proxy GUI — pure Python, 3proxy-like chaining (no native binaries).

Maps to 3proxy concepts without shipping/downloading 3proxy.exe (Defender FPs):
  listen  — local HTTP (+ SOCKS5) on 127.0.0.1
  parent  — upstream HTTP CONNECT or SOCKS5 with username/password
  auth    — credentials for the parent only (local listen is open to this PC)

Modes:
  apps    — only local listen; pick apps / set proxy in app settings (no system proxy)
  system  — also set Windows system proxy to the local HTTP listen

No .exe required — run start.pyw / Start Local Proxy.lnk.
"""

from __future__ import annotations

import base64
import ipaddress
import json
import logging
import os
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from tkinter import filedialog, messagebox, scrolledtext, simpledialog, ttk
from typing import Any, Callable, Optional
from urllib.parse import urlparse, urlunparse

try:
    import ctypes
    import winreg
except ImportError:
    ctypes = None  # type: ignore
    winreg = None  # type: ignore

IS_WINDOWS = sys.platform.startswith("win")
IS_MACOS = sys.platform == "darwin"

APP_DIR = Path(__file__).resolve().parent
CONFIG_PATH = APP_DIR / "proxy_config.json"
LOG_PATH = APP_DIR / "proxy.log"
BROWSER_PROFILES_DIR = APP_DIR / "browser_profiles"
LOCAL_HOST = "127.0.0.1"
DEFAULT_LOCAL_PORT = 18080
BUFFER = 65536
CONNECT_TIMEOUT = 10.0
UPSTREAM_TIMEOUT = 12.0
PROTO_HTTP = "HTTP"
PROTO_HTTPS = "HTTPS"
PROTO_SOCKS5 = "SOCKS5"
# Parent protocols we can talk to. HTTPS = TLS to the parent, then CONNECT inside.
PROTO_CHOICES = (PROTO_HTTP, PROTO_HTTPS, PROTO_SOCKS5)
SCOPE_APPS = "apps"
SCOPE_SYSTEM = "system"
BROWSER_CHROME = "chrome"
BROWSER_EDGE = "edge"
BROWSER_BRAVE = "brave"
BROWSER_FIREFOX = "firefox"
BROWSER_CHOICES = (BROWSER_CHROME, BROWSER_EDGE, BROWSER_BRAVE, BROWSER_FIREFOX)
BROWSER_LABELS = {
    BROWSER_CHROME: "Chrome",
    BROWSER_EDGE: "Edge",
    BROWSER_BRAVE: "Brave",
    BROWSER_FIREFOX: "Firefox",
}
# Bump when Chromium launch flags/prefs change incompatibly — forces a fresh user-data-dir
# so a leftover singleton (old socks5 / farbling / host-resolver-rules) cannot reuse the profile.
CHROMIUM_PROFILE_GEN = "http3"

VK_A, VK_C, VK_V, VK_X = 65, 67, 86, 88

IPV6_HINT = (
    "IPv6 parent: в «Хост» — IPv6-шлюз продавца [2001:db8::1], "
    "не IPv4 exit-IP. Строка: [addr]:port:user:pass"
)

def strip_brackets(host: str) -> str:
    host = host.strip()
    if host.startswith("[") and host.endswith("]"):
        return host[1:-1]
    return host

def is_ipv6_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(strip_brackets(host)).version == 6
    except ValueError:
        return False

def is_ipv4_literal(host: str) -> bool:
    try:
        return ipaddress.ip_address(strip_brackets(host)).version == 4
    except ValueError:
        return False

def format_host_for_url(host: str) -> str:
    """Bracket bare IPv6 for CONNECT / Host / display."""
    host = strip_brackets(host)
    if is_ipv6_literal(host):
        return f"[{host}]"
    return host

def format_endpoint(host: str, port: int) -> str:
    return f"{format_host_for_url(host)}:{port}"

def split_host_port(hostport: str) -> tuple[Optional[str], Optional[str]]:
    """Split 'host:port' where host may be [ipv6], ipv4, or hostname."""
    hostport = hostport.strip()
    if not hostport:
        return None, None
    if hostport.startswith("["):
        end = hostport.find("]")
        if end == -1:
            return None, None
        host = hostport[1:end]
        rest = hostport[end + 1 :]
        if rest.startswith(":") and rest[1:]:
            return host, rest[1:]
        return host, None
    if hostport.count(":") == 1:
        host, port_s = hostport.rsplit(":", 1)
        return host, port_s
    return hostport, None

def parse_host_field(text: str) -> tuple[str, Optional[int]]:
    """Parse host field: hostname, IPv4, [IPv6], or [IPv6]:port / host:port."""
    text = text.strip()
    if not text:
        return "", None
    host, port_s = split_host_port(text)
    if host is None:
        return strip_brackets(text), None
    if port_s is not None and port_s.isdigit():
        return strip_brackets(host), int(port_s)
    # Bare IPv6 without brackets (no port) — keep as-is after strip
    return strip_brackets(text if host == text else host), None

def setup_file_logging() -> logging.Logger:
    logger = logging.getLogger("proxy_tool")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    logger.addHandler(handler)
    return logger

log = setup_file_logging()

def basic_auth_header(username: str, password: str) -> bytes:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return f"Proxy-Authorization: Basic {token}\r\n".encode("ascii")

def build_connect_request(target: str, username: str, password: str) -> bytes:
    return (
        f"CONNECT {target} HTTP/1.1\r\n"
        f"Host: {target}\r\n"
        f"Proxy-Connection: Keep-Alive\r\n"
        f"User-Agent: win-http-proxy/1.0\r\n"
    ).encode("ascii") + basic_auth_header(username, password) + b"\r\n"

def _http_status_ok_connect(status_line: str) -> bool:
    parts = status_line.split()
    return len(parts) >= 2 and parts[1] == "200"

def tls_wrap_parent(sock: socket.socket, host: str, timeout: float = CONNECT_TIMEOUT) -> socket.socket:
    """Wrap a socket to the parent in TLS — HTTPS-proxy style: TLS to the proxy
    itself, then a plain HTTP CONNECT tunnel carried inside it.

    Certificate verification is off on purpose. Sellers routinely use
    self-signed certs on their gateway, and a successful CONNECT reply already
    proves we reached a working proxy. The tunnelled payload keeps its own
    end-to-end TLS, so nothing user-visible is weakened.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    sock.settimeout(timeout)
    server_hostname = None if is_ipv6_literal(host) else host
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


def parse_proxy_string(text: str) -> Optional[dict[str, str]]:
    """Parse common seller formats into host/port/user/pass/protocol.

    IPv6: [2001:db8::1]:port:user:pass  or  user:pass@[2001:db8::1]:port
    """
    raw = text.strip().replace(" ", "")
    if not raw:
        return None

    protocol = PROTO_HTTP
    lower = raw.lower()
    if lower.startswith("socks5://"):
        protocol = PROTO_SOCKS5
        raw = raw[9:]
    elif lower.startswith("socks://"):
        protocol = PROTO_SOCKS5
        raw = raw[8:]
    elif lower.startswith("http://"):
        raw = raw[7:]
    elif lower.startswith("https://"):
        protocol = PROTO_HTTPS
        raw = raw[8:]

    # user:pass@host:port  (host may be [ipv6])
    if "@" in raw:
        creds, hostport = raw.rsplit("@", 1)
        if ":" not in creds:
            return None
        user, password = creds.split(":", 1)
        host, port_s = split_host_port(hostport)
        if not host or not port_s or not port_s.isdigit():
            return None
        return {
            "host": strip_brackets(host),
            "port": port_s,
            "username": user,
            "password": password,
            "protocol": protocol,
        }

    # [ipv6]:port:user:pass
    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            return None
        host = raw[1:end]
        rest = raw[end + 1 :]
        if not rest.startswith(":"):
            return None
        parts = rest[1:].split(":")
        if len(parts) < 3 or not parts[0].isdigit():
            return None
        port_s, user = parts[0], parts[1]
        password = ":".join(parts[2:])
        if not is_ipv6_literal(host):
            return None
        return {
            "host": host,
            "port": port_s,
            "username": user,
            "password": password,
            "protocol": protocol,
        }

    parts = raw.split(":")
    # host:port:user:pass  (IPv4 / hostname)
    if len(parts) >= 4 and parts[1].isdigit():
        host, port_s, user = parts[0], parts[1], parts[2]
        password = ":".join(parts[3:])
        return {
            "host": host,
            "port": port_s,
            "username": user,
            "password": password,
            "protocol": protocol,
        }
    # user:pass:host:port
    if len(parts) >= 4 and parts[-1].isdigit():
        port_s, host = parts[-1], parts[-2]
        user, password = parts[0], ":".join(parts[1:-2])
        return {
            "host": host,
            "port": port_s,
            "username": user,
            "password": password,
            "protocol": protocol,
        }
    return None

def socks5_connect(
    upstream_host: str,
    upstream_port: int,
    target_host: str,
    target_port: int,
    username: str,
    password: str,
    timeout: float = UPSTREAM_TIMEOUT,
) -> socket.socket:
    """Open TCP to SOCKS5 proxy, authenticate, CONNECT to target. Returns connected socket."""
    up_host = strip_brackets(upstream_host)
    sock = socket.create_connection((up_host, upstream_port), timeout=CONNECT_TIMEOUT)
    sock.settimeout(timeout)
    try:
        # greeting: ver=5, methods=user/pass (2) and no-auth (0)
        sock.sendall(bytes([0x05, 0x02, 0x00, 0x02]))
        resp = sock.recv(2)
        if len(resp) < 2 or resp[0] != 0x05:
            raise OSError(f"SOCKS5: плохой ответ на handshake: {list(resp)}")
        method = resp[1]
        if method == 0x02:
            u = username.encode("utf-8")
            p = password.encode("utf-8")
            if len(u) > 255 or len(p) > 255:
                raise OSError("SOCKS5: слишком длинный логин/пароль")
            sock.sendall(bytes([0x01, len(u)]) + u + bytes([len(p)]) + p)
            auth = sock.recv(2)
            if len(auth) < 2 or auth[1] != 0x00:
                raise OSError("SOCKS5: авторизация отклонена (логин/пароль)")
        elif method == 0x00:
            pass
        elif method == 0xFF:
            raise OSError("SOCKS5: прокси не принял методы авторизации")
        else:
            raise OSError(f"SOCKS5: неизвестный метод {method}")

        # CONNECT request — ATYP: 0x01 IPv4, 0x04 IPv6, 0x03 domain
        req = bytearray([0x05, 0x01, 0x00])
        tgt = strip_brackets(target_host)
        packed = None
        atyp = 0x03
        try:
            packed = socket.inet_pton(socket.AF_INET, tgt)
            atyp = 0x01
        except OSError:
            try:
                packed = socket.inet_pton(socket.AF_INET6, tgt)
                atyp = 0x04
            except OSError:
                packed = None
        if packed is not None:
            req += bytes([atyp]) + packed
        else:
            host_b = tgt.encode("idna")
            if len(host_b) > 255:
                raise OSError("SOCKS5: слишком длинное имя хоста")
            req += bytes([0x03, len(host_b)]) + host_b
        req += struct.pack("!H", target_port)
        sock.sendall(req)

        # reply: ver, rep, rsv, atyp, bind.addr..., bind.port
        hdr = sock.recv(4)
        if len(hdr) < 4 or hdr[0] != 0x05:
            raise OSError(f"SOCKS5: плохой CONNECT reply: {list(hdr)}")
        if hdr[1] != 0x00:
            codes = {
                1: "general failure",
                2: "not allowed",
                3: "network unreachable",
                4: "host unreachable",
                5: "connection refused",
                6: "TTL expired",
                7: "command not supported",
                8: "address type not supported",
            }
            raise OSError(f"SOCKS5 CONNECT failed: {codes.get(hdr[1], hdr[1])}")
        atyp = hdr[3]
        if atyp == 0x01:
            sock.recv(4 + 2)
        elif atyp == 0x03:
            ln = sock.recv(1)
            sock.recv(ln[0] + 2)
        elif atyp == 0x04:
            sock.recv(16 + 2)
        else:
            raise OSError(f"SOCKS5: unknown atyp {atyp}")
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise

def diagnose_upstream(host: str, port: int, username: str, password: str, timeout: float = 6.0) -> str:
    """Multi-protocol probe; returns a human-readable report. Raises if nothing works."""
    lines: list[str] = []
    host = strip_brackets(host)
    ep = format_endpoint(host, port)

    # TCP
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.close()
        lines.append(f"TCP {ep} — OK")
    except OSError as exc:
        raise RuntimeError(f"TCP {ep} недоступен: {exc}") from exc

    http_ok = False
    socks_ok = False

    # HTTP CONNECT
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(build_connect_request("example.com:443", username, password))
        reply = b""
        while b"\r\n" not in reply:
            chunk = s.recv(4096)
            if not chunk:
                break
            reply += chunk
            if len(reply) > 65536:
                break
        s.close()
        if not reply:
            lines.append("HTTP CONNECT — пустой ответ")
        else:
            status = reply.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            lines.append(f"HTTP CONNECT — {status}")
            if _http_status_ok_connect(status) or status.upper().startswith("HTTP/"):
                http_ok = True
                if "407" in status:
                    http_ok = False
                    lines.append("  -> неверный логин/пароль (407)")
    except TimeoutError:
        lines.append("HTTP CONNECT — timeout (молчание)")
    except OSError as exc:
        lines.append(f"HTTP CONNECT — ошибка: {exc}")

    # SOCKS5
    try:
        s = socks5_connect(host, port, "example.com", 443, username, password, timeout=timeout)
        s.close()
        lines.append("SOCKS5 — OK (CONNECT example.com:443)")
        socks_ok = True
    except TimeoutError:
        lines.append("SOCKS5 — timeout (молчание)")
    except OSError as exc:
        lines.append(f"SOCKS5 — {exc}")

    # HTTPS proxy = TLS to the proxy itself, then CONNECT
    https_ok = False
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((host, port), timeout=timeout)
        raw.settimeout(timeout)
        ss = ctx.wrap_socket(raw, server_hostname=host if not is_ipv6_literal(host) else None)
        ss.sendall(build_connect_request("example.com:443", username, password))
        reply = b""
        while b"\r\n" not in reply:
            chunk = ss.recv(4096)
            if not chunk:
                break
            reply += chunk
            if len(reply) > 65536:
                break
        ss.close()
        if not reply:
            lines.append("HTTPS (TLS-to-proxy) — handshake OK, пустой ответ на CONNECT")
        else:
            status = reply.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
            lines.append(f"HTTPS (TLS-to-proxy) — {status}")
            if _http_status_ok_connect(status) or status.upper().startswith("HTTP/"):
                https_ok = "407" not in status
    except TimeoutError:
        lines.append("HTTPS (TLS-to-proxy) — timeout (TLS handshake или CONNECT)")
    except ssl.SSLError as exc:
        lines.append(f"HTTPS (TLS-to-proxy) — SSL ошибка: {exc}")
    except OSError as exc:
        lines.append(f"HTTPS (TLS-to-proxy) — {exc}")

    report = "\n".join(lines)
    if http_ok or socks_ok or https_ok:
        return report

    raise RuntimeError(
        report
        + "\n\nВывод: порт открыт, но это не рабочий HTTP / HTTPS-proxy / SOCKS5.\n"
        "Частые причины:\n"
        "• у продавца дан exit-IP вместо gateway (нужен host вроде gate.xxx.com)\n"
        "• прокси истёк / ваш IP не в whitelist у продавца\n"
        "• неверный порт или тип\n"
        "• «IPv6-прокси» часто требует отдельный IPv6-шлюз, а не IPv4 из строки\n\n"
        "Напишите продавцу:\n"
        "«Строка user:pass@IP:port: TCP ок, но нет ответа на HTTP CONNECT, "
        "SOCKS5 и TLS(HTTPS-proxy). Пришлите рабочий gateway и протокол.»\n"
        + (f"\n{IPV6_HINT}" if is_ipv4_literal(host) else "")
    )

def probe_upstream(
    host: str,
    port: int,
    username: str,
    password: str,
    protocol: str = PROTO_HTTP,
    timeout: float = 8.0,
) -> str:
    host = strip_brackets(host)
    ep = format_endpoint(host, port)
    if protocol == PROTO_SOCKS5:
        try:
            s = socks5_connect(host, port, "example.com", 443, username, password, timeout=timeout)
            s.close()
            return f"SOCKS5 OK → {ep}"
        except TimeoutError as exc:
            raise RuntimeError(
                f"SOCKS5 {ep}: timeout. Прокси молчит — проверьте gateway/порт/whitelist.\n{IPV6_HINT}"
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"SOCKS5 {ep}: {exc}") from exc

    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError as exc:
        raise RuntimeError(f"Не удалось открыть TCP {ep}: {exc}") from exc

    try:
        sock.settimeout(timeout)
        if protocol == PROTO_HTTPS:
            sock = tls_wrap_parent(sock, host, timeout=timeout)
            sock.settimeout(timeout)
        sock.sendall(build_connect_request("example.com:443", username, password))
        reply = b""
        while b"\r\n" not in reply:
            chunk = sock.recv(4096)
            if not chunk:
                break
            reply += chunk
            if len(reply) > 65536:
                break
    except TimeoutError as exc:
        hint = (
            f"HTTP {ep}: порт открыт, но молчит на CONNECT. "
            "Попробуйте протокол SOCKS5 или другой host (gateway, не exit-IP)."
        )
        if is_ipv4_literal(host):
            hint += f"\n{IPV6_HINT}"
        raise RuntimeError(hint) from exc
    except OSError as exc:
        raise RuntimeError(f"Ошибка обмена с {ep}: {exc}") from exc
    finally:
        try:
            sock.close()
        except OSError:
            pass

    if not reply:
        raise RuntimeError(f"{ep} закрыл соединение без ответа.")

    status = reply.split(b"\x0d\x0a", 1)[0].decode("latin-1", errors="replace")
    if _http_status_ok_connect(status):
        return f"{protocol} OK: {status}"
    if "407" in status:
        raise RuntimeError(f"{protocol} 407 (логин/пароль): {status}")
    if status.upper().startswith("HTTP/"):
        return f"{protocol} отвечает: {status}"
    raise RuntimeError(f"Не HTTP-ответ: {status!r}. Попробуйте SOCKS5.")


def probe_upstream_fast(
    host: str,
    port: int,
    username: str,
    password: str,
    prefer: str = PROTO_HTTP,
    timeout: float = 3.5,
) -> tuple[str, str]:
    """
    Probe preferred + alternate protocol in parallel.
    Returns (protocol, result_message). Prefers user's selection when both work.
    Connect wait ≈ timeout (not serial 8s+8s).
    """
    prefer = prefer if prefer in PROTO_CHOICES else PROTO_HTTP
    alts = [p for p in PROTO_CHOICES if p != prefer]
    alt_hit: Optional[tuple[str, str]] = None
    prefer_err: Optional[BaseException] = None

    with ThreadPoolExecutor(max_workers=1 + len(alts)) as pool:
        fut_map = {
            pool.submit(
                probe_upstream, host, port, username, password, proto, timeout
            ): proto
            for proto in (prefer, *alts)
        }
        try:
            for fut in as_completed(fut_map, timeout=timeout + 1.0):
                proto = fut_map[fut]
                try:
                    msg = fut.result()
                except Exception as exc:
                    if proto == prefer:
                        prefer_err = exc
                        if alt_hit is not None:
                            return alt_hit
                    continue
                if proto == prefer:
                    return prefer, msg
                if alt_hit is None:
                    alt_hit = (proto, msg)
                if prefer_err is not None:
                    return alt_hit
        except TimeoutError:
            pass

    if alt_hit is not None:
        return alt_hit
    if prefer_err is not None:
        raise RuntimeError(str(prefer_err)) from prefer_err
    raise RuntimeError("Parent не отвечает (HTTP/HTTPS/SOCKS5)")

def send_error(client: socket.socket, code: int, reason: str, detail: str) -> None:
    body = detail.encode("utf-8", errors="replace")
    header = (
        f"HTTP/1.1 {code} {reason}\r\n"
        f"Content-Type: text/plain; charset=utf-8\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("ascii")
    try:
        client.sendall(header + body)
    except OSError:
        pass

def parse_target_host_port(target: str, default_port: int = 80) -> tuple[str, int]:
    """Parse CONNECT host:port or absolute URL host (IPv6 with brackets OK)."""
    if "://" in target:
        u = urlparse(target)
        host = u.hostname or strip_brackets(target)
        port = u.port or (443 if u.scheme == "https" else default_port)
        return host, port
    host, port_s = split_host_port(target)
    if host is not None and port_s is not None and port_s.isdigit():
        return strip_brackets(host), int(port_s)
    if host is not None and (port_s is None or not port_s.isdigit()):
        # bare [ipv6] or hostname without port
        return strip_brackets(host), default_port
    return strip_brackets(target), default_port

def _pipe_sockets(a: socket.socket, b: socket.socket, stop: threading.Event) -> None:
    sockets = [a, b]
    try:
        while not stop.is_set():
            readable, _, errored = select.select(sockets, [], sockets, 1.0)
            if errored:
                break
            if not readable:
                continue
            for src in readable:
                data = src.recv(BUFFER)
                if not data:
                    return
                dst = b if src is a else a
                dst.sendall(data)
    except OSError:
        return

def open_via_parent(
    parent_host: str,
    parent_port: int,
    username: str,
    password: str,
    protocol: str,
    target_host: str,
    target_port: int,
) -> socket.socket:
    """Open TCP to target through parent (HTTP CONNECT, HTTPS/TLS-to-parent or SOCKS5)."""
    parent_host = strip_brackets(parent_host)
    target_host = strip_brackets(target_host)
    if protocol == PROTO_SOCKS5:
        return socks5_connect(
            parent_host, parent_port, target_host, target_port, username, password
        )

    sock = socket.create_connection((parent_host, parent_port), timeout=CONNECT_TIMEOUT)
    sock.settimeout(UPSTREAM_TIMEOUT)
    try:
        if protocol == PROTO_HTTPS:
            sock = tls_wrap_parent(sock, parent_host)
            sock.settimeout(UPSTREAM_TIMEOUT)
        target = f"{format_host_for_url(target_host)}:{target_port}"
        sock.sendall(build_connect_request(target, username, password))
        reply = b""
        while b"\r\n\r\n" not in reply:
            chunk = sock.recv(BUFFER)
            if not chunk:
                break
            reply += chunk
            if len(reply) > 1024 * 1024:
                break
        if not reply:
            raise OSError("parent HTTP: пустой ответ на CONNECT")
        status = reply.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        if not _http_status_ok_connect(status):
            raise OSError(f"parent HTTP CONNECT: {status}")
        return sock
    except Exception:
        try:
            sock.close()
        except OSError:
            pass
        raise

class ParentChainService:
    """Local listen (HTTP + SOCKS5) → parent proxy with auth. Pure Python 3proxy-like core."""

    def __init__(
        self,
        parent_host: str,
        parent_port: int,
        username: str,
        password: str,
        listen_port: int,
        protocol: str = PROTO_HTTP,
        on_event: Optional[Callable[[str], None]] = None,
    ):
        self.parent_host = strip_brackets(parent_host)
        self.parent_port = parent_port
        self.username = username
        self.password = password
        self.listen_port = listen_port
        self.socks_port = listen_port + 1
        self.protocol = protocol
        self.on_event = on_event
        self._http_sock: Optional[socket.socket] = None
        self._socks_sock: Optional[socket.socket] = None
        self._threads: list[threading.Thread] = []
        self._stop = threading.Event()
        self._clients_lock = threading.Lock()
        self._active_socks: set[socket.socket] = set()

    def _emit(self, message: str) -> None:
        log.info(message)
        if self.on_event:
            self.on_event(message)

    def _track(self, sock: socket.socket) -> None:
        with self._clients_lock:
            self._active_socks.add(sock)

    def _untrack(self, sock: socket.socket) -> None:
        with self._clients_lock:
            self._active_socks.discard(sock)

    def start(self) -> None:
        if any(t.is_alive() for t in self._threads):
            return
        self._stop.clear()
        self._http_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._http_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._http_sock.bind((LOCAL_HOST, self.listen_port))
        self._http_sock.listen(128)
        self._http_sock.settimeout(1.0)

        self._socks_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socks_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._socks_sock.bind((LOCAL_HOST, self.socks_port))
        self._socks_sock.listen(128)
        self._socks_sock.settimeout(1.0)

        t_http = threading.Thread(target=self._serve_http, name="listen-http", daemon=True)
        t_socks = threading.Thread(target=self._serve_socks, name="listen-socks", daemon=True)
        self._threads = [t_http, t_socks]
        t_http.start()
        t_socks.start()
        parent_ep = format_endpoint(self.parent_host, self.parent_port)
        self._emit(
            f"listen HTTP {LOCAL_HOST}:{self.listen_port} + SOCKS5 {LOCAL_HOST}:{self.socks_port} "
            f"-> parent {self.protocol} {parent_ep}"
        )

    def stop(self) -> None:
        self._stop.set()
        for s in (self._http_sock, self._socks_sock):
            if s:
                try:
                    s.close()
                except OSError:
                    pass
        self._http_sock = None
        self._socks_sock = None
        with self._clients_lock:
            pending = list(self._active_socks)
            self._active_socks.clear()
        for s in pending:
            try:
                s.close()
            except OSError:
                pass
        for t in self._threads:
            t.join(timeout=2.0)
        self._threads = []
        self._emit("listen остановлен")

    def _serve_http(self) -> None:
        assert self._http_sock is not None
        while not self._stop.is_set():
            try:
                client, addr = self._http_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_http_client, args=(client, addr), daemon=True).start()

    def _serve_socks(self) -> None:
        assert self._socks_sock is not None
        while not self._stop.is_set():
            try:
                client, addr = self._socks_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_socks_client, args=(client, addr), daemon=True).start()

    def _open_parent_http(self) -> socket.socket:
        sock = socket.create_connection(
            (self.parent_host, self.parent_port),
            timeout=CONNECT_TIMEOUT,
        )
        sock.settimeout(UPSTREAM_TIMEOUT)
        if self.protocol == PROTO_HTTPS:
            try:
                sock = tls_wrap_parent(sock, self.parent_host)
            except Exception:
                try:
                    sock.close()
                except OSError:
                    pass
                raise
            sock.settimeout(UPSTREAM_TIMEOUT)
        self._track(sock)
        return sock

    def _handle_http_client(self, client: socket.socket, addr: tuple) -> None:
        upstream: Optional[socket.socket] = None
        self._track(client)
        try:
            if self._stop.is_set():
                return
            client.settimeout(UPSTREAM_TIMEOUT)
            request = self._recv_headers(client)
            if not request or self._stop.is_set():
                return

            first_line, rest = request.split(b"\r\n", 1)
            line = first_line.decode("latin-1", errors="replace")
            parts = line.split(" ")
            if len(parts) < 2:
                return
            method = parts[0].upper()
            target = parts[1]
            self._emit(f"HTTP {addr[0]} {method} {target}")

            if self.protocol == PROTO_SOCKS5:
                self._handle_http_via_socks_parent(client, method, target, first_line, rest)
                return

            try:
                upstream = self._open_parent_http()
            except OSError as exc:
                self._emit(f"Нет связи с parent: {exc}")
                send_error(client, 502, "Bad Gateway", f"parent connect failed: {exc}")
                return

            if method == "CONNECT":
                upstream.sendall(build_connect_request(target, self.username, self.password))
                try:
                    reply = self._recv_headers(upstream)
                except TimeoutError:
                    self._emit(f"CONNECT {target}: parent не ответил (timeout)")
                    send_error(client, 504, "Gateway Timeout", "Parent did not answer CONNECT")
                    return
                if not reply:
                    send_error(client, 502, "Bad Gateway", "Empty parent response")
                    return
                status = reply.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")

                # Parent DNS/route failed: retry via locally resolved IPv4
                if (not _http_status_ok_connect(status)) and (
                    b"Host Not Found" in reply or b"502" in reply.split(b"\r\n", 1)[0]
                ):
                    th, tp = parse_target_host_port(target, 443)
                    ip4 = resolve_ipv4(th)
                    if ip4:
                        self._emit(f"CONNECT {target}: {status} -> retry IPv4 {ip4}:{tp}")
                        try:
                            upstream.close()
                        except OSError:
                            pass
                        self._untrack(upstream)
                        try:
                            upstream = self._open_parent_http()
                            retry_target = f"{ip4}:{tp}"
                            upstream.sendall(
                                build_connect_request(retry_target, self.username, self.password)
                            )
                            reply = self._recv_headers(upstream)
                            status = (
                                reply.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
                                if reply
                                else ""
                            )
                        except (OSError, TimeoutError) as exc:
                            self._emit(f"CONNECT retry IPv4 failed: {exc}")
                            send_error(client, 502, "Bad Gateway", f"parent 502 and IPv4 retry failed: {exc}")
                            return

                client.sendall(reply if reply else b"")
                if not reply or not _http_status_ok_connect(status):
                    self._emit(f"CONNECT {target}: {status or 'empty'}")
                    return
                client.settimeout(None)
                upstream.settimeout(None)
                _pipe_sockets(client, upstream, self._stop)
            else:
                forwarded = (
                    first_line
                    + b"\r\n"
                    + basic_auth_header(self.username, self.password)
                    + self._filter_headers(rest)
                )
                if not forwarded.endswith(b"\r\n\r\n"):
                    forwarded += b"\r\n" if forwarded.endswith(b"\r\n") else b"\r\n\r\n"
                upstream.sendall(forwarded)
                client.settimeout(None)
                upstream.settimeout(None)
                _pipe_sockets(client, upstream, self._stop)
        except TimeoutError:
            self._emit(f"Таймаут клиента {addr}")
            log.warning("client timeout %s", addr)
            try:
                send_error(client, 504, "Gateway Timeout", "timeout")
            except OSError:
                pass
        except OSError as exc:
            if not self._stop.is_set():
                self._emit(f"Ошибка клиента {addr}: {exc}")
                log.warning("client error %s: %s", addr, exc)
        finally:
            for s in (client, upstream):
                if s:
                    self._untrack(s)
                    try:
                        s.close()
                    except OSError:
                        pass

    def _handle_http_via_socks_parent(
        self,
        client: socket.socket,
        method: str,
        target: str,
        first_line: bytes,
        rest: bytes,
    ) -> None:
        upstream: Optional[socket.socket] = None
        try:
            if method == "CONNECT":
                host, port = parse_target_host_port(target, 443)
                upstream = socks5_connect(
                    self.parent_host,
                    self.parent_port,
                    host,
                    port,
                    self.username,
                    self.password,
                )
                self._track(upstream)
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                client.settimeout(None)
                upstream.settimeout(None)
                _pipe_sockets(client, upstream, self._stop)
            else:
                host, port = parse_target_host_port(target, 80)
                path = "/"
                if "://" in target:
                    u = urlparse(target)
                    path = u.path or "/"
                    if u.query:
                        path += "?" + u.query
                upstream = socks5_connect(
                    self.parent_host,
                    self.parent_port,
                    host,
                    port,
                    self.username,
                    self.password,
                )
                self._track(upstream)
                new_first = f"{method} {path} HTTP/1.1".encode("latin-1", errors="replace")
                forwarded = new_first + b"\r\n" + self._filter_headers(rest)
                if not forwarded.endswith(b"\r\n\r\n"):
                    forwarded += b"\r\n" if forwarded.endswith(b"\r\n") else b"\r\n\r\n"
                if b"\r\nhost:" not in b"\r\n" + forwarded.lower():
                    host_hdr = format_host_for_url(host)
                    forwarded = (
                        new_first
                        + f"\r\nHost: {host_hdr}\r\n".encode()
                        + self._filter_headers(rest)
                    )
                    if not forwarded.endswith(b"\r\n\r\n"):
                        forwarded += b"\r\n\r\n"
                upstream.sendall(forwarded)
                client.settimeout(None)
                upstream.settimeout(None)
                _pipe_sockets(client, upstream, self._stop)
        finally:
            if upstream:
                self._untrack(upstream)
                try:
                    upstream.close()
                except OSError:
                    pass

    def _handle_socks_client(self, client: socket.socket, addr: tuple) -> None:
        """Local SOCKS5 (no auth) → parent. Like 3proxy socks + parent."""
        upstream: Optional[socket.socket] = None
        self._track(client)
        try:
            client.settimeout(UPSTREAM_TIMEOUT)
            greeting = client.recv(2)
            if len(greeting) < 2 or greeting[0] != 0x05:
                return
            nmethods = greeting[1]
            methods = client.recv(nmethods) if nmethods else b""
            if len(methods) < nmethods:
                return
            # no auth for local listen
            client.sendall(bytes([0x05, 0x00]))
            req = client.recv(4)
            if len(req) < 4 or req[0] != 0x05:
                return
            cmd, atyp = req[1], req[3]
            if cmd != 0x01:  # CONNECT only
                client.sendall(bytes([0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                return
            if atyp == 0x01:
                raw = client.recv(4)
                if len(raw) < 4:
                    return
                host = socket.inet_ntop(socket.AF_INET, raw)
            elif atyp == 0x03:
                ln = client.recv(1)
                if not ln:
                    return
                name = client.recv(ln[0])
                if len(name) < ln[0]:
                    return
                # The idna codec rejects the errors= argument outright, so a
                # single non-ASCII name used to raise UnicodeError and drop the
                # whole socket — every domain-addressed CONNECT died here.
                try:
                    host = name.decode("idna")
                except (UnicodeError, ValueError):
                    host = name.decode("utf-8", errors="replace")
            elif atyp == 0x04:
                raw = client.recv(16)
                if len(raw) < 16:
                    return
                host = socket.inet_ntop(socket.AF_INET6, raw)
            else:
                client.sendall(bytes([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                return
            port_b = client.recv(2)
            if len(port_b) < 2:
                return
            port = struct.unpack("!H", port_b)[0]
            self._emit(f"SOCKS {addr[0]} CONNECT {format_endpoint(host, port)}")
            try:
                upstream = open_via_parent(
                    self.parent_host,
                    self.parent_port,
                    self.username,
                    self.password,
                    self.protocol,
                    host,
                    port,
                )
                self._track(upstream)
            except OSError as exc:
                self._emit(f"SOCKS parent fail: {exc}")
                client.sendall(bytes([0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
                return
            # success + bind 0.0.0.0:0
            client.sendall(bytes([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]))
            client.settimeout(None)
            upstream.settimeout(None)
            _pipe_sockets(client, upstream, self._stop)
        except OSError as exc:
            if not self._stop.is_set():
                self._emit(f"SOCKS ошибка {addr}: {exc}")
        finally:
            for s in (client, upstream):
                if s:
                    self._untrack(s)
                    try:
                        s.close()
                    except OSError:
                        pass

    @staticmethod
    def _recv_headers(sock: socket.socket) -> bytes:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(BUFFER)
            if not chunk:
                break
            data += chunk
            if len(data) > 1024 * 1024:
                break
        return data

    @staticmethod
    def _filter_headers(header_block: bytes) -> bytes:
        if b"\r\n\r\n" in header_block:
            headers, body = header_block.split(b"\r\n\r\n", 1)
            trailing = b"\r\n\r\n" + body
        else:
            headers = header_block.rstrip(b"\r\n")
            trailing = b"\r\n\r\n"

        out_lines: list[bytes] = []
        for line in headers.split(b"\r\n"):
            if not line:
                continue
            lower = line.lower()
            if lower.startswith(b"proxy-authorization:"):
                continue
            if lower.startswith(b"proxy-connection:"):
                continue
            out_lines.append(line)
        return b"\r\n".join(out_lines) + trailing

# Back-compat alias
AuthHttpForwarder = ParentChainService

def resolve_ipv4(host: str) -> Optional[str]:
    """Resolve hostname to IPv4 A record (None if already IP or resolve fails)."""
    host = strip_brackets(host)
    if is_ipv4_literal(host) or is_ipv6_literal(host):
        return None
    try:
        infos = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except OSError:
        return None
    return None

def _macos_network_services() -> list[str]:
    """Active network service names on macOS (Wi-Fi, Ethernet, Thunderbolt Bridge, ...)."""
    try:
        out = subprocess.run(
            ["networksetup", "-listallnetworkservices"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    services: list[str] = []
    for line in out.stdout.splitlines():
        line = line.strip()
        if not line or line.startswith("An asterisk") or line.startswith("*"):
            continue
        services.append(line)
    return services


def _macos_set_system_proxy(
    enable: bool,
    local_port: int = DEFAULT_LOCAL_PORT,
    bypass_hosts: Optional[list[str]] = None,
) -> None:
    """Set/clear the macOS system HTTP+HTTPS proxy for every active network service."""
    host = LOCAL_HOST
    port = str(local_port)
    services = _macos_network_services()
    if not services:
        raise RuntimeError(
            "networksetup недоступен — не удалось определить сетевые сервисы macOS."
        )

    domains = [
        "localhost", "127.0.0.1", "10.*", "192.168.*", "172.16.*/12",
        "*.local", "*.lan",
    ]
    if bypass_hosts:
        for h in bypass_hosts:
            h = strip_brackets(h.strip())
            if h and h not in domains:
                domains.append(h)

    def _run(*args: str) -> None:
        subprocess.run(["networksetup", *args], capture_output=True, text=True, timeout=15, check=False)

    for service in services:
        if enable:
            _run("-setwebproxy", service, host, port)
            _run("-setsecurewebproxy", service, host, port)
            _run("-setwebproxystate", service, "on")
            _run("-setsecurewebproxystate", service, "on")
            _run("-setproxybypassdomains", service, *domains)
        else:
            _run("-setwebproxystate", service, "off")
            _run("-setsecurewebproxystate", service, "off")


def set_system_proxy(
    enable: bool,
    local_port: int = DEFAULT_LOCAL_PORT,
    bypass_hosts: Optional[list[str]] = None,
) -> None:
    """Point the OS at the local IPv4 forwarder (127.0.0.1). Upstream may be IPv6."""
    if IS_MACOS:
        _macos_set_system_proxy(enable, local_port, bypass_hosts)
        return
    if winreg is None or ctypes is None:
        raise RuntimeError("Системный прокси поддерживается только на Windows и macOS.")

    key = winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        winreg.KEY_SET_VALUE,
    )
    try:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if enable:
            server = f"http={LOCAL_HOST}:{local_port};https={LOCAL_HOST}:{local_port}"
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, server)
            # Bypass LAN + loopback so router/Steam local checks don't go through parent
            parts = [
                "localhost",
                "127.*",
                "<local>",
                LOCAL_HOST,
                "10.*",
                "192.168.*",
                "172.16.*",
                "172.17.*",
                "172.18.*",
                "172.19.*",
                "172.20.*",
                "172.21.*",
                "172.22.*",
                "172.23.*",
                "172.24.*",
                "172.25.*",
                "172.26.*",
                "172.27.*",
                "172.28.*",
                "172.29.*",
                "172.30.*",
                "172.31.*",
                "*.local",
                "*.lan",
            ]
            if bypass_hosts:
                for h in bypass_hosts:
                    h = strip_brackets(h.strip())
                    if h and h not in parts:
                        parts.append(h)
            try:
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, ";".join(parts))
            except OSError:
                pass
            try:
                winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, 0)
            except OSError:
                pass
        else:
            # Clear WinINET so Brave/Chrome stop suggesting LAN proxy / auto-detect
            try:
                winreg.SetValueEx(key, "AutoDetect", 0, winreg.REG_DWORD, 0)
            except OSError:
                pass
            try:
                winreg.SetValueEx(key, "AutoConfigURL", 0, winreg.REG_SZ, "")
            except OSError:
                pass
    finally:
        winreg.CloseKey(key)

    internet_set_option = ctypes.windll.wininet.InternetSetOptionW
    internet_set_option(0, 39, 0, 0)
    internet_set_option(0, 37, 0, 0)

def default_config() -> dict[str, Any]:
    return {
        "connections": [],
        "last_selected": "",
        "local_port": DEFAULT_LOCAL_PORT,
        "scope": SCOPE_APPS,
        "apps": [],
        "browser": BROWSER_CHROME,
        "browser_use_proxy": True,
        "browser_profiles": ["default"],
        "last_browser_profile": "default",
    }


def load_config() -> dict[str, Any]:
    if CONFIG_PATH.exists():
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return default_config()
        if "connections" not in data and data.get("host"):
            name = data.get("name") or f"{data.get('host')}:{data.get('port', '')}"
            data = {
                "connections": [
                    {
                        "name": name,
                        "host": data.get("host", ""),
                        "port": int(data.get("port") or 8080),
                        "username": data.get("username", ""),
                        "password": data.get("password", ""),
                        "local_port": int(data.get("local_port") or DEFAULT_LOCAL_PORT),
                        "protocol": data.get("protocol", PROTO_HTTP),
                    }
                ],
                "last_selected": name,
                "local_port": int(data.get("local_port") or DEFAULT_LOCAL_PORT),
            }
            save_config(data)
        for c in data.get("connections", []):
            if c.get("protocol") not in PROTO_CHOICES:
                c["protocol"] = PROTO_HTTP
        data.setdefault("connections", [])
        data.setdefault("last_selected", "")
        data.setdefault("local_port", DEFAULT_LOCAL_PORT)
        data.setdefault("scope", SCOPE_APPS)
        data.setdefault("apps", [])
        data.setdefault("browser", BROWSER_CHROME)
        if data.get("browser") not in BROWSER_CHOICES:
            data["browser"] = BROWSER_CHROME
        data.setdefault("browser_use_proxy", True)
        profiles = data.get("browser_profiles")
        if not isinstance(profiles, list) or not profiles:
            profiles = ["default"]
        cleaned_profiles: list[str] = []
        seen: set[str] = set()
        for item in profiles:
            name = sanitize_profile_dir_name(str(item))
            if name not in seen:
                seen.add(name)
                cleaned_profiles.append(name)
        if not cleaned_profiles:
            cleaned_profiles = ["default"]
        data["browser_profiles"] = cleaned_profiles
        last_bp = sanitize_profile_dir_name(str(data.get("last_browser_profile") or "default"))
        if last_bp not in cleaned_profiles:
            last_bp = cleaned_profiles[0]
        data["last_browser_profile"] = last_bp
        return data
    return default_config()


def proxy_env_for_listen(local_port: int) -> dict[str, str]:
    """Env vars honored by curl/git/python/many Electron apps."""
    http = f"http://{LOCAL_HOST}:{local_port}"
    socks = f"socks5://{LOCAL_HOST}:{local_port + 1}"
    return {
        "HTTP_PROXY": http,
        "HTTPS_PROXY": http,
        "http_proxy": http,
        "https_proxy": http,
        "ALL_PROXY": socks,
        "all_proxy": socks,
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
    }


# ── per-app proxy: env vars alone are not enough ──────────────────────────
# HTTP_PROXY/ALL_PROXY only reach apps that read them. Chromium and Electron
# accept the proxy on the command line; Firefox needs profile prefs; Telegram
# Desktop has no command-line proxy at all.
_CHROMIUM_EXES = frozenset(
    {
        "chrome.exe", "msedge.exe", "brave.exe", "chromium.exe", "vivaldi.exe",
        "opera.exe", "opera_gx.exe", "yandex.exe", "thorium.exe",
        "discord.exe", "slack.exe", "code.exe", "spotify.exe", "signal.exe",
        "whatsapp.exe", "notion.exe", "figma.exe", "obsidian.exe",
    }
)
_FIREFOX_EXES = frozenset(
    {"firefox.exe", "waterfox.exe", "librewolf.exe", "firefox developer edition.exe"}
)
# No command-line proxy support: these read the OS settings or their own only.
_NO_CLI_PROXY_EXES = frozenset({"telegram.exe"})


def app_proxy_argv(exe_path: str, local_port: int) -> tuple[list[str], Optional[str]]:
    """Extra argv that routes one app through the local proxy.

    Returns ``(argv, note)``; ``note`` is a line for the UI log when the app
    cannot be routed automatically.
    """
    label = Path(exe_path).name
    name = label.lower()
    if name in _FIREFOX_EXES:
        try:
            profile = ensure_firefox_profile("app-proxy", local_port, use_proxy=True)
        except OSError as exc:
            return [], f"{label}: профиль не подготовлен — {exc}"
        return (
            ["-no-remote", "-new-instance", "-profile", str(profile)],
            f"{label}: изолированный профиль, SOCKS5 {LOCAL_HOST}:{local_port + 1}",
        )
    if name in _CHROMIUM_EXES:
        return (
            [
                f"--proxy-server=http://{LOCAL_HOST}:{local_port}",
                "--proxy-bypass-list=<-loopback>",
            ],
            f"{label}: --proxy-server={LOCAL_HOST}:{local_port}",
        )
    if name in _NO_CLI_PROXY_EXES:
        return [], (
            f"{label}: прокси из окружения не читает. Задай в нём один раз SOCKS5 "
            f"{LOCAL_HOST}:{local_port + 1} (Настройки → Продвинутые → Тип подключения) — "
            "дальше ходит через прокси при любом запуске."
        )
    return [], None


def launch_app_with_proxy(
    exe_path: str,
    local_port: int,
    args: Optional[list[str]] = None,
    on_note: Optional[Callable[[str], None]] = None,
) -> int:
    path = Path(exe_path)
    if not path.is_file():
        raise FileNotFoundError(f"Не найден файл: {exe_path}")
    env = os.environ.copy()
    env.update(proxy_env_for_listen(local_port))
    extra, note = app_proxy_argv(exe_path, local_port)
    if note and on_note:
        on_note(note)
    return _detached_popen(path, [*(args or []), *extra], env=env)


def _detached_popen(exe_path: Path, args: list[str], env: Optional[dict[str, str]] = None) -> int:
    creation = 0
    if hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
        creation |= subprocess.CREATE_NEW_PROCESS_GROUP  # type: ignore[attr-defined]
    if hasattr(subprocess, "DETACHED_PROCESS"):
        creation |= subprocess.DETACHED_PROCESS  # type: ignore[attr-defined]
    proc = subprocess.Popen(
        [str(exe_path), *args],
        cwd=str(exe_path.parent),
        env=env if env is not None else os.environ.copy(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        creationflags=creation,
        close_fds=True,
    )
    return int(proc.pid)


def _first_existing(paths: list[Path]) -> Optional[Path]:
    seen: set[str] = set()
    for path in paths:
        key = str(path).lower()
        if key in seen:
            continue
        seen.add(key)
        if path.is_file():
            return path
    return None


def _app_path_from_registry(exe_name: str) -> list[Path]:
    found: list[Path] = []
    if winreg is None:
        return found
    for root, sub in (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"),
        (winreg.HKEY_CURRENT_USER, rf"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"),
    ):
        try:
            with winreg.OpenKey(root, sub) as key:
                val, _ = winreg.QueryValueEx(key, "")
                if val:
                    found.append(Path(val))
        except OSError:
            pass
    return found


_MACOS_BROWSER_PATHS = {
    BROWSER_CHROME: [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "~/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    ],
    BROWSER_EDGE: [
        "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
        "~/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    ],
    BROWSER_BRAVE: [
        "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
        "~/Applications/Brave Browser.app/Contents/MacOS/Brave Browser",
    ],
    BROWSER_FIREFOX: [
        "/Applications/Firefox.app/Contents/MacOS/firefox",
        "~/Applications/Firefox.app/Contents/MacOS/firefox",
    ],
}


def _find_browser_macos(kind: str) -> Optional[Path]:
    """Resolve a browser binary inside its .app bundle on macOS."""
    paths = [Path(p).expanduser() for p in _MACOS_BROWSER_PATHS.get(kind, [])]
    return _first_existing(paths)


def find_browser(kind: str) -> Optional[Path]:
    """Resolve installed browser executable by kind."""
    kind = (kind or BROWSER_CHROME).lower().strip()
    if IS_MACOS:
        return _find_browser_macos(kind)
    local = os.environ.get("LOCALAPPDATA", "")
    pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
    pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
    kind = (kind or BROWSER_CHROME).lower().strip()

    if kind == BROWSER_CHROME:
        return _first_existing(
            _app_path_from_registry("chrome.exe")
            + [
                Path(pf) / "Google" / "Chrome" / "Application" / "chrome.exe",
                Path(pf86) / "Google" / "Chrome" / "Application" / "chrome.exe",
                Path(local) / "Google" / "Chrome" / "Application" / "chrome.exe",
            ]
        )
    if kind == BROWSER_EDGE:
        return _first_existing(
            _app_path_from_registry("msedge.exe")
            + [
                Path(pf) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                Path(pf86) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
                Path(local) / "Microsoft" / "Edge" / "Application" / "msedge.exe",
            ]
        )
    if kind == BROWSER_BRAVE:
        return _first_existing(
            _app_path_from_registry("brave.exe")
            + [
                Path(local) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
                Path(pf) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
                Path(pf86) / "BraveSoftware" / "Brave-Browser" / "Application" / "brave.exe",
            ]
        )
    if kind == BROWSER_FIREFOX:
        return _first_existing(
            _app_path_from_registry("firefox.exe")
            + [
                Path(pf) / "Mozilla Firefox" / "firefox.exe",
                Path(pf86) / "Mozilla Firefox" / "firefox.exe",
                Path(local) / "Mozilla Firefox" / "firefox.exe",
            ]
        )
    return None


def sanitize_profile_dir_name(name: str) -> str:
    raw = (name or "default").strip() or "default"
    cleaned = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in raw)
    return cleaned[:80] or "default"


def _is_tmp_profile_dirname(name: str) -> bool:
    """True for tmp_* or Chromium tmp_*__<gen> profile folder names."""
    base = name
    if "__" in name:
        maybe = name.rsplit("__", 1)[0]
        if maybe.startswith("tmp_"):
            base = maybe
    return base.startswith("tmp_")


def _chromium_profile_lock_present(data_dir: Path) -> bool:
    """True if Chromium/Firefox left a profile lock (likely still running)."""
    try:
        if any(
            (data_dir / name).exists()
            for name in ("SingletonLock", "lockfile", "Lock File", "parent.lock")
        ):
            return True
        return any(data_dir.glob("Singleton*"))
    except OSError:
        return False


def _macos_browser_processes_for_profile(marker: str) -> list[tuple[int, str]]:
    """PIDs whose command line references this profile path (macOS: ps -axo)."""
    try:
        out = subprocess.check_output(
            ["ps", "-axo", "pid=,command="],
            stderr=subprocess.DEVNULL,
            timeout=5,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return []
    found: list[tuple[int, str]] = []
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        pid_text, _, command = line.partition(" ")
        if marker not in command.lower():
            continue
        try:
            found.append((int(pid_text), command))
        except ValueError:
            continue
    return found


def _browser_processes_for_profile(data_dir: Path) -> list[tuple[int, str]]:
    """
    PIDs whose command line references this profile path.
    No profile lock → skip process scan (keeps cold Open fast on powerful PCs).
    """
    marker = str(data_dir.resolve()).lower()
    if not marker or not _chromium_profile_lock_present(data_dir):
        return []

    if IS_MACOS:
        return _macos_browser_processes_for_profile(marker)

    found: list[tuple[int, str]] = []
    # WMIC /VALUE: blocks of CommandLine=... / ProcessId=... (no CSV comma issues).
    try:
        out = subprocess.check_output(
            [
                "wmic",
                "process",
                "where",
                "name='chrome.exe' or name='msedge.exe' or name='brave.exe' or name='firefox.exe'",
                "get",
                "ProcessId,CommandLine",
                "/VALUE",
            ],
            stderr=subprocess.DEVNULL,
            timeout=5,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        out = ""

    if out.strip():
        cl_cur = ""
        pid_cur: Optional[int] = None
        for raw in out.splitlines():
            line = raw.strip()
            if not line:
                if pid_cur is not None and marker in cl_cur.lower():
                    found.append((pid_cur, cl_cur))
                cl_cur, pid_cur = "", None
                continue
            low = line.lower()
            if low.startswith("commandline="):
                cl_cur = line.split("=", 1)[1]
            elif low.startswith("processid="):
                try:
                    pid_cur = int(line.split("=", 1)[1].strip())
                except ValueError:
                    pid_cur = None
        if pid_cur is not None and marker in cl_cur.lower():
            found.append((pid_cur, cl_cur))
        if found:
            return found

    # Fallback if WMIC unavailable.
    try:
        out = subprocess.check_output(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                (
                    "Get-CimInstance Win32_Process -Filter "
                    "\"Name='chrome.exe' OR Name='msedge.exe' OR Name='brave.exe' OR Name='firefox.exe'\" "
                    "| Select-Object ProcessId, CommandLine | ConvertTo-Json -Compress"
                ),
            ],
            stderr=subprocess.DEVNULL,
            timeout=6,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.SubprocessError):
        return found
    text = (out or "").strip()
    if not text:
        return found
    try:
        rows = json.loads(text)
    except json.JSONDecodeError:
        return found
    if isinstance(rows, dict):
        rows = [rows]
    if not isinstance(rows, list):
        return found
    for row in rows:
        if not isinstance(row, dict):
            continue
        cl = str(row.get("CommandLine") or "")
        if marker not in cl.lower():
            continue
        try:
            found.append((int(row.get("ProcessId")), cl))
        except (TypeError, ValueError):
            continue
    return found


def _any_browser_using_profile(data_dir: Path) -> bool:
    """True if a Chromium/Firefox process still holds this profile path."""
    return bool(_browser_processes_for_profile(data_dir))


def cleanup_stale_tmp_browser_profiles(max_age_hours: float = 12.0) -> int:
    """Remove orphaned disposable profile dirs older than max_age_hours (if unused)."""
    if not BROWSER_PROFILES_DIR.is_dir():
        return 0
    cutoff = time.time() - max_age_hours * 3600
    removed = 0
    try:
        browser_dirs = list(BROWSER_PROFILES_DIR.iterdir())
    except OSError:
        return 0
    for browser_dir in browser_dirs:
        if not browser_dir.is_dir():
            continue
        try:
            children = list(browser_dir.iterdir())
        except OSError:
            continue
        for profile_dir in children:
            if not profile_dir.is_dir() or not _is_tmp_profile_dirname(profile_dir.name):
                continue
            try:
                mtime = profile_dir.stat().st_mtime
            except OSError:
                continue
            if mtime > cutoff:
                continue
            if _any_browser_using_profile(profile_dir):
                continue
            try:
                shutil.rmtree(profile_dir, ignore_errors=True)
                removed += 1
                log.info("Удалён stale tmp-профиль: %s", profile_dir)
            except OSError:
                pass
    return removed


def watch_disposable_profile(data_dir: Path) -> None:
    """Daemon thread: wait until no browser holds data_dir, then rmtree."""

    def _run() -> None:
        # Give Chromium/Firefox time to spawn real browser processes.
        time.sleep(3.0)
        idle_rounds = 0
        # Cap ~48h of polling (safety); stale cleanup covers the rest.
        for _ in range(57600):
            try:
                if not data_dir.exists():
                    return
            except OSError:
                return
            try:
                in_use = _any_browser_using_profile(data_dir)
            except Exception:
                in_use = True
            if in_use:
                idle_rounds = 0
                time.sleep(3.0)
                continue
            idle_rounds += 1
            # Require a few consecutive idle checks (launcher may exit early).
            if idle_rounds >= 2:
                time.sleep(1.0)
                try:
                    if _any_browser_using_profile(data_dir):
                        idle_rounds = 0
                        time.sleep(3.0)
                        continue
                except Exception:
                    idle_rounds = 0
                    time.sleep(3.0)
                    continue
                shutil.rmtree(data_dir, ignore_errors=True)
                log.info("Удалён disposable профиль: %s", data_dir)
                return
            time.sleep(2.0)

    threading.Thread(target=_run, name=f"tmp-profile-{data_dir.name}", daemon=True).start()


def chromium_profile_root(browser_kind: str, profile_name: str) -> Path:
    """user-data-dir for Chromium. Gen suffix escapes stale singletons (old socks flags)."""
    base = sanitize_profile_dir_name(profile_name)
    return BROWSER_PROFILES_DIR / browser_kind / f"{base}__{CHROMIUM_PROFILE_GEN}"


def _terminate_browsers_for_profile(data_dir: Path) -> int:
    """
    Kill Chromium/Firefox still holding this user-data-dir / profile.
    Otherwise a new Popen reuses the old process and ignores updated --proxy-server flags.
    """
    killed = 0
    for pid, _cl in _browser_processes_for_profile(data_dir):
        try:
            os.kill(pid, 9)
            killed += 1
        except OSError:
            try:
                subprocess.run(
                    ["taskkill", "/F", "/PID", str(pid)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )
                killed += 1
            except OSError:
                pass
    return killed


# Old stealth builds force-blocked these; strip so profiles look like a normal user.
_POISONED_CONTENT_KEYS = (
    "media_stream_mic",
    "media_stream_camera",
    "geolocation",
    "notifications",
)

# Chromium ContentSetting::ALLOW — for Brave fingerprintingV2 this turns farbling OFF
# (default ASK = standard farbling → fv.pro "canvas/audio/screen not real").
_CONTENT_SETTING_ALLOW = 1


def _windows_timezone_name() -> str:
    """Best-effort Windows TZ key (for fv.pro Environment hint)."""
    if winreg is not None:
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\TimeZoneInformation",
            ) as key:
                val, _ = winreg.QueryValueEx(key, "TimeZoneKeyName")
                if val:
                    return str(val)
        except OSError:
            pass
    try:
        return time.tzname[0] or "?"
    except Exception:
        return "?"


def _set_pref_path(prefs: dict[str, Any], dotted: str, value: Any) -> None:
    """Set nested Preferences key like 'brave.reduce_language'."""
    parts = dotted.split(".")
    cur: dict[str, Any] = prefs
    for part in parts[:-1]:
        nxt = cur.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            cur[part] = nxt
        cur = nxt
    cur[parts[-1]] = value


# Browser UI / Accept-Language default (timezone still follows proxy geo).
DEFAULT_BROWSER_LANG = "en-US"
DEFAULT_ACCEPT_LANGUAGES = "en-US,en"


def _recv_http_response(sock: socket.socket, timeout: float) -> tuple[int, bytes]:
    """Read one HTTP response; return (status_code, body)."""
    sock.settimeout(timeout)
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
        if len(buf) > 65536:
            break
    if b"\r\n\r\n" not in buf:
        raise OSError("incomplete HTTP headers")
    header_raw, body = bytes(buf).split(b"\r\n\r\n", 1)
    status_line = header_raw.split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
    parts = status_line.split(" ", 2)
    code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
    headers = header_raw.lower()
    # Content-Length body (geo JSON is small)
    clen = None
    for line in header_raw.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                clen = int(line.split(b":", 1)[1].strip())
            except ValueError:
                clen = None
            break
    if clen is not None:
        while len(body) < clen:
            chunk = sock.recv(min(4096, clen - len(body)))
            if not chunk:
                break
            body += chunk
        body = body[:clen]
    elif b"transfer-encoding: chunked" in headers:
        # minimal chunked decode
        decoded = bytearray()
        rest = body
        while True:
            while b"\r\n" not in rest:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
            if b"\r\n" not in rest:
                break
            size_line, rest = rest.split(b"\r\n", 1)
            try:
                size = int(size_line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                break
            if size == 0:
                break
            while len(rest) < size + 2:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                rest += chunk
            decoded.extend(rest[:size])
            rest = rest[size + 2 :]  # skip data + CRLF
        body = bytes(decoded)
    else:
        sock.settimeout(1.0)
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                body += chunk
                if len(body) > 65536:
                    break
        except (socket.timeout, OSError):
            pass
    return code, body


def _http_get_via_connect_proxy(
    local_port: int,
    host: str,
    port: int,
    path: str,
    timeout: float = 8.0,
    tls: bool = False,
) -> bytes:
    """
    Plain GET through local forwarder using CONNECT (many parents are CONNECT-only;
    absolute-form GET http://… often returns empty/garbage → geo timezone missing).
    """
    t0 = time.monotonic()
    stage = "connect_local"
    sock = socket.create_connection((LOCAL_HOST, local_port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        connect_req = (
            f"CONNECT {host}:{port} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            f"Proxy-Connection: keep-alive\r\n"
            f"\r\n"
        ).encode("ascii")
        stage = "connect_parent"
        sock.sendall(connect_req)
        # Read CONNECT reply only (not the tunneled response)
        hdr = bytearray()
        while b"\r\n\r\n" not in hdr:
            chunk = sock.recv(4096)
            if not chunk:
                raise OSError("empty CONNECT reply")
            hdr.extend(chunk)
            if len(hdr) > 16384:
                raise OSError("CONNECT reply too large")
        status = bytes(hdr).split(b"\r\n", 1)[0].decode("latin-1", errors="replace")
        if not _http_status_ok_connect(status):
            raise OSError(f"CONNECT {host}:{port}: {status}")

        tunnel: socket.socket = sock
        if tls:
            stage = "tls"
            ctx = ssl.create_default_context()
            tunnel = ctx.wrap_socket(sock, server_hostname=host)
            sock = tunnel  # close TLS wrapper in finally

        stage = "http_get"
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: LocalProxy/1.0\r\n"
            f"Accept: application/json\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        ).encode("ascii")
        tunnel.sendall(req)
        code, body = _recv_http_response(tunnel, timeout)
        if code != 200:
            raise OSError(f"GET {host}{path}: HTTP {code}")
        return body
    except Exception as exc:
        raise
    finally:
        try:
            sock.close()
        except OSError:
            pass


def _normalize_geo_payload(data: dict[str, Any]) -> dict[str, str]:
    """Map ip-api / ipapi.co / ipinfo shapes → countryCode, timezone, query."""
    out: dict[str, str] = {}
    cc = data.get("countryCode") or data.get("country_code") or data.get("country")
    if isinstance(cc, str) and len(cc) >= 2:
        out["countryCode"] = cc[:2].upper()
    tz = data.get("timezone") or data.get("time_zone")
    if isinstance(tz, dict):
        tz = tz.get("id") or tz.get("name")
    if tz:
        out["timezone"] = str(tz)
    ip = data.get("query") or data.get("ip") or data.get("ipAddress")
    if ip:
        out["query"] = str(ip)
    return out


_GEO_CACHE: dict[int, tuple[float, dict[str, str]]] = {}
_GEO_CACHE_LOCK = threading.Lock()
_GEO_CACHE_TTL_SEC = 1800.0


def _geo_cache_get(local_port: int) -> dict[str, str]:
    with _GEO_CACHE_LOCK:
        hit = _GEO_CACHE.get(local_port)
    if not hit:
        return {}
    ts, geo = hit
    if time.monotonic() - ts > _GEO_CACHE_TTL_SEC:
        return {}
    return dict(geo)


def _geo_cache_put(local_port: int, geo: dict[str, str]) -> None:
    if not geo.get("timezone"):
        return
    with _GEO_CACHE_LOCK:
        _GEO_CACHE[local_port] = (time.monotonic(), dict(geo))


def _geo_try_one(
    local_port: int,
    host: str,
    port: int,
    path: str,
    tls: bool,
    hint: str,
    timeout: float,
) -> dict[str, str]:
    raw = _http_get_via_connect_proxy(
        local_port, host, port, path, timeout=timeout, tls=tls
    )
    data = json.loads(raw.decode("utf-8", errors="replace"))
    if not isinstance(data, dict):
        raise OSError(f"{hint}: not a JSON object")
    if hint == "ip-api" and data.get("status") and data.get("status") != "success":
        raise OSError(f"ip-api: {data.get('message') or data.get('status')}")
    out = _normalize_geo_payload(data)
    if not out.get("timezone"):
        raise OSError(f"{hint}: no timezone in {list(data.keys())[:8]}")
    out["_via"] = hint
    return out


def fetch_proxy_geo(local_port: int, timeout: float = 10.0) -> dict[str, str]:
    """
    Exit-IP geo via local HTTP listen — for locale + CDP timezone.
    Uses CONNECT tunnels in parallel + short-lived cache (busy parents often time out serial).
    """
    cached = _geo_cache_get(local_port)
    if cached:
        return cached

    attempts: list[tuple[str, int, str, bool, str]] = [
        ("ip-api.com", 80, "/json/?fields=status,message,countryCode,timezone,query", False, "ip-api"),
        ("ipapi.co", 443, "/json/", True, "ipapi"),
        ("ipinfo.io", 443, "/json", True, "ipinfo"),
    ]
    last_err = "no attempts"
    # Parallel — first valid timezone wins (serial 3×timeout was starving Open).
    with ThreadPoolExecutor(max_workers=3) as pool:
        futs = {
            pool.submit(
                _geo_try_one, local_port, host, port, path, tls, hint, timeout
            ): hint
            for host, port, path, tls, hint in attempts
        }
        try:
            for fut in as_completed(futs, timeout=timeout + 2.0):
                hint = futs[fut]
                try:
                    out = fut.result()
                except Exception as exc:
                    last_err = f"{hint}: {exc}"
                    continue
                via = out.pop("_via", hint)
                log.info(
                    "geo via CONNECT %s → %s %s tz=%s",
                    via,
                    out.get("countryCode", "?"),
                    out.get("query", "?"),
                    out["timezone"],
                )
                _geo_cache_put(local_port, out)
                return out
        except TimeoutError:
            last_err = f"parallel wait timed out; {last_err}"

    log.warning("geo timezone missing (%s)", last_err)
    return {}


def _find_free_localhost_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((LOCAL_HOST, 0))
        sock.listen(1)
        return int(sock.getsockname()[1])


_CDP_TZ_TARGET_TYPES = frozenset({"page", "iframe", "other", "background_page"})


class _CdpWebSocket:
    """Minimal masked client WebSocket for Chromium DevTools (localhost only)."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._buf = bytearray()

    @classmethod
    def connect(cls, ws_url: str, timeout: float = 5.0) -> "_CdpWebSocket":
        parsed = urlparse(ws_url)
        if parsed.scheme not in ("ws", "http"):
            raise OSError(f"unsupported DevTools URL scheme: {parsed.scheme}")
        host = parsed.hostname or LOCAL_HOST
        port = int(parsed.port or 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        sock.sendall(req.encode("ascii"))
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = sock.recv(4096)
            if not chunk:
                sock.close()
                raise OSError("DevTools WebSocket handshake closed")
            header += chunk
            if len(header) > 65536:
                sock.close()
                raise OSError("DevTools WebSocket handshake too large")
        status_line = header.split(b"\r\n", 1)[0]
        if b"101" not in status_line:
            sock.close()
            raise OSError(f"DevTools WebSocket upgrade failed: {status_line!r}")
        sep = header.find(b"\r\n\r\n")
        leftover = header[sep + 4 :] if sep >= 0 else b""
        conn = cls(sock)
        if leftover:
            conn._buf.extend(leftover)
        return conn

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    def send_json(self, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        mask = os.urandom(4)
        header = bytearray([0x81])
        n = len(data)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", n))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        self._sock.sendall(header + masked)

    def _recv_exact(self, n: int) -> bytes:
        while len(self._buf) < n:
            chunk = self._sock.recv(max(4096, n - len(self._buf)))
            if not chunk:
                raise OSError("DevTools WebSocket closed")
            self._buf.extend(chunk)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out

    def recv_json(self, timeout: Optional[float] = None) -> dict[str, Any]:
        if timeout is not None:
            self._sock.settimeout(timeout)
        while True:
            b0, b1 = self._recv_exact(2)
            opcode = b0 & 0x0F
            masked = bool(b1 & 0x80)
            length = b1 & 0x7F
            if length == 126:
                length = struct.unpack("!H", self._recv_exact(2))[0]
            elif length == 127:
                length = struct.unpack("!Q", self._recv_exact(8))[0]
            mask = self._recv_exact(4) if masked else b""
            payload = self._recv_exact(length)
            if masked:
                payload = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
            if opcode == 0x8:  # close
                raise OSError("DevTools WebSocket close frame")
            if opcode == 0x9:  # ping → pong
                self._send_raw_frame(0xA, payload)
                continue
            if opcode == 0xA:  # pong
                continue
            if opcode not in (0x1, 0x2):
                continue
            return json.loads(payload.decode("utf-8"))

    def _send_raw_frame(self, opcode: int, payload: bytes) -> None:
        mask = os.urandom(4)
        header = bytearray([0x80 | (opcode & 0x0F)])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", n))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", n))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self._sock.sendall(header + masked)


def _wait_devtools_ws_url(port: int, timeout: float = 15.0) -> str:
    """Poll Chromium DevTools HTTP until /json/version exposes webSocketDebuggerUrl."""
    import urllib.error
    import urllib.request

    url = f"http://{LOCAL_HOST}:{port}/json/version"
    # Never send DevTools polls through the app/upstream proxy.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    deadline = time.time() + timeout
    last_err = "timeout"
    while time.time() < deadline:
        try:
            with opener.open(url, timeout=1.5) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            ws = data.get("webSocketDebuggerUrl") if isinstance(data, dict) else None
            if ws:
                # Normalize host to loopback (some builds advertise 127.0.0.1 already).
                parsed = urlparse(str(ws))
                netloc = f"{LOCAL_HOST}:{port}"
                return urlunparse(("ws", netloc, parsed.path, "", parsed.query, ""))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError, ValueError) as exc:
            last_err = str(exc)
        time.sleep(0.15)
    raise OSError(f"DevTools not ready on {LOCAL_HOST}:{port} ({last_err})")


def _cdp_apply_timezone(
    ws: _CdpWebSocket,
    msg_id: int,
    session_id: Optional[str],
    timezone_id: str,
) -> int:
    msg_id += 1
    payload: dict[str, Any] = {
        "id": msg_id,
        "method": "Emulation.setTimezoneOverride",
        "params": {"timezoneId": timezone_id},
    }
    if session_id:
        payload["sessionId"] = session_id
    ws.send_json(payload)
    return msg_id


def _chromium_cdp_timezone_loop(
    port: int,
    timezone_id: str,
    ready: threading.Event,
    status: dict[str, Any],
) -> None:
    """Keep CDP attached so new tabs inherit timezone override."""
    ws: Optional[_CdpWebSocket] = None
    try:
        ws_url = _wait_devtools_ws_url(port)
        ws = _CdpWebSocket.connect(ws_url, timeout=5.0)
        msg_id = 0

        def cmd(method: str, params: Optional[dict[str, Any]] = None) -> int:
            nonlocal msg_id
            msg_id += 1
            ws.send_json({"id": msg_id, "method": method, "params": params or {}})
            return msg_id

        cmd("Target.setDiscoverTargets", {"discover": True})
        cmd(
            "Target.setAutoAttach",
            {
                "autoAttach": True,
                "waitForDebuggerOnStart": False,
                "flatten": True,
            },
        )
        status["ok"] = True
        status["via"] = "CDP"
        ready.set()
        log.info("CDP TZ override armed → %s (port %s)", timezone_id, port)

        while True:
            try:
                msg = ws.recv_json(timeout=30.0)
            except socket.timeout:
                continue
            if msg.get("method") != "Target.attachedToTarget":
                continue
            params = msg.get("params") or {}
            info = params.get("targetInfo") or {}
            ttype = str(info.get("type") or "")
            session_id = params.get("sessionId")
            if ttype not in _CDP_TZ_TARGET_TYPES or not session_id:
                continue
            msg_id = _cdp_apply_timezone(ws, msg_id, str(session_id), timezone_id)
            status["applied"] = int(status.get("applied") or 0) + 1
            log.debug("CDP TZ applied to %s session (%s)", ttype, timezone_id)
    except Exception as exc:
        status["ok"] = bool(status.get("ok"))
        status["error"] = str(exc)
        if not ready.is_set():
            log.warning("CDP TZ override failed: %s", exc)
        else:
            log.info("CDP TZ watcher ended: %s", exc)
    finally:
        ready.set()
        if ws is not None:
            ws.close()


def start_chromium_timezone_override(
    port: int,
    timezone_id: str,
    ready_timeout: float = 12.0,
    on_ready: Optional[Callable[[bool], None]] = None,
) -> None:
    """
    Start CDP Emulation.setTimezoneOverride in the background (non-blocking).
    Open must not wait for DevTools — that alone cost several seconds.
    """
    ready = threading.Event()
    status: dict[str, Any] = {"ok": False, "applied": 0}
    threading.Thread(
        target=_chromium_cdp_timezone_loop,
        args=(port, timezone_id, ready, status),
        name=f"cdp-tz-{port}",
        daemon=True,
    ).start()

    if on_ready is None:
        return

    def _wait_ready() -> None:
        armed = ready.wait(timeout=ready_timeout)
        ok = bool(armed and status.get("ok"))
        if not ok and not status.get("ok"):
            err = status.get("error") or "DevTools not ready"
            log.warning("TZ override skipped: %s", err)
        try:
            on_ready(ok)
        except Exception:
            pass

    threading.Thread(target=_wait_ready, name=f"cdp-tz-ready-{port}", daemon=True).start()


def ensure_chromium_profile(browser_kind: str, profile_name: str) -> Path:
    """Native Chromium fingerprint; minimal prefs (fv.pro-friendly)."""
    root = chromium_profile_root(browser_kind, profile_name)
    base = sanitize_profile_dir_name(profile_name)
    legacy_candidates = [
        BROWSER_PROFILES_DIR / browser_kind / base,
        BROWSER_PROFILES_DIR / browser_kind / f"{base}__http1",
        BROWSER_PROFILES_DIR / browser_kind / f"{base}__http2",
    ]
    for legacy in legacy_candidates:
        if legacy.is_dir() and legacy.resolve() != root.resolve():
            _terminate_browsers_for_profile(legacy)
            try:
                shutil.rmtree(legacy, ignore_errors=True)
            except OSError:
                pass
    default = root / "Default"
    default.mkdir(parents=True, exist_ok=True)
    prefs_path = default / "Preferences"
    prefs: dict[str, Any] = {}
    if prefs_path.is_file():
        try:
            prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            prefs = {}

    prefs.pop("proxy", None)
    net = prefs.get("net")
    if isinstance(net, dict):
        net.pop("proxy", None)

    # Soft WebRTC: no non-proxied UDP (leak guard) — does not touch canvas/audio/GPU.
    webrtc = prefs.setdefault("webrtc", {})
    webrtc["ip_handling_policy"] = "disable_non_proxied_udp"
    webrtc["multiple_routes_enabled"] = False
    webrtc["nonproxied_udp_enabled"] = False

    prefs.setdefault("browser", {})["has_seen_welcome_page"] = True
    br = prefs.get("browser")
    if isinstance(br, dict):
        br.pop("enable_do_not_track", None)

    prefs.setdefault("intl", {})["accept_languages"] = DEFAULT_ACCEPT_LANGUAGES

    profile = prefs.setdefault("profile", {})
    content = profile.get("default_content_setting_values")
    if not isinstance(content, dict):
        content = {}
        profile["default_content_setting_values"] = content
    for key in _POISONED_CONTENT_KEYS:
        content.pop(key, None)

    # Brave farbling (default Shields fingerprinting) makes canvas/audio/screen look
    # synthetic to fv.pro. ALLOW = protection off = real device APIs.
    if browser_kind == BROWSER_BRAVE:
        content["fingerprintingV2"] = _CONTENT_SETTING_ALLOW
        content["fingerprinting"] = _CONTENT_SETTING_ALLOW  # obsolete v1 key
        _set_pref_path(prefs, "brave.reduce_language", False)
        cs = profile.setdefault("content_settings", {})
        if not isinstance(cs, dict):
            cs = {}
            profile["content_settings"] = cs
        exceptions = cs.setdefault("exceptions", {})
        if not isinstance(exceptions, dict):
            exceptions = {}
            cs["exceptions"] = exceptions
        fp_rule = {
            "*,*": {
                "last_modified": str(int(time.time() * 1_000_000)),
                "setting": _CONTENT_SETTING_ALLOW,
            }
        }
        exceptions["fingerprintingV2"] = fp_rule
        exceptions["fingerprinting"] = fp_rule

    if not content:
        profile.pop("default_content_setting_values", None)

    # Prefer real GPU path (don't leave a prior disable sticky).
    ham = prefs.get("hardware_acceleration_mode")
    if isinstance(ham, dict) and ham.get("enabled") is False:
        ham["enabled"] = True

    prefs.pop("credentials_enable_service", None)
    prefs.pop("credentials_enable_autosignin", None)
    signin = prefs.get("signin")
    if isinstance(signin, dict):
        signin.pop("allowed", None)
        signin.pop("allowed_on_next_startup", None)

    prefs_path.write_text(json.dumps(prefs, ensure_ascii=False, indent=2), encoding="utf-8")

    local_state_path = root / "Local State"
    local_state: dict[str, Any] = {}
    if local_state_path.is_file():
        try:
            local_state = json.loads(local_state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            local_state = {}
    local_state.setdefault("browser", {})["enabled_labs_experiments"] = []
    local_state_path.write_text(json.dumps(local_state, ensure_ascii=False, indent=2), encoding="utf-8")
    return root


def ensure_firefox_profile(
    profile_name: str,
    local_port: int,
    use_proxy: bool = True,
) -> Path:
    """Firefox: SOCKS5+remote DNS; soft WebRTC; English locale."""
    root = BROWSER_PROFILES_DIR / BROWSER_FIREFOX / sanitize_profile_dir_name(profile_name)
    root.mkdir(parents=True, exist_ok=True)
    socks_port = local_port + 1
    if use_proxy:
        proxy_block = (
            'user_pref("network.proxy.type", 1);\n'
            f'user_pref("network.proxy.socks", "{LOCAL_HOST}");\n'
            f'user_pref("network.proxy.socks_port", {socks_port});\n'
            'user_pref("network.proxy.socks_version", 5);\n'
            'user_pref("network.proxy.socks_remote_dns", true);\n'
            'user_pref("network.proxy.no_proxies_on", "localhost, 127.0.0.1");\n'
        )
    else:
        proxy_block = 'user_pref("network.proxy.type", 0);\n'

    lang_block = (
        f'user_pref("intl.accept_languages", "{DEFAULT_ACCEPT_LANGUAGES}");\n'
        f'user_pref("intl.locale.requested", "{DEFAULT_BROWSER_LANG}");\n'
        'user_pref("intl.regional_prefs.use_os_locales", false);\n'
    )

    user_js = (
        "// generated by Proxy tool — fv.pro soft stealth (native canvas/audio)\n"
        + proxy_block
        + lang_block
        + 'user_pref("media.peerconnection.ice.default_address_only", true);\n'
        + 'user_pref("media.peerconnection.ice.no_host", true);\n'
        + 'user_pref("privacy.resistFingerprinting", false);\n'
        + 'user_pref("browser.shell.checkDefaultBrowser", false);\n'
    )
    (root / "user.js").write_text(user_js, encoding="utf-8")
    return root


def _clean_proxy_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "http_proxy",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "SOCKS_PROXY",
        "socks_proxy",
    ):
        env.pop(key, None)
    return env


def launch_isolated_browser(
    profile_name: str,
    local_port: int,
    browser_kind: str = BROWSER_CHROME,
    use_proxy: bool = True,
    on_event: Optional[Callable[[str], None]] = None,
) -> tuple[int, Path, Path, dict[str, str]]:
    """
    fv.pro-oriented launch: native canvas/audio/screen, minimal CLI.
    Chromium family uses local HTTP listen (SOCKS5 caused ERR_CONNECTION_RESET).
    Firefox keeps SOCKS5 + remote DNS. Browser language is en-US; TZ from exit IP via CDP.
    Brave: fingerprinting/farbling off so APIs look real (not randomized).
    Geo+CDP run in background when cache miss so Open is not blocked.
    Returns (pid, exe, data_dir, geo).
    """
    kind = (browser_kind or BROWSER_CHROME).lower().strip()
    if kind not in BROWSER_CHOICES:
        kind = BROWSER_CHROME
    browser = find_browser(kind)
    label = BROWSER_LABELS.get(kind, kind)
    if browser is None:
        raise FileNotFoundError(f"Установи {label}")

    def _notify(msg: str) -> None:
        log.info(msg)
        if on_event:
            on_event(msg)

    env = _clean_proxy_env()
    geo: dict[str, str] = {}
    if use_proxy:
        # Instant path: cache from a prior successful Open/Connect on this listen port.
        geo = _geo_cache_get(local_port)
    tz_id = (geo.get("timezone") or "").strip()
    if tz_id:
        env["TZ"] = tz_id

    dbg_port: Optional[int] = None
    # Always expose DevTools when proxied so background geo can still apply TZ.
    want_cdp = bool(use_proxy)

    if kind == BROWSER_FIREFOX:
        data_dir = ensure_firefox_profile(
            profile_name, local_port, use_proxy=use_proxy
        )
        _terminate_browsers_for_profile(data_dir)
        args = [
            "-no-remote",
            "-new-instance",
            "-profile",
            str(data_dir),
        ]
        if want_cdp:
            dbg_port = _find_free_localhost_port()
            args.append(f"--remote-debugging-port={dbg_port}")
    else:
        data_dir = ensure_chromium_profile(kind, profile_name)
        _terminate_browsers_for_profile(data_dir)
        args = [
            f"--user-data-dir={data_dir}",
            "--no-first-run",
            "--no-default-browser-check",
        ]
        if use_proxy:
            args.insert(1, f"--proxy-server=http://{LOCAL_HOST}:{local_port}")
            args.insert(2, "--proxy-bypass-list=<-loopback>")
        else:
            args.insert(1, "--no-proxy-server")
        args.append(f"--lang={DEFAULT_BROWSER_LANG}")
        if want_cdp:
            dbg_port = _find_free_localhost_port()
            args.append(f"--remote-debugging-port={dbg_port}")
            args.append(f"--remote-debugging-address={LOCAL_HOST}")
            args.append("--remote-allow-origins=*")

    pid = _detached_popen(browser, args, env=env)

    def _apply_tz(geo_now: dict[str, str], via_fetch: bool) -> None:
        tz = (geo_now.get("timezone") or "").strip()
        if not tz:
            _notify("TZ override skipped (no geo timezone)")
            return
        if via_fetch:
            _notify(
                f"geo {geo_now.get('countryCode', '?')} {geo_now.get('query', '?')} "
                f"· proxy TZ {tz}"
            )
        if dbg_port is None:
            if kind == BROWSER_FIREFOX:
                geo_now["tzSpoof"] = tz
                geo_now["tzSpoofVia"] = "TZ"
                _notify(f"TZ override → {tz} (TZ env)")
            else:
                _notify(f"TZ override failed (wanted {tz})")
            return

        def _on_cdp(ok: bool) -> None:
            if ok:
                geo_now["tzSpoof"] = tz
                geo_now["tzSpoofVia"] = "CDP"
                _notify(f"TZ override → {tz} (CDP)")
            elif kind == BROWSER_FIREFOX:
                geo_now["tzSpoof"] = tz
                geo_now["tzSpoofVia"] = "TZ"
                _notify(f"TZ override → {tz} (TZ env)")
            else:
                _notify(f"TZ override failed (wanted {tz})")

        start_chromium_timezone_override(dbg_port, tz, on_ready=_on_cdp)

    def _bg_tz_pipeline() -> None:
        try:
            if tz_id:
                _apply_tz(geo, via_fetch=False)
                return
            if not use_proxy:
                return
            _notify("geo/TZ pending…")
            g = fetch_proxy_geo(local_port, timeout=12.0)
            if g:
                geo.update(g)
                _apply_tz(geo, via_fetch=True)
            else:
                _notify("TZ override skipped (no geo timezone)")
        except Exception as exc:
            log.warning("background geo/TZ failed: %s", exc)
            _notify(f"TZ override failed ({exc})")

    if use_proxy:
        threading.Thread(target=_bg_tz_pipeline, name="geo-tz-bg", daemon=True).start()

    return pid, browser, data_dir, geo



def save_config(data: dict[str, Any]) -> None:
    CONFIG_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    log.debug("Конфиг сохранён (%s профилей)", len(data.get("connections", [])))

def bind_clipboard(root: tk.Misc) -> None:
    def focused_entry() -> Optional[tk.Entry]:
        w = root.focus_get()
        if isinstance(w, (tk.Entry, ttk.Entry)):
            return w  # type: ignore[return-value]
        return None

    def do_copy(_event: tk.Event | None = None) -> str:
        w = focused_entry()
        if w is None:
            return "break"
        try:
            text = w.selection_get()
        except tk.TclError:
            return "break"
        root.clipboard_clear()
        root.clipboard_append(text)
        return "break"

    def do_cut(event: tk.Event | None = None) -> str:
        w = focused_entry()
        if w is None:
            return "break"
        do_copy(event)
        try:
            w.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        return "break"

    def do_paste(_event: tk.Event | None = None) -> str:
        w = focused_entry()
        if w is None:
            return "break"
        try:
            text = root.clipboard_get()
        except tk.TclError:
            return "break"
        try:
            w.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        w.insert("insert", text)
        return "break"

    def do_select_all(_event: tk.Event | None = None) -> str:
        w = focused_entry()
        if w is None:
            return "break"
        w.selection_range(0, "end")
        w.icursor("end")
        return "break"

    def on_ctrl_key(event: tk.Event) -> Optional[str]:
        if not (event.state & 0x4):
            return None
        code = event.keycode
        if code == VK_C:
            return do_copy(event)
        if code == VK_V:
            return do_paste(event)
        if code == VK_X:
            return do_cut(event)
        if code == VK_A:
            return do_select_all(event)
        return None

    for seq, handler in (
        ("<Control-c>", do_copy),
        ("<Control-C>", do_copy),
        ("<Control-v>", do_paste),
        ("<Control-V>", do_paste),
        ("<Control-x>", do_cut),
        ("<Control-X>", do_cut),
        ("<Control-a>", do_select_all),
        ("<Control-A>", do_select_all),
        ("<Control-Insert>", do_copy),
        ("<Shift-Insert>", do_paste),
    ):
        root.bind_all(seq, handler)
    root.bind_all("<Control-KeyPress>", on_ctrl_key)

class ToolTip:
    """Classic hover tooltip for ttk widgets (small bordered Toplevel)."""

    def __init__(self, widget: tk.Misc, text: str, delay: int = 450) -> None:
        self.widget = widget
        self.text = text
        self.delay = delay
        self._after_id: Optional[str] = None
        self._tip: Optional[tk.Toplevel] = None
        widget.bind("<Enter>", self._on_enter, add="+")
        widget.bind("<Leave>", self._on_leave, add="+")
        widget.bind("<ButtonPress>", self._on_leave, add="+")

    def _on_enter(self, _event: object = None) -> None:
        self._cancel()
        try:
            self._after_id = self.widget.after(self.delay, self._show)
        except tk.TclError:
            self._after_id = None

    def _on_leave(self, _event: object = None) -> None:
        self._cancel()
        self._hide()

    def _cancel(self) -> None:
        if self._after_id is not None:
            try:
                self.widget.after_cancel(self._after_id)
            except (tk.TclError, ValueError):
                pass
            self._after_id = None

    def _show(self) -> None:
        self._after_id = None
        if self._tip is not None or not self.text:
            return
        try:
            x = self.widget.winfo_rootx() + 14
            y = self.widget.winfo_rooty() + self.widget.winfo_height() + 6
        except tk.TclError:
            return
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.wm_geometry(f"+{x}+{y}")
        border = tk.Frame(tip, background="#8A96A0")
        border.pack()
        tk.Label(
            border,
            text=self.text,
            justify="left",
            background="#FBFCFD",
            foreground="#2F3A45",
            font=("Tahoma", 8),
            padx=7,
            pady=4,
        ).pack(padx=1, pady=1)
        self._tip = tip

    def _hide(self) -> None:
        if self._tip is not None:
            try:
                self._tip.destroy()
            except tk.TclError:
                pass
            self._tip = None


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Local Proxy")
        self.geometry("470x580")
        self.minsize(450, 520)
        self.configure(bg="#E6EBF0")
        self.forwarder: Optional[ParentChainService] = None
        self.config_data = load_config()
        self._app_paths: list[str] = []
        self._logo_photo: Optional[tk.PhotoImage] = None
        self._icon_photos: list[tk.PhotoImage] = []
        self._tooltips: list["ToolTip"] = []
        self._password_shown = False
        bind_clipboard(self)
        self._apply_window_icon()
        self._build_styles()
        self._build_ui()
        self._refresh_profile_list()
        self._refresh_browser_profile_list()
        self._refresh_apps_list()
        cleaned = cleanup_stale_tmp_browser_profiles()
        if cleaned:
            log.info("Очищено stale tmp-профилей: %s", cleaned)
        log.info("Local Proxy запущено")

    def _build_styles(self) -> None:
        # ── Liquid Glass, light ───────────────────────────────────────
        # Near-white frosted body, glass panels, one accent that matches the
        # Tor mark on the icon.
        self._bg = "#EDF0F6"          # window body (light grey)
        self._face = "#FFFFFF"        # raised glass
        self._ink = "#1E2433"         # primary text
        self._muted = "#6C7688"       # secondary text
        self._slate = "#7B3FE4"       # accent (Tor purple)
        self._slate_hi = "#9A63F0"
        self._slate_press = "#5F2CB8"
        self._warm = "#E5484D"        # danger / disconnect
        self._select = "#CDB8F5"
        self._card = "#FFFFFF"        # field fill
        self._line = "#D5DCE8"        # hairline
        self._glass_hi = "#FFFFFF"    # top edge highlight
        self._accent = self._slate
        self._log_bg = "#F7F9FD"
        self._log_fg = "#2A3550"

        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        ui = ("Segoe UI", 9)
        ui_s = ("Segoe UI", 8)
        ui_b = ("Segoe UI", 9, "bold")

        style.configure(".", background=self._bg, foreground=self._ink, font=ui)
        style.configure("TFrame", background=self._bg)
        style.configure("Panel.TFrame", background=self._bg)
        style.configure("Glass.TFrame", background=self._face)
        style.configure("Divider.TFrame", background=self._line)
        style.configure("TLabel", background=self._bg, foreground=self._ink, font=ui)
        style.configure("Glass.TLabel", background=self._face, foreground=self._ink, font=ui)
        style.configure("Muted.TLabel", background=self._bg, foreground=self._muted, font=ui_s)
        style.configure("Field.TLabel", background=self._bg, foreground=self._muted, font=ui_s)
        style.configure("Brand.TLabel", background=self._bg, foreground=self._ink, font=("Segoe UI", 12, "bold"))
        style.configure("Sub.TLabel", background=self._bg, foreground=self._muted, font=("Segoe UI", 8))
        style.configure("StatusOff.TLabel", background=self._bg, foreground=self._muted, font=ui_s)
        style.configure("StatusOn.TLabel", background=self._bg, foreground="#12855A", font=("Segoe UI", 8, "bold"))

        # fields — inset frosted glass
        style.configure(
            "TEntry",
            fieldbackground=self._card,
            foreground=self._ink,
            insertcolor=self._ink,
            padding=3,
            bordercolor=self._line,
            lightcolor=self._glass_hi,
            darkcolor="#C3CBD9",
        )
        style.map("TEntry", bordercolor=[("focus", self._slate)])
        style.configure(
            "TCombobox",
            fieldbackground=self._card,
            foreground=self._ink,
            background=self._face,
            arrowcolor=self._muted,
            padding=2,
            bordercolor=self._line,
            lightcolor=self._glass_hi,
            darkcolor="#C3CBD9",
        )
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", self._card)],
            foreground=[("readonly", self._ink)],
            selectbackground=[("readonly", self._select)],
            selectforeground=[("readonly", self._ink)],
            bordercolor=[("focus", self._slate)],
        )
        # dropdown list of the combobox (a plain Tk listbox under the hood)
        self.option_add("*TCombobox*Listbox.background", "#FFFFFF")
        self.option_add("*TCombobox*Listbox.foreground", self._ink)
        self.option_add("*TCombobox*Listbox.selectBackground", self._select)
        self.option_add("*TCombobox*Listbox.selectForeground", self._ink)

        # buttons — a bright glass pill for the primary action
        style.configure(
            "Primary.TButton",
            font=ui_b,
            padding=(10, 6),
            background=self._slate,
            foreground="#FFFFFF",
            bordercolor=self._slate_press,
            lightcolor=self._slate_hi,
            darkcolor=self._slate_press,
            borderwidth=1,
            focuscolor=self._slate,
        )
        style.map(
            "Primary.TButton",
            background=[("active", self._slate_hi), ("pressed", self._slate_press),
                        ("disabled", "#E2E6EF")],
            foreground=[("disabled", "#9AA3B5")],
            bordercolor=[("disabled", "#D5DCE8")],
            lightcolor=[("disabled", "#FFFFFF")],
            darkcolor=[("disabled", "#D5DCE8")],
        )
        style.configure(
            "Danger.TButton",
            font=ui_b,
            padding=(10, 6),
            background=self._warm,
            foreground="#FFFFFF",
            bordercolor="#C13A3E",
            lightcolor="#F2686C",
            darkcolor="#C13A3E",
            borderwidth=1,
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#EF5F64"), ("pressed", "#CC3F43"),
                        ("disabled", "#E2E6EF")],
            foreground=[("disabled", "#9AA3B5")],
            bordercolor=[("disabled", "#D5DCE8")],
            lightcolor=[("disabled", "#FFFFFF")],
            darkcolor=[("disabled", "#D5DCE8")],
        )
        style.configure(
            "Ghost.TButton",
            font=ui,
            padding=(5, 2),
            background=self._face,
            foreground=self._ink,
            bordercolor=self._line,
            lightcolor=self._glass_hi,
            darkcolor="#C3CBD9",
            borderwidth=1,
        )
        style.map(
            "Ghost.TButton",
            background=[("active", "#F3F5FA"), ("pressed", "#E4E8F1"),
                        ("disabled", "#F2F4F8")],
            foreground=[("disabled", "#A8B0C0")],
        )
        style.configure(
            "TCheckbutton",
            background=self._bg,
            foreground=self._ink,
            font=ui_s,
            indicatorcolor="#FFFFFF",
            bordercolor=self._line,
            lightcolor=self._glass_hi,
            darkcolor="#C3CBD9",
            focuscolor=self._slate,
        )
        style.map(
            "TCheckbutton",
            background=[("active", self._bg)],
            indicatorcolor=[("selected", self._slate), ("!selected", "#FFFFFF")],
        )
        style.configure(
            "Box.TCheckbutton",
            background=self._bg,
            foreground=self._ink,
            font=ui_s,
            indicatorcolor="#FFFFFF",
            bordercolor=self._line,
        )
        style.map(
            "Box.TCheckbutton",
            background=[("active", self._bg)],
            indicatorcolor=[("selected", self._slate), ("!selected", "#FFFFFF")],
        )
        style.configure("TButton", font=ui, padding=(5, 2), background=self._face,
                        foreground=self._ink, bordercolor=self._line)
        # section cards — frosted glass plates
        style.configure(
            "TLabelframe",
            background=self._bg,
            foreground=self._ink,
            bordercolor=self._line,
            lightcolor=self._glass_hi,
            darkcolor="#C3CBD9",
            relief="solid",
            borderwidth=1,
        )
        style.configure(
            "TLabelframe.Label",
            background=self._bg,
            foreground=self._muted,
            font=("Segoe UI", 8, "bold"),
        )
        style.configure(
            "Vertical.TScrollbar",
            background="#E7EBF3",
            troughcolor=self._bg,
            bordercolor=self._bg,
            arrowcolor=self._muted,
        )
        # notebook — the two-tab shell
        style.configure("TNotebook", background=self._bg, bordercolor=self._line, tabmargins=(2, 4, 2, 0))
        style.configure(
            "TNotebook.Tab",
            background="#E3E8F1",
            foreground=self._muted,
            padding=(16, 6),
            font=("Segoe UI", 9, "bold"),
            bordercolor=self._line,
            lightcolor="#FFFFFF",
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", self._face), ("active", "#EDF1F8")],
            foreground=[("selected", self._slate)],
            expand=[("selected", (0, 0, 0, 0))],
        )

        # real translucency — the "glass" part of Liquid Glass
        try:
            self.attributes("-alpha", 0.98)
        except tk.TclError:
            pass
        # light DWM title bar to match the light body
        self.after(60, self._apply_titlebar_theme)

    def _apply_titlebar_theme(self) -> None:
        """Match the native Windows frame to the light glass body."""
        try:
            import ctypes

            self.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            if not hwnd:
                hwnd = self.winfo_id()
            value = ctypes.c_int(0)          # 0 = light, 1 = dark
            for attr in (20, 19):            # DWMWA_USE_IMMERSIVE_DARK_MODE
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd, attr, ctypes.byref(value), ctypes.sizeof(value)
                )
        except Exception:
            log.debug("title bar theme unavailable", exc_info=True)

    def _build_ui(self) -> None:
        self.geometry("540x620")
        self.minsize(520, 560)
        self.configure(bg=self._bg)

        root = ttk.Frame(self, style="Panel.TFrame", padding=(8, 6))
        root.grid(row=0, column=0, sticky="nsew")
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(1, weight=1)

        self.name_var = tk.StringVar()
        self.host_var = tk.StringVar()
        self.port_var = tk.StringVar(value="8080")
        self.user_var = tk.StringVar()
        self.pass_var = tk.StringVar()
        self.proto_var = tk.StringVar(value=PROTO_HTTP)
        self.local_port_var = tk.StringVar(value=str(self.config_data.get("local_port", DEFAULT_LOCAL_PORT)))
        self.scope_var = tk.StringVar(value=self.config_data.get("scope", SCOPE_APPS))
        self.profile_var = tk.StringVar()
        self.paste_var = tk.StringVar()
        self.system_wide_var = tk.BooleanVar(value=self.scope_var.get() == SCOPE_SYSTEM)
        self.browser_proxy_var = tk.BooleanVar(value=bool(self.config_data.get("browser_use_proxy", True)))
        self.browser_profile_var = tk.StringVar(
            value=str(self.config_data.get("last_browser_profile") or "default")
        )
        self.endpoints_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="○  offline")

        # header
        head = ttk.Frame(root, style="Panel.TFrame")
        head.grid(row=0, column=0, sticky="ew")
        self._logo_photo = None
        for candidate in (
            APP_DIR / "assets" / "localproxy-mark.png",
            APP_DIR / "assets" / "localproxy-logo-128.png",
            APP_DIR / "assets" / "localproxy-logo.png",
            APP_DIR / "assets" / "selfproxy-logo-128.png",
            APP_DIR / "assets" / "selfproxy-logo.png",
            APP_DIR / "assets" / "proxy-logo-128.png",
            APP_DIR / "assets" / "proxy-logo.png",
        ):
            if not candidate.exists():
                continue
            try:
                photo = tk.PhotoImage(file=str(candidate))
                target = 28
                side = max(photo.width(), photo.height())
                if side > target:
                    factor = max(1, side // target)
                    if factor > 1:
                        photo = photo.subsample(factor, factor)
                self._logo_photo = photo
                break
            except tk.TclError:
                continue
        brand_col = 0
        if self._logo_photo is not None:
            ttk.Label(head, image=self._logo_photo, style="Brand.TLabel").grid(
                row=0, column=0, sticky="w", padx=(0, 4)
            )
            brand_col = 1
        ttk.Label(head, text="Local Proxy", style="Brand.TLabel").grid(row=0, column=brand_col, sticky="w")
        status_col = brand_col + 1
        head.columnconfigure(status_col, weight=1)
        self.status_label = ttk.Label(head, textvariable=self.status_var, style="StatusOff.TLabel", cursor="hand2")
        self.status_label.grid(row=0, column=status_col, sticky="e")
        self.status_label.bind("<Double-Button-1>", lambda _e: self.run_diagnose())
        self._tip(self.status_label, "Состояние прокси.\nДвойной клик — диагностика parent.")

        # ── two tabs: connection vs apps/browser ──────────────────
        nb = ttk.Notebook(root)
        nb.grid(row=1, column=0, sticky="nsew", pady=(8, 0))
        tab_conn = ttk.Frame(nb, style="Panel.TFrame", padding=(10, 10))
        tab_apps = ttk.Frame(nb, style="Panel.TFrame", padding=(10, 10))
        nb.add(tab_conn, text="   Подключение   ")
        nb.add(tab_apps, text="   Приложения   ")
        tab_conn.columnconfigure(0, weight=1)
        tab_apps.columnconfigure(0, weight=1)
        tab_apps.rowconfigure(4, weight=1)
        self._tab_conn = tab_conn
        self._tab_apps = tab_apps

        # ── tab 1: parent connection ──────────────────────────────
        box = ttk.LabelFrame(tab_conn, text=" Parent-прокси ", padding=(8, 7))
        box.grid(row=0, column=0, sticky="ew")
        box.columnconfigure(0, weight=1)

        lbl_w = 7

        prow = ttk.Frame(box, style="Panel.TFrame")
        prow.grid(row=0, column=0, sticky="ew", pady=(0, 3))
        prow.columnconfigure(1, weight=1)
        ttk.Label(prow, text="Профиль", style="Field.TLabel", width=lbl_w, anchor="w").grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self.profile_combo = ttk.Combobox(prow, textvariable=self.profile_var, state="readonly", height=6)
        self.profile_combo.grid(row=0, column=1, sticky="ew", padx=(0, 3))
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_selected)
        self._tip(self.profile_combo, "Сохранённые подключения.\nВыбери профиль или создай новый (＋).")
        add_profile_btn = ttk.Button(prow, text="＋", style="Ghost.TButton", width=2, command=self.add_profile)
        add_profile_btn.grid(row=0, column=2, padx=(0, 2))
        self._tip(add_profile_btn, "Новый профиль подключения")
        save_profile_btn = ttk.Button(prow, text="💾", style="Ghost.TButton", width=2, command=self.save_profile)
        save_profile_btn.grid(row=0, column=3, padx=(0, 2))
        self._tip(save_profile_btn, "Сохранить поля в профиль")
        del_profile_btn = ttk.Button(prow, text="✕", style="Ghost.TButton", width=2, command=self.delete_profile)
        del_profile_btn.grid(row=0, column=4)
        self._tip(del_profile_btn, "Удалить профиль")

        paste_row = ttk.Frame(box, style="Panel.TFrame")
        paste_row.grid(row=1, column=0, sticky="ew", pady=(0, 3))
        paste_row.columnconfigure(1, weight=1)
        ttk.Label(paste_row, text="Строка", style="Field.TLabel", width=lbl_w, anchor="w").grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self.paste_entry = ttk.Entry(paste_row, textvariable=self.paste_var)
        self.paste_entry.grid(row=0, column=1, sticky="ew", padx=(0, 3))
        self.paste_entry.bind("<Return>", lambda _e: self.apply_paste())
        self._tip(self.paste_entry, "Вставь строку прокси, например:\nhost:port:user:pass\nuser:pass@host:port")
        paste_btn = ttk.Button(paste_row, text="📋", style="Ghost.TButton", width=3, command=self.apply_paste)
        paste_btn.grid(row=0, column=2)
        self._tip(paste_btn, "Разобрать строку и заполнить поля")

        hrow = ttk.Frame(box, style="Panel.TFrame")
        hrow.grid(row=2, column=0, sticky="ew", pady=(0, 3))
        hrow.columnconfigure(1, weight=1)
        ttk.Label(hrow, text="Хост", style="Field.TLabel", width=lbl_w, anchor="w").grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self.host_entry = ttk.Entry(hrow, textvariable=self.host_var)
        self.host_entry.grid(row=0, column=1, sticky="ew")
        self._tip(self.host_entry, "Адрес parent-прокси (gateway).\nНапр. gate.provider.com или [2001:db8::1]")

        pprow = ttk.Frame(box, style="Panel.TFrame")
        pprow.grid(row=3, column=0, sticky="ew", pady=(0, 3))
        pprow.columnconfigure(3, weight=1)
        ttk.Label(pprow, text="Порт", style="Field.TLabel", width=lbl_w, anchor="w").grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self.port_entry = ttk.Entry(pprow, textvariable=self.port_var, width=7)
        self.port_entry.grid(row=0, column=1, sticky="w")
        self._tip(self.port_entry, "Порт parent-прокси (1–65535)")
        self.proto_combo = ttk.Combobox(
            pprow, textvariable=self.proto_var, values=PROTO_CHOICES, state="readonly", width=8
        )
        self.proto_combo.grid(row=0, column=2, sticky="w", padx=(10, 0))
        self._tip(
            self.proto_combo,
            "Протокол parent:\n"
            "HTTP — обычный CONNECT\n"
            "HTTPS — TLS до прокси, затем CONNECT\n"
            "SOCKS5 — с логином и паролем",
        )

        arow = ttk.Frame(box, style="Panel.TFrame")
        arow.grid(row=4, column=0, sticky="ew", pady=(0, 3))
        arow.columnconfigure(1, weight=1)
        arow.columnconfigure(3, weight=1)
        ttk.Label(arow, text="Логин", style="Field.TLabel", width=lbl_w, anchor="w").grid(
            row=0, column=0, sticky="w", padx=(0, 4)
        )
        self.user_entry = ttk.Entry(arow, textvariable=self.user_var)
        self.user_entry.grid(row=0, column=1, sticky="ew", padx=(0, 6))
        self._tip(self.user_entry, "Логин parent-прокси")
        ttk.Label(arow, text="Пароль", style="Field.TLabel", anchor="w").grid(
            row=0, column=2, sticky="w", padx=(0, 4)
        )
        self.pass_entry = ttk.Entry(arow, textvariable=self.pass_var, show="•")
        self.pass_entry.grid(row=0, column=3, sticky="ew", padx=(0, 3))
        self._tip(self.pass_entry, "Пароль parent-прокси")
        self.pass_toggle = ttk.Button(arow, text="👁", style="Ghost.TButton", width=2, command=self._toggle_password)
        self.pass_toggle.grid(row=0, column=4)
        self._tip(self.pass_toggle, "Показать / скрыть пароль")

        foot = ttk.Frame(box, style="Panel.TFrame")
        foot.grid(row=5, column=0, sticky="ew")
        foot.columnconfigure(2, weight=1)
        sys_cb = ttk.Checkbutton(
            foot,
            text="🖥 Весь ОС через прокси",
            variable=self.system_wide_var,
            command=self._on_system_wide_toggle,
            style="Box.TCheckbutton",
        )
        sys_cb.grid(row=0, column=0, sticky="w")
        self._tip(
            sys_cb,
            "Включено — системный прокси ОС, через прокси идёт весь трафик.\n"
            "Выключено — прокси только для приложений из списка на вкладке «Приложения».",
        )
        diag_btn = ttk.Button(foot, text="🩺 Проверить", style="Ghost.TButton", command=self.run_diagnose)
        diag_btn.grid(row=0, column=1, sticky="w", padx=(8, 0))
        self._tip(diag_btn, "Проверить parent: TCP, HTTP CONNECT, SOCKS5, TLS")
        self.endpoints_var.set(self._endpoints_text())
        ep = ttk.Label(foot, textvariable=self.endpoints_var, style="Muted.TLabel", cursor="hand2")
        ep.grid(row=0, column=2, sticky="e")
        ep.bind("<Button-1>", lambda _e: self.copy_endpoints())
        self._tip(ep, "Локальные адреса прокси.\nКлик — скопировать.")

        hint = ttk.Label(
            tab_conn,
            style="Muted.TLabel",
            justify="left",
            wraplength=470,
            text=(
                "Connect поднимает локальный прокси на 127.0.0.1 и параллельно проверяет "
                "parent по HTTP, HTTPS и SOCKS5 — поднимется на том, который ответил.\n"
                "Список приложений и запуск браузера в изолированном профиле — "
                "на вкладке «Приложения»."
            ),
        )
        hint.grid(row=1, column=0, sticky="nw", pady=(12, 0))

        # ── tab 2: apps + browser + log ───────────────────────────
        self.apps_wrap = ttk.LabelFrame(tab_apps, text=" Apps ", padding=(5, 4))
        self.apps_wrap.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        self.apps_wrap.columnconfigure(0, weight=1)

        self.scope_note = ttk.Label(
            tab_apps,
            style="Muted.TLabel",
            justify="left",
            wraplength=470,
            text=(
                "Весь ОС идёт через прокси — список приложений не нужен.\n"
                "Снимите галочку «Весь ОС через прокси» на вкладке «Подключение», "
                "чтобы проксировать только выбранные приложения."
            ),
        )
        apps_row = ttk.Frame(self.apps_wrap, style="Panel.TFrame")
        apps_row.grid(row=0, column=0, sticky="ew")
        apps_row.columnconfigure(0, weight=1)
        self.apps_list = tk.Listbox(
            apps_row,
            height=6,
            activestyle="dotbox",
            borderwidth=1,
            relief="sunken",
            highlightthickness=0,
            background=self._card,
            foreground=self._ink,
            font=("Courier New", 8),
            selectbackground=self._select,
            selectforeground="#FFFFFF",
            selectmode=tk.EXTENDED,
            exportselection=False,
        )
        self.apps_list.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self.apps_list.bind("<Double-Button-1>", lambda _e: self.launch_selected_apps())
        self._tip(self.apps_list, "Приложения, которые запускаются через локальный прокси.\nДвойной клик — запустить выбранные.")
        ab = ttk.Frame(apps_row, style="Panel.TFrame")
        ab.grid(row=0, column=1, sticky="n")
        add_app_btn = ttk.Button(ab, text="＋", style="Ghost.TButton", width=2, command=self.add_app)
        add_app_btn.grid(row=0, column=0)
        self._tip(add_app_btn, "Добавить .exe в список")
        run_app_btn = ttk.Button(ab, text="▶", style="Ghost.TButton", width=2, command=self.launch_selected_apps)
        run_app_btn.grid(row=1, column=0)
        self._tip(run_app_btn, "Запустить выбранные приложения через прокси")
        del_app_btn = ttk.Button(ab, text="−", style="Ghost.TButton", width=2, command=self.remove_selected_apps)
        del_app_btn.grid(row=2, column=0)
        self._tip(del_app_btn, "Убрать из списка")

        # ── always-visible action bar (below the tabs) ────────────
        row1 = ttk.Frame(root, style="Panel.TFrame")
        row1.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        row1.columnconfigure(0, weight=1)
        self.connect_btn = ttk.Button(row1, text="⚡ Connect", style="Primary.TButton", command=self.toggle_proxy)
        self.connect_btn.grid(row=0, column=0, sticky="ew", padx=(0, 3))
        self._tip(self.connect_btn, "Запустить локальный прокси (Enter).\nПовторное нажатие — остановить.")
        self.disconnect_btn = ttk.Button(
            row1,
            text="⏻ Disconnect",
            style="Danger.TButton",
            command=self.disconnect_proxy,
            state="disabled",
        )
        self.disconnect_btn.grid(row=0, column=1, sticky="ew")
        self._tip(
            self.disconnect_btn,
            "Разорвать соединение: остановить listener,\nснять системный прокси и закрыть туннели.",
        )

        row2 = ttk.Frame(tab_apps, style="Panel.TFrame")
        row2.grid(row=2, column=0, sticky="ew", pady=(8, 0))
        row2.columnconfigure(1, weight=1)
        saved_browser = str(self.config_data.get("browser", BROWSER_CHROME)).lower()
        if saved_browser not in BROWSER_CHOICES:
            saved_browser = BROWSER_CHROME
        self.browser_var = tk.StringVar(value=BROWSER_LABELS[saved_browser])
        self.browser_combo = ttk.Combobox(
            row2,
            textvariable=self.browser_var,
            values=tuple(BROWSER_LABELS[k] for k in BROWSER_CHOICES),
            state="readonly",
            width=8,
        )
        self.browser_combo.grid(row=0, column=0, sticky="w", padx=(0, 3))
        self.browser_combo.bind("<<ComboboxSelected>>", self._on_browser_selected)
        self._tip(self.browser_combo, "Браузер для запуска (в изолированном профиле).")
        browser_proxy_cb = ttk.Checkbutton(
            row2,
            text="через прокси",
            variable=self.browser_proxy_var,
            command=self._on_browser_proxy_toggle,
            style="Box.TCheckbutton",
        )
        browser_proxy_cb.grid(row=0, column=1, sticky="w", padx=(0, 3))
        self._tip(browser_proxy_cb, "Открывать браузер через локальный прокси.\nВыкл — браузер пойдёт напрямую.")
        open_browser_btn = ttk.Button(row2, text="🌐 Open", style="Ghost.TButton", command=self.launch_browser_profile)
        open_browser_btn.grid(row=0, column=2, sticky="e")
        self._tip(open_browser_btn, "Открыть браузер с выбранным профилем")

        # browser profile (isolated user-data-dir) — separate from proxy connection profile
        row_bp = ttk.Frame(tab_apps, style="Panel.TFrame")
        row_bp.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        row_bp.columnconfigure(1, weight=1)
        ttk.Label(row_bp, text="профиль", style="Muted.TLabel").grid(row=0, column=0, sticky="w", padx=(0, 3))
        self.browser_profile_combo = ttk.Combobox(
            row_bp,
            textvariable=self.browser_profile_var,
            height=6,
        )
        self.browser_profile_combo.grid(row=0, column=1, sticky="ew", padx=(0, 3))
        self.browser_profile_combo.bind("<<ComboboxSelected>>", self._on_browser_profile_selected)
        self.browser_profile_combo.bind("<Return>", lambda _e: self.save_browser_profile_name())
        self._tip(self.browser_profile_combo, "Профиль браузера (отдельный каталог данных).")
        bp_save_btn = ttk.Button(row_bp, text="＋", style="Ghost.TButton", width=2, command=self.save_browser_profile_name)
        bp_save_btn.grid(row=0, column=2, padx=(0, 2))
        self._tip(bp_save_btn, "Сохранить / создать профиль браузера")
        bp_del_btn = ttk.Button(row_bp, text="✕", style="Ghost.TButton", width=2, command=self.delete_browser_profile)
        bp_del_btn.grid(row=0, column=3, padx=(0, 2))
        self._tip(bp_del_btn, "Удалить профиль браузера")
        bp_tmp_btn = ttk.Button(row_bp, text="⚡ tmp", style="Ghost.TButton", command=self.launch_disposable_browser)
        bp_tmp_btn.grid(row=0, column=4, sticky="e")
        self._tip(bp_tmp_btn, "Разовый профиль — удалится после закрытия браузера")

        log_frame = ttk.LabelFrame(tab_apps, text=" Log ", padding=(6, 4))
        log_frame.grid(row=4, column=0, sticky="nsew", pady=(8, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(1, weight=1)

        log_head = ttk.Frame(log_frame, style="Panel.TFrame")
        log_head.grid(row=0, column=0, sticky="ew", pady=(0, 2))
        log_head.columnconfigure(0, weight=1)
        ttk.Label(log_head, text="двойной клик — очистить", style="Muted.TLabel").grid(row=0, column=0, sticky="w")
        clear_log_btn = ttk.Button(log_head, text="🧹 Очистить", style="Ghost.TButton", command=self.clear_log)
        clear_log_btn.grid(row=0, column=1, sticky="e")
        self._tip(clear_log_btn, "Очистить журнал")

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            wrap="word",
            state="disabled",
            bg=self._log_bg,
            fg=self._log_fg,
            insertbackground=self._log_fg,
            relief="sunken",
            borderwidth=1,
            font=("Courier New", 7),
            padx=3,
            pady=2,
        )
        self.log_text.grid(row=1, column=0, sticky="nsew")
        self.log_text.bind("<Double-Button-1>", lambda _e: self.clear_log())
        self._tip(self.log_text, "Журнал работы прокси.\nДвойной клик — очистить.")

        self.bind("<Return>", lambda _e: self._on_enter_key())
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self._sync_apps_visibility()

    def _set_status(self, text: str, online: bool = False) -> None:
        if online:
            self.status_var.set(f"●  {text}")
        else:
            bare = text.strip()
            if not bare.startswith("○") and not bare.startswith("━"):
                bare = f"○  {bare}"
            self.status_var.set(bare)
        if hasattr(self, "status_label"):
            self.status_label.configure(style="StatusOn.TLabel" if online else "StatusOff.TLabel")
        if hasattr(self, "connect_btn"):
            if online:
                # cable break symbol for disconnect
                self.connect_btn.configure(text="━╳━ Disconnect", style="Danger.TButton")
            else:
                self.connect_btn.configure(text="⚡ Connect", style="Primary.TButton")
        if hasattr(self, "disconnect_btn"):
            try:
                self.disconnect_btn.configure(state="normal" if online else "disabled")
            except tk.TclError:
                pass


    def _tip(self, widget: tk.Misc, text: str) -> None:
        self._tooltips.append(ToolTip(widget, text))

    def _toggle_password(self) -> None:
        if not hasattr(self, "pass_entry"):
            return
        self._password_shown = not getattr(self, "_password_shown", False)
        try:
            self.pass_entry.configure(show="" if self._password_shown else "•")
        except tk.TclError:
            return
        if hasattr(self, "pass_toggle"):
            self.pass_toggle.configure(text="🙈" if self._password_shown else "👁")

    def _apply_window_icon(self) -> None:
        def first(*names: str) -> Optional[Path]:
            for name in names:
                p = APP_DIR / "assets" / name
                if p.exists():
                    return p
            return None

        ico = first("localproxy.ico", "selfproxy.ico", "proxy.ico")
        png = first("localproxy-logo-128.png", "localproxy-logo.png",
                    "selfproxy-logo-128.png", "selfproxy-logo.png",
                    "proxy-logo-128.png", "proxy-logo.png")
        try:
            if ico is not None:
                self.iconbitmap(default=str(ico))
        except tk.TclError:
            pass
        if png is not None:
            try:
                photo = tk.PhotoImage(file=str(png))
                self._icon_photos.append(photo)
                self.iconphoto(True, photo)
            except tk.TclError:
                pass

    def _ui_log(self, message: str) -> None:
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"{stamp}  {message}\n"

        def append() -> None:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line)
            lines = int(self.log_text.index("end-1c").split(".")[0])
            if lines > 200:
                self.log_text.delete("1.0", f"{lines - 150}.0")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")

        self.after(0, append)

    def _endpoints_text(self) -> str:
        try:
            lp = int(self.local_port_var.get().strip())
        except (ValueError, AttributeError, tk.TclError):
            lp = int(self.config_data.get("local_port", DEFAULT_LOCAL_PORT))
        return f"🔗  {LOCAL_HOST}:{lp}  ·  :{lp + 1}"

    def _on_system_wide_toggle(self) -> None:
        self.scope_var.set(SCOPE_SYSTEM if self.system_wide_var.get() else SCOPE_APPS)
        self.config_data["scope"] = self.scope_var.get()
        save_config(self.config_data)
        self._sync_apps_visibility()

    def _sync_apps_visibility(self) -> None:
        if not hasattr(self, "apps_wrap"):
            return
        if self.system_wide_var.get():
            self.apps_wrap.grid_remove()
            if hasattr(self, "scope_note"):
                self.scope_note.grid(row=1, column=0, sticky="nw", pady=(10, 0))
        else:
            if hasattr(self, "scope_note"):
                self.scope_note.grid_remove()
            self.apps_wrap.grid()

    def _on_enter_key(self) -> None:
        focus = self.focus_get()
        if focus is getattr(self, "paste_entry", None):
            self.apply_paste()
            return
        if focus is getattr(self, "browser_profile_combo", None):
            self.save_browser_profile_name()
            return
        self.toggle_proxy()

    def _on_scope_change(self) -> None:
        self._on_system_wide_toggle()

    def _browser_profiles(self) -> list[str]:
        raw = self.config_data.get("browser_profiles")
        if not isinstance(raw, list) or not raw:
            return ["default"]
        names: list[str] = []
        seen: set[str] = set()
        for item in raw:
            name = sanitize_profile_dir_name(str(item))
            if name not in seen:
                seen.add(name)
                names.append(name)
        return names or ["default"]

    def _refresh_browser_profile_list(self, select_name: Optional[str] = None) -> None:
        names = self._browser_profiles()
        self.config_data["browser_profiles"] = names
        if hasattr(self, "browser_profile_combo"):
            self.browser_profile_combo["values"] = names
        target = select_name or self.config_data.get("last_browser_profile") or names[0]
        target = sanitize_profile_dir_name(str(target))
        if target not in names:
            target = names[0]
        self.browser_profile_var.set(target)
        self.config_data["last_browser_profile"] = target

    def _on_browser_profile_selected(self, _event: object = None) -> None:
        name = sanitize_profile_dir_name(self.browser_profile_var.get())
        self.browser_profile_var.set(name)
        self.config_data["last_browser_profile"] = name
        save_config(self.config_data)
        self._ui_log(f"browser profile {name}")

    def save_browser_profile_name(self) -> None:
        name = sanitize_profile_dir_name(self.browser_profile_var.get())
        names = self._browser_profiles()
        if name not in names:
            names.append(name)
        self.config_data["browser_profiles"] = names
        self.config_data["last_browser_profile"] = name
        save_config(self.config_data)
        self._refresh_browser_profile_list(select_name=name)
        self._ui_log(f"browser profile + {name}")

    def delete_browser_profile(self) -> None:
        name = sanitize_profile_dir_name(self.browser_profile_var.get())
        names = self._browser_profiles()
        if name not in names:
            self._ui_log(f"browser profile ? {name}")
            return
        if name == "default" and len(names) == 1:
            messagebox.showinfo("профиль", "Нельзя удалить единственный default")
            return
        if not messagebox.askyesno("Удалить профиль браузера", f"{name}?"):
            return
        names = [n for n in names if n != name]
        if not names:
            names = ["default"]
        self.config_data["browser_profiles"] = names
        if self.config_data.get("last_browser_profile") == name:
            self.config_data["last_browser_profile"] = names[0]
        save_config(self.config_data)
        kind = self._selected_browser_kind()
        if kind == BROWSER_FIREFOX:
            disk = BROWSER_PROFILES_DIR / BROWSER_FIREFOX / sanitize_profile_dir_name(name)
        else:
            disk = chromium_profile_root(kind, name)
        if disk.is_dir():
            _terminate_browsers_for_profile(disk)
            if not _any_browser_using_profile(disk):
                shutil.rmtree(disk, ignore_errors=True)
        self._refresh_browser_profile_list()
        self._ui_log(f"browser profile del {name}")

    def _refresh_apps_list(self) -> None:
        raw = self.config_data.get("apps", [])
        self._app_paths = []
        for item in raw:
            path = item if isinstance(item, str) else item.get("path", "")
            if path:
                self._app_paths.append(path)
        self.apps_list.delete(0, tk.END)
        for path in self._app_paths:
            self.apps_list.insert(tk.END, Path(path).name)

    def _save_apps_from_list(self) -> None:
        self.config_data["apps"] = list(self._app_paths)
        save_config(self.config_data)

    def add_app(self) -> None:
        path = filedialog.askopenfilename(
            title="Выбери .exe",
            filetypes=[("Programs", "*.exe"), ("All", "*.*")],
        )
        if not path:
            return
        if path in self._app_paths:
            return
        self._app_paths.append(path)
        self.apps_list.insert(tk.END, Path(path).name)
        self._save_apps_from_list()

    def remove_selected_apps(self) -> None:
        sel = list(self.apps_list.curselection())
        if not sel:
            return
        for i in reversed(sel):
            self.apps_list.delete(i)
            del self._app_paths[i]
        self._save_apps_from_list()

    def copy_endpoints(self) -> None:
        text = self._endpoints_text()
        self.clipboard_clear()
        self.clipboard_append(text)
        self._ui_log(f"copied {text}")

    def launch_selected_apps(self) -> None:
        if not self.forwarder:
            messagebox.showwarning("○ Offline", "Сначала ⚡ Connect")
            return
        try:
            local_port = int(self.local_port_var.get().strip())
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный listen порт")
            return
        sel = list(self.apps_list.curselection()) or list(range(len(self._app_paths)))
        if not sel:
            messagebox.showinfo("📦 Apps", "Добавь .exe кнопкой ＋")
            return
        for i in sel:
            path = self._app_paths[i]
            try:
                pid = launch_app_with_proxy(path, local_port, on_note=self._ui_log)
                self._ui_log(f"▶ {Path(path).name} #{pid}")
            except OSError as exc:
                messagebox.showerror("Launch", f"{Path(path).name}\n{exc}")

    def _selected_browser_kind(self) -> str:
        label = (self.browser_var.get() if hasattr(self, "browser_var") else "").strip()
        for kind, name in BROWSER_LABELS.items():
            if name == label:
                return kind
        return BROWSER_CHROME

    def _on_browser_selected(self, _event: object = None) -> None:
        kind = self._selected_browser_kind()
        self.config_data["browser"] = kind
        save_config(self.config_data)
        path = find_browser(kind)
        mark = "✓" if path else "✗"
        self._ui_log(f"🌐 {BROWSER_LABELS[kind]} {mark}")

    def _on_browser_proxy_toggle(self) -> None:
        self.config_data["browser_use_proxy"] = bool(self.browser_proxy_var.get())
        save_config(self.config_data)
        mode = "прокси" if self.browser_proxy_var.get() else "direct"
        self._ui_log(f"🌐 Open → {mode}")

    def _prepare_browser_launch(self) -> tuple[bool, int, str]:
        """Shared checks for Open / disposable. Returns (use_proxy, local_port, kind)."""
        use_proxy = bool(self.browser_proxy_var.get()) if hasattr(self, "browser_proxy_var") else True
        if use_proxy and not self.forwarder:
            messagebox.showwarning("○ Offline", "Сначала ⚡ Connect\nили сними «через прокси»")
            raise RuntimeError("offline")
        try:
            local_port = int(self.local_port_var.get().strip())
        except ValueError:
            local_port = int(self.config_data.get("local_port", DEFAULT_LOCAL_PORT))

        # Never leave Windows system proxy on for isolated browser launch
        # (Brave shows ERR_CONNECTION_RESET / "снимите флажок LAN proxy" otherwise)
        if self.system_wide_var.get():
            self.system_wide_var.set(False)
            self.scope_var.set(SCOPE_APPS)
            self.config_data["scope"] = SCOPE_APPS
            self._ui_log("WinINET system proxy → off (browser uses --proxy-server)")
        try:
            set_system_proxy(False)
        except RuntimeError as exc:
            self._ui_log(str(exc))

        kind = self._selected_browser_kind()
        self.config_data["browser"] = kind
        self.config_data["browser_use_proxy"] = use_proxy
        return use_proxy, local_port, kind

    def _log_browser_launch(
        self,
        kind: str,
        use_proxy: bool,
        browser: Path,
        pid: int,
        data_dir: Path,
        local_port: int,
        geo: Optional[dict[str, str]] = None,
    ) -> None:
        if use_proxy:
            if kind == BROWSER_FIREFOX:
                via = f"socks5 {LOCAL_HOST}:{local_port + 1}"
            else:
                via = f"http {LOCAL_HOST}:{local_port}"
            self._ui_log(f"🌐 {BROWSER_LABELS[kind]} · {via} · {browser.name} #{pid}")
            if geo and geo.get("timezone"):
                tz = geo.get("timezone", "?")
                cc = geo.get("countryCode", "?")
                ip = geo.get("query", "?")
                win_tz = _windows_timezone_name()
                self._ui_log(f"geo {cc} {ip} · proxy TZ {tz}")
                self._ui_log(f"Windows TZ: {win_tz}")
                if kind == BROWSER_BRAVE:
                    self._ui_log("Brave farbling off (fingerprinting ALLOW)")
                spoof = geo.get("tzSpoof")
                if spoof:
                    via_tz = geo.get("tzSpoofVia", "CDP")
                    self._ui_log(f"TZ override → {spoof} ({via_tz})")
            elif use_proxy:
                if kind == BROWSER_BRAVE:
                    self._ui_log("Brave farbling off (fingerprinting ALLOW)")
                # geo/TZ lines come from background via on_event
        else:
            self._ui_log(f"🌐 {BROWSER_LABELS[kind]} · direct · {browser.name} #{pid}")
        self._ui_log(f"profile {data_dir}")
        self._sync_apps_visibility()

    def launch_browser_profile(self) -> None:
        threading.Thread(
            target=cleanup_stale_tmp_browser_profiles, name="tmp-cleanup", daemon=True
        ).start()
        try:
            use_proxy, local_port, kind = self._prepare_browser_launch()
        except RuntimeError:
            return

        name = sanitize_profile_dir_name(self.browser_profile_var.get())
        names = self._browser_profiles()
        if name not in names:
            names.append(name)
        self.config_data["browser_profiles"] = names
        self.config_data["last_browser_profile"] = name
        save_config(self.config_data)
        self._refresh_browser_profile_list(select_name=name)

        try:
            pid, browser, data_dir, geo = launch_isolated_browser(
                name, local_port, browser_kind=kind, use_proxy=use_proxy, on_event=self._ui_log
            )
        except FileNotFoundError as exc:
            messagebox.showerror("🌐 Browser", str(exc))
            return
        except OSError as exc:
            messagebox.showerror("🌐 Browser", str(exc))
            return
        self._log_browser_launch(kind, use_proxy, browser, pid, data_dir, local_port, geo)

    def launch_disposable_browser(self) -> None:
        """One-shot tmp profile: not added to saved list; deleted after browser exits."""
        threading.Thread(
            target=cleanup_stale_tmp_browser_profiles, name="tmp-cleanup", daemon=True
        ).start()
        try:
            use_proxy, local_port, kind = self._prepare_browser_launch()
        except RuntimeError:
            return

        name = f"tmp_{int(time.time())}_{os.getpid()}"
        save_config(self.config_data)
        try:
            pid, browser, data_dir, geo = launch_isolated_browser(
                name, local_port, browser_kind=kind, use_proxy=use_proxy, on_event=self._ui_log
            )
        except FileNotFoundError as exc:
            messagebox.showerror("🌐 Browser", str(exc))
            return
        except OSError as exc:
            messagebox.showerror("🌐 Browser", str(exc))
            return
        watch_disposable_profile(data_dir)
        self._ui_log(f"⚡ tmp {name}")
        self._log_browser_launch(kind, use_proxy, browser, pid, data_dir, local_port, geo)

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def toggle_proxy(self) -> None:
        if getattr(self, "_connecting", False):
            return
        if self.forwarder:
            self.disable_proxy()
        else:
            self.enable_proxy()

    def disconnect_proxy(self) -> None:
        """Explicit disconnect — no toggle guessing: stop the listener, drop the
        system proxy and let live tunnels die with their sockets."""
        if getattr(self, "_connecting", False):
            return
        if not self.forwarder:
            self._set_status("offline", online=False)
            return
        self.disable_proxy()

    def apply_paste(self) -> None:
        text = self.paste_var.get().strip()
        if not text:
            try:
                text = self.clipboard_get().strip()
                self.paste_var.set(text)
            except tk.TclError:
                messagebox.showwarning("Paste", "Буфер пуст")
                return
        parsed = parse_proxy_string(text)
        if not parsed:
            messagebox.showerror("Paste", "Формат: user:pass@host:port")
            return
        self.host_var.set(parsed["host"])
        self.port_var.set(parsed["port"])
        self.user_var.set(parsed["username"])
        self.pass_var.set(parsed["password"])
        self.proto_var.set(parsed["protocol"])
        self.name_var.set(format_endpoint(parsed["host"], int(parsed["port"])))
        self._ui_log(f"ok {parsed['protocol']} {format_endpoint(parsed['host'], int(parsed['port']))}")

    def _connections(self) -> list[dict[str, Any]]:
        return list(self.config_data.get("connections", []))

    def _refresh_profile_list(self, select_name: Optional[str] = None) -> None:
        names = [c["name"] for c in self._connections()]
        self.profile_combo["values"] = names
        target = select_name or self.config_data.get("last_selected") or (names[0] if names else "")
        if target and target in names:
            self.profile_var.set(target)
            self._load_profile_into_fields(target)
        elif not names:
            self.profile_var.set("")

    def _find_profile(self, name: str) -> Optional[dict[str, Any]]:
        for conn in self._connections():
            if conn.get("name") == name:
                return conn
        return None

    def _load_profile_into_fields(self, name: str) -> None:
        conn = self._find_profile(name)
        if not conn:
            return
        self.name_var.set(conn.get("name", ""))
        self.host_var.set(conn.get("host", ""))
        self.port_var.set(str(conn.get("port", 8080)))
        self.user_var.set(conn.get("username", ""))
        self.pass_var.set(conn.get("password", ""))
        self.local_port_var.set(str(conn.get("local_port", DEFAULT_LOCAL_PORT)))
        self.proto_var.set(conn.get("protocol", PROTO_HTTP))

    def _profile_dict(self, name: str, host: str, port: int, username: str, password: str, local_port: int) -> dict:
        return {
            "name": name,
            "host": host,
            "port": port,
            "username": username,
            "password": password,
            "local_port": local_port,
            "protocol": self.proto_var.get() or PROTO_HTTP,
        }

    def _upsert_profile(self, profile: dict[str, Any], *, select: bool = True) -> None:
        name = str(profile.get("name") or "")
        conns = self._connections()
        for i, conn in enumerate(conns):
            if conn.get("name") == name:
                conns[i] = profile
                break
        else:
            conns.append(profile)
        self.config_data["connections"] = conns
        self.config_data["last_selected"] = name
        self.config_data["local_port"] = int(profile.get("local_port") or DEFAULT_LOCAL_PORT)
        save_config(self.config_data)
        self.name_var.set(name)
        if select:
            self._refresh_profile_list(select_name=name)
        else:
            if hasattr(self, "profile_combo"):
                self.profile_combo["values"] = [c["name"] for c in self._connections()]

    def _persist_fields_to_profile(self, name: str, *, silent: bool = False) -> bool:
        """Write current form fields into named profile. Returns False if invalid."""
        try:
            host, port, username, password, local_port = self._read_fields(require_auth=True)
        except ValueError as exc:
            if not silent:
                messagebox.showerror("Ошибка", str(exc))
            return False
        profile = self._profile_dict(name, host, port, username, password, local_port)
        self._upsert_profile(profile, select=not silent)
        return True

    def on_profile_selected(self, _event: object = None) -> None:
        name = self.profile_var.get()
        if not name:
            return
        prev = str(self.config_data.get("last_selected") or "")
        if prev and prev != name and self._find_profile(prev):
            # Keep edits to the previous profile without re-selecting it
            self._persist_fields_to_profile(prev, silent=True)
        self._load_profile_into_fields(name)
        self.config_data["last_selected"] = name
        save_config(self.config_data)
        self.paste_var.set("")
        self._ui_log(f"profile {name}")

    def add_profile(self) -> None:
        suggested = self.name_var.get().strip() or self.profile_var.get().strip()
        name = simpledialog.askstring("Профиль", "Имя нового профиля:", initialvalue=suggested, parent=self)
        if name is None:
            return
        name = name.strip()
        if not name:
            messagebox.showwarning("Профиль", "Имя не может быть пустым")
            return
        if self._find_profile(name):
            if not messagebox.askyesno("Профиль", f"«{name}» уже есть. Перезаписать?"):
                return
        if self._persist_fields_to_profile(name):
            self.paste_var.set("")
            self._ui_log(f"profile + {name}")

    def save_profile(self) -> None:
        name = (self.profile_var.get() or self.name_var.get()).strip()
        if not name:
            # No selection — treat Save as add (prompt for name)
            self.add_profile()
            return
        if self._persist_fields_to_profile(name):
            self.paste_var.set("")
            self._ui_log(f"saved {name}")

    def delete_profile(self) -> None:
        name = self.profile_var.get() or self.name_var.get().strip()
        if not name:
            return
        if not messagebox.askyesno("Удалить", f"{name}?"):
            return
        self.config_data["connections"] = [c for c in self._connections() if c.get("name") != name]
        if self.config_data.get("last_selected") == name:
            self.config_data["last_selected"] = ""
        save_config(self.config_data)
        self.name_var.set("")
        self.host_var.set("")
        self.port_var.set("8080")
        self.user_var.set("")
        self.pass_var.set("")
        self.proto_var.set(PROTO_HTTP)
        self.paste_var.set("")
        self._refresh_profile_list()
        self._ui_log(f"del {name}")

    def _read_fields(self, require_auth: bool = True) -> tuple[str, int, str, str, int]:
        host_raw = self.host_var.get().strip()
        if not host_raw:
            raise ValueError("Укажите parent хост (gateway / IPv6).")
        host, embedded_port = parse_host_field(host_raw)
        if not host:
            raise ValueError("Укажите parent хост (gateway / IPv6).")
        # Normalize display: bare IPv6 without brackets is fine in field
        if host_raw != host and embedded_port is None and is_ipv6_literal(host):
            self.host_var.set(host)
        elif embedded_port is not None:
            self.host_var.set(host)
            self.port_var.set(str(embedded_port))
        try:
            port = embedded_port if embedded_port is not None else int(self.port_var.get().strip())
            local_port = int(self.local_port_var.get().strip())
        except ValueError as exc:
            raise ValueError("Порт должен быть числом.") from exc
        if not (1 <= port <= 65535 and 1 <= local_port <= 65535):
            raise ValueError("Порт должен быть в диапазоне 1–65535.")
        username = self.user_var.get()
        password = self.pass_var.get()
        if require_auth and not username:
            raise ValueError("Укажите логин.")
        return host, port, username, password, local_port

    def run_diagnose(self) -> None:
        try:
            host, port, username, password, _ = self._read_fields()
        except ValueError as exc:
            self._ui_log(str(exc))
            return
        self._ui_log(f"diag {format_endpoint(host, port)}")
        self.update_idletasks()
        try:
            report = diagnose_upstream(host, port, username, password)
            for line in report.splitlines():
                self._ui_log(line)
        except RuntimeError as exc:
            for line in str(exc).splitlines():
                self._ui_log(line)
            log.error("diagnose: %s", exc)

    def test_proxy(self) -> None:
        self.run_diagnose()

    def enable_proxy(self) -> None:
        if getattr(self, "_connecting", False):
            return
        # paste field wins if filled
        if self.paste_var.get().strip() and not self.host_var.get().strip():
            self.apply_paste()
        elif self.paste_var.get().strip() and ":" in self.paste_var.get():
            parsed = parse_proxy_string(self.paste_var.get().strip())
            if parsed:
                self.apply_paste()
        try:
            host, port, username, password, local_port = self._read_fields()
        except ValueError as exc:
            messagebox.showerror("Ошибка", str(exc))
            return
        prefer = self.proto_var.get() or PROTO_HTTP
        self._connecting = True
        if hasattr(self, "connect_btn"):
            self.connect_btn.configure(state="disabled")
        if hasattr(self, "disconnect_btn"):
            self.disconnect_btn.configure(state="disabled")
        self._ui_log(f"check {prefer} {format_endpoint(host, port)}…")
        self._set_status("connecting…", online=False)

        def _unlock_btn() -> None:
            self._connecting = False
            if hasattr(self, "connect_btn"):
                try:
                    self.connect_btn.configure(state="normal")
                except tk.TclError:
                    pass

        def _fail(hint: str) -> None:
            _unlock_btn()
            self._set_status("○  offline", online=False)
            self._ui_log(hint)
            if is_ipv4_literal(host):
                hint += (
                    "\n\nIPv4 в поле host. Для IPv6 нужен gateway вида "
                    "[2001:db8::1]:port:user:pass"
                )
            messagebox.showerror("Offline", hint)

        def _start_listen(proto: str, result: str) -> None:
            self.disable_proxy(silent=True)
            try:
                fwd = ParentChainService(
                    parent_host=host,
                    parent_port=port,
                    username=username,
                    password=password,
                    listen_port=local_port,
                    protocol=proto,
                    on_event=self._ui_log,
                )
                fwd.start()
            except OSError as exc:
                _fail(f"Не удалось запустить listen:\n{exc}")
                return
            except RuntimeError as exc:
                _fail(str(exc))
                return

            _unlock_btn()
            if proto != prefer:
                self.proto_var.set(proto)
            self._ui_log(result)
            self.forwarder = fwd
            scope = SCOPE_SYSTEM if self.system_wide_var.get() else SCOPE_APPS
            self.scope_var.set(scope)
            self.config_data["scope"] = scope
            try:
                if scope == SCOPE_SYSTEM:
                    set_system_proxy(True, local_port, bypass_hosts=[host])
                else:
                    set_system_proxy(False)
            except RuntimeError as exc:
                self._ui_log(str(exc))
            self.endpoints_var.set(self._endpoints_text())
            name = self.name_var.get().strip() or format_endpoint(host, port)
            self.name_var.set(name)
            profile = self._profile_dict(name, host, port, username, password, local_port)
            conns = self._connections()
            for i, conn in enumerate(conns):
                if conn.get("name") == name:
                    conns[i] = profile
                    break
            else:
                conns.append(profile)
            self.config_data["connections"] = conns
            self.config_data["last_selected"] = name
            self.config_data["local_port"] = local_port
            save_config(self.config_data)
            self._refresh_profile_list(select_name=name)
            mode = "system" if scope == SCOPE_SYSTEM else "apps"
            self._set_status(f"{mode} · {LOCAL_HOST}:{local_port}", online=True)
            self._ui_log(f"⚡ up {proto} {format_endpoint(host, port)}")

            def _warm_geo() -> None:
                try:
                    g = fetch_proxy_geo(local_port, timeout=12.0)
                    if g.get("timezone"):
                        self.after(
                            0,
                            lambda: self._ui_log(
                                f"geo ready {g.get('countryCode', '?')} "
                                f"{g.get('query', '?')} · {g['timezone']}"
                            ),
                        )
                except Exception as exc:
                    log.debug("geo warm failed: %s", exc)

            threading.Thread(target=_warm_geo, name="geo-warm", daemon=True).start()

        def _worker() -> None:
            try:
                proto, result = probe_upstream_fast(
                    host, port, username, password, prefer=prefer, timeout=3.5
                )
            except RuntimeError as exc:
                log.error("refuse connect: %s", exc)
                self.after(0, lambda: _fail(str(exc)))
                return
            self.after(0, lambda: _start_listen(proto, result))

        threading.Thread(target=_worker, name="connect-worker", daemon=True).start()

    def disable_proxy(self, silent: bool = False) -> None:
        if self.forwarder:
            self.forwarder.stop()
            self.forwarder = None
        try:
            set_system_proxy(False)
        except RuntimeError as exc:
            if not silent:
                messagebox.showerror("Ошибка", str(exc))
            self._ui_log(str(exc))
            return
        self._set_status("offline", online=False)
        if not silent:
            self._ui_log("━╳━ down")

    def on_close(self) -> None:
        self.disable_proxy(silent=True)
        # Watcher threads are daemons — sweep unused tmp_* now (any age).
        cleanup_stale_tmp_browser_profiles(max_age_hours=0)
        log.info("Приложение закрыто")
        self.destroy()

def main() -> None:
    if winreg is None:
        raise SystemExit("Нужна Windows (модуль winreg).")
    app = App()
    app.mainloop()

if __name__ == "__main__":
    main()
