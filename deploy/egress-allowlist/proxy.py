"""Minimal webhook egress allowlist forward proxy (sample sidecar).

Listens for HTTP absolute-URI requests and HTTPS CONNECT tunnels. Only
destinations whose hostname is in ``EGRESS_ALLOWED_HOSTS`` are accepted.
After DNS resolution, private / loopback / link-local / metadata addresses
are rejected (basic DNS-rebinding guard).

This is a **sample** for local/staging compose — not a hardened production
egress gateway. Prefer a managed egress proxy or mesh policy in production.

Env:
  EGRESS_ALLOWED_HOSTS  comma-separated hostnames (required for any traffic)
  EGRESS_LISTEN         bind address (default 0.0.0.0:8888)
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

_METADATA = frozenset(
    {
        "metadata.google.internal",
        "metadata.goog",
        "metadata",
        "instance-data",
    }
)


def _allowed_hosts() -> frozenset[str]:
    raw = os.environ.get("EGRESS_ALLOWED_HOSTS", "")
    return frozenset(h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip())


def _is_blocked_ip(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return True
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def resolve_and_check(host: str, port: int, allowed: frozenset[str]) -> tuple[str, int]:
    """Return (ip, port) if host is allowlisted and resolves to a public address."""
    hostname = (host or "").lower().rstrip(".")
    if hostname.startswith("[") and hostname.endswith("]"):
        hostname = hostname[1:-1]
    if not hostname:
        raise ValueError("missing_host")
    if hostname in _METADATA or hostname.endswith(".metadata.google.internal"):
        raise ValueError("blocked_metadata")
    if not allowed or hostname not in allowed:
        raise ValueError("host_not_allowlisted")
    try:
        infos = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("dns_failed") from exc
    if not infos:
        raise ValueError("dns_failed")
    # Prefer first A/AAAA that is not blocked; reject if any resolution is private
    # when the hostname was allowlisted (rebinding / dual-homed risk).
    public: list[str] = []
    for family, _type, _proto, _canon, sockaddr in infos:
        ip = sockaddr[0]
        if _is_blocked_ip(ip):
            raise ValueError("blocked_resolved_ip")
        public.append(ip)
    return public[0], port


class EgressProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        print(f"egress-allowlist: {self.address_string()} - {fmt % args}")

    def _deny(self, code: int, reason: str) -> None:
        body = f'{{"error":"{reason}"}}\n'.encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def do_CONNECT(self) -> None:  # noqa: N802
        allowed = _allowed_hosts()
        host_port = self.path
        if ":" in host_port:
            host, _, port_s = host_port.rpartition(":")
            try:
                port = int(port_s)
            except ValueError:
                self._deny(400, "bad_port")
                return
        else:
            host, port = host_port, 443
        try:
            ip, port = resolve_and_check(host, port, allowed)
        except ValueError as exc:
            self._deny(403, str(exc))
            return
        try:
            upstream = socket.create_connection((ip, port), timeout=10)
        except OSError:
            self._deny(502, "upstream_connect_failed")
            return
        self.send_response(200, "Connection Established")
        self.send_header("Connection", "close")
        self.end_headers()
        self._tunnel(self.connection, upstream)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy_absolute()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy_absolute()

    def do_PUT(self) -> None:  # noqa: N802
        self._proxy_absolute()

    def do_DELETE(self) -> None:  # noqa: N802
        self._proxy_absolute()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy_absolute()

    def do_PATCH(self) -> None:  # noqa: N802
        self._proxy_absolute()

    def _proxy_absolute(self) -> None:
        allowed = _allowed_hosts()
        parsed = urlsplit(self.path)
        if not parsed.scheme or not parsed.hostname:
            self._deny(400, "absolute_uri_required")
            return
        if parsed.scheme.lower() not in {"http", "https"}:
            self._deny(400, "unsupported_scheme")
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        try:
            ip, port = resolve_and_check(parsed.hostname, port, allowed)
        except ValueError as exc:
            self._deny(403, str(exc))
            return
        if parsed.scheme.lower() == "https":
            # Absolute-form HTTPS via plain forward proxy is uncommon; prefer CONNECT.
            self._deny(400, "use_connect_for_https")
            return
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        length = int(self.headers.get("Content-Length", "0") or 0)
        body = self.rfile.read(length) if length else b""
        try:
            upstream = socket.create_connection((ip, port), timeout=10)
        except OSError:
            self._deny(502, "upstream_connect_failed")
            return
        try:
            req = (
                f"{self.command} {path} HTTP/1.1\r\n"
                f"Host: {parsed.hostname}\r\n"
                f"Connection: close\r\n"
            )
            for key, value in self.headers.items():
                lk = key.lower()
                if lk in {"proxy-connection", "connection", "host", "content-length"}:
                    continue
                req += f"{key}: {value}\r\n"
            req += f"Content-Length: {len(body)}\r\n\r\n"
            upstream.sendall(req.encode("latin-1") + body)
            while True:
                chunk = upstream.recv(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)
        finally:
            upstream.close()

    @staticmethod
    def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 60)
                if errored or not readable:
                    break
                for sock in readable:
                    other = upstream if sock is client else client
                    data = sock.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
        except OSError:
            return
        finally:
            try:
                upstream.close()
            except OSError:
                pass


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    listen = os.environ.get("EGRESS_LISTEN", "0.0.0.0:8888").strip() or "0.0.0.0:8888"
    host, _, port_s = listen.rpartition(":")
    host = host or "0.0.0.0"
    port = int(port_s or "8888")
    allowed = _allowed_hosts()
    print(
        f"egress-allowlist listening on {host}:{port}; "
        f"allowed={sorted(allowed) or '(none — deny all)'}"
    )
    server = ThreadedTCPServer((host, port), EgressProxyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    thread.join()


if __name__ == "__main__":
    main()
