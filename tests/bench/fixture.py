#!/usr/bin/env python3
"""Local HTTPS model/transfer fixture; never part of the measured box."""
import argparse
import http.server
import json
import socket
import ssl
import time
from urllib.parse import parse_qs, urlsplit

TOKEN = "plybox-benchmark-only-key"
MODEL = json.dumps({"model": "fixture", "content": "x" * 16300}).encode()
BLOCK = b"x" * 65536


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    def log_message(self, *_):
        pass

    def do_POST(self):
        route = urlsplit(self.path)
        query = parse_qs(route.query)
        if query.get("secret") == ["1"] and self.headers.get("Authorization") != f"Bearer {TOKEN}":
            self.send_error(403, "fixture did not receive the substituted test key")
            return
        remaining = int(self.headers.get("Content-Length", "0"))
        received = remaining
        while remaining:
            data = self.rfile.read(min(remaining, len(BLOCK)))
            if not data:
                raise EOFError("truncated upload")
            remaining -= len(data)
        self.send_response(200)
        self.send_header("Connection", "close")
        self.close_connection = True
        if route.path == "/stream":
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            # Eight ~2 KiB chunks, seven 1 ms gaps. This is a deliberately
            # fast model stream, not a model inference latency simulation.
            size = (len(MODEL) + 7) // 8
            for i in range(0, len(MODEL), size):
                if i:
                    time.sleep(0.001)
                data = MODEL[i:i + size]
                self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
                self.wfile.flush()
            self.wfile.write(b"0\r\n\r\n")
        elif route.path == "/download":
            remaining = int(query["bytes"][0])
            self.send_header("Content-Length", str(remaining))
            self.end_headers()
            while remaining:
                data = BLOCK[:min(remaining, len(BLOCK))]
                self.wfile.write(data)
                remaining -= len(data)
        else:
            body = json.dumps({"received": received}).encode() if route.path == "/upload" else MODEL
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    args = ap.parse_args()
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(args.cert, args.key)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"port": server.server_port, "response_bytes": len(MODEL)}), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
