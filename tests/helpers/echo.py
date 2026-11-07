#!/usr/bin/env python3
"""plybox lab, step 4: a TLS upstream standing in for an API provider.

It knows the real API key (like the provider would) and answers only
whether the key it received is that one. It never echoes the value back,
so the response cannot leak the secret into the box.

    echo.py --port P --cert leaf.pem --key leaf.key --expect REAL --name NAME

Reply body: `name=NAME key=ok|placeholder|missing|other`.
"""
import argparse
import http.server
import ssl

ap = argparse.ArgumentParser()
ap.add_argument("--port", type=int, required=True)
ap.add_argument("--cert", required=True)
ap.add_argument("--key", required=True)
ap.add_argument("--expect", required=True)
ap.add_argument("--name", required=True)
A = ap.parse_args()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        key = self.headers.get("x-api-key") or self.headers.get("authorization", "").removeprefix("Bearer ").strip()
        if not key:
            verdict = "missing"
        elif key == A.expect:
            verdict = "ok"
        elif key.startswith("PLYBOX_SECRET_"):
            verdict = "placeholder"
        else:
            verdict = "other"
        body = f"name={A.name} key={verdict}\n".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    do_POST = do_GET

    def log_message(self, *_):
        pass


server = http.server.ThreadingHTTPServer(("127.0.0.1", A.port), Handler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(A.cert, A.key)
server.socket = ctx.wrap_socket(server.socket, server_side=True)
server.serve_forever()
