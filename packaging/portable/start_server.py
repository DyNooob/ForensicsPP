#!/usr/bin/env python3
"""Forensics++ offline launcher. Python 3 standard library only; no installs or network downloads.
Copyright (c) 2026 DyNooob. Released under the MIT License; see LICENSE.txt.
"""
import argparse
import functools
import http.server
import pathlib
import threading
import webbrowser
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parent

class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = {**http.server.SimpleHTTPRequestHandler.extensions_map, '.wasm': 'application/wasm', '.js': 'text/javascript'}

    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        if path.startswith('/tools/') and not pathlib.Path(self.translate_path(self.path)).exists():
            self.path = '/index.html'
        super().do_GET()

    def end_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        super().end_headers()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start Forensics++ locally without any package installation.')
    parser.add_argument('--port', type=int, default=8765)
    parser.add_argument('--no-browser', action='store_true')
    args = parser.parse_args()
    factory = functools.partial(Handler, directory=str(ROOT))
    try:
        server = http.server.ThreadingHTTPServer(('127.0.0.1', args.port), factory)
    except OSError as error:
        raise SystemExit(f'Cannot start on port {args.port}: {error}. Try --port 8766.')
    url = f'http://127.0.0.1:{server.server_port}/'
    print(f'Forensics++ offline: {url}\nLocal access only. Press Ctrl+C to stop.', flush=True)
    if not args.no_browser:
        threading.Timer(0.5, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
