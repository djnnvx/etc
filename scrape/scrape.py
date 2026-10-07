#!/usr/bin/env python3
"""
Tiny stupid scrapper. It's very basic but it bypasses a lot of WAFs lol


Usage:
  scrape.py get <url>                       # print page body
  scrape.py links <url> [regex]             # absolute links, optionally filtered
  scrape.py grab <url> <outdir> [regex]     # download every (filtered) link
  scrape.py dl <outdir> < urls.txt          # download urls from stdin, one per line

Options (env):
  IMPERSONATE=chrome   DELAY_MS=500   TIMEOUT=60   IFACE=tun0   RETRIES=5
"""

import os
import re
import sys
import time
import hashlib
from pathlib import Path
from urllib.parse import urljoin, urlparse

from curl_cffi import requests as creq

IMPERSONATE = os.environ.get("IMPERSONATE", "chrome")
DELAY = float(os.environ.get("DELAY_MS", "500")) / 1000.0
TIMEOUT = int(os.environ.get("TIMEOUT", "60"))
IFACE = os.environ.get("IFACE") or None
RETRIES = max(1, int(os.environ.get("RETRIES", "5")))

_HREF = re.compile(rb"""(?:href|src)\s*=\s*["']?([^"'\s>]+)""", re.I)


class Session:
    def __init__(self):
        self.s = creq.Session(impersonate=IMPERSONATE)
        self._last = 0.0

    def _throttle(self):
        wait = DELAY - (time.monotonic() - self._last)
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()

    def get(self, url, **kw):
        kw.setdefault("timeout", TIMEOUT)
        if IFACE:
            kw.setdefault("interface", IFACE)
        delays = (1, 2, 4, 8, 16)[:RETRIES]
        for n, backoff in enumerate(delays):
            self._throttle()
            try:
                r = self.s.get(url, **kw)
            except creq.RequestsError:
                if n == len(delays) - 1:
                    raise
                time.sleep(backoff)
                continue
            if r.status_code != 429 or n == len(delays) - 1:
                return r
            r.close()
            time.sleep(backoff)

    def download(self, url, dest: Path) -> dict:
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        part = dest.with_name(dest.name + ".part")
        sha, size = hashlib.sha256(), 0
        r = self.get(url, stream=True)
        try:
            r.raise_for_status()
            with open(part, "wb") as f:
                for chunk in r.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        sha.update(chunk)
                        size += len(chunk)
        except BaseException:
            part.unlink(missing_ok=True)
            raise
        finally:
            r.close()
        part.replace(dest)
        return {"sha256": sha.hexdigest(), "size": size}


def links(sess, url, pat=None):
    r = sess.get(url)
    r.raise_for_status()
    seen, out = set(), []
    rx = re.compile(pat) if pat else None
    for m in _HREF.finditer(r.content):
        u = urljoin(url, m.group(1).decode("latin-1"))
        if u in seen or (rx and not rx.search(u)):
            continue
        seen.add(u)
        out.append(u)
    return out


def _name(url):
    n = os.path.basename(urlparse(url).path) or hashlib.sha256(url.encode()).hexdigest()[:16]
    return n


def grab(sess, urls, outdir):
    outdir = Path(outdir)
    for u in urls:
        dest = outdir / _name(u)
        if dest.exists():
            print(f"skip  {dest}", file=sys.stderr)
            continue
        try:
            info = sess.download(u, dest)
            print(f"ok    {dest}  {info['size']}B  {info['sha256'][:12]}")
        except Exception as e:
            print(f"fail  {u}  {e}", file=sys.stderr)


def main(argv):
    if not argv:
        print(__doc__.strip())
        return 1
    sess = Session()
    cmd = argv[0]
    if cmd == "get":
        r = sess.get(argv[1])
        r.raise_for_status()
        sys.stdout.buffer.write(r.content)
    elif cmd == "links":
        pat = argv[2] if len(argv) > 2 else None
        print("\n".join(links(sess, argv[1], pat)))
    elif cmd == "grab":
        pat = argv[3] if len(argv) > 3 else None
        grab(sess, links(sess, argv[1], pat), argv[2])
    elif cmd == "dl":
        urls = [l.strip() for l in sys.stdin if l.strip()]
        grab(sess, urls, argv[1])
    else:
        print(__doc__.strip())
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
