#!/usr/bin/env python3
"""Automatic login for the University of Moratuwa Wi-Fi (UoM_Wireless).

A LaunchAgent runs this when macOS reports a network change (e.g. waking from
sleep or joining Wi-Fi) and every 5 minutes as a backstop, in case the portal
drops the session while the Mac is awake. A normal run costs one tiny request
to Apple's captive-portal check and writes nothing to disk. Only when that check fails *and* the Mac is on
the UoM campus network does it fill in the Cisco login page at wlan.uom.lk,
using the username and password that "Set Up.command" saved in the Keychain.

Python 3.9 + standard library only (the python3 that ships with Xcode tools).

Flags:  --now      ignore the 10-minute pause after a rejected login
        --verbose  print what is happening (used by the .command files)
"""

import collections
import fcntl
import http.client
import ipaddress
import json
import os
import random
import re
import socket
import ssl
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from html.parser import HTMLParser
from http.cookiejar import CookieJar

KEYCHAIN_SERVICE = os.environ.get("UOM_KEYCHAIN_SERVICE", "UoM WiFi Login")
# The campus Cisco wireless controller serves its login page here (wlan.uom.lk -> 1.1.1.1 on campus).
PORTAL_URL = os.environ.get("UOM_PORTAL_URL", "https://wlan.uom.lk/login.html")
CHECK_URL = os.environ.get("UOM_CHECK_URL", "http://captive.apple.com/hotspot-detect.html")
# The campus DHCP hands out the search domain wifi.uom.lk. A café hotspot won't,
# so the password is never sent to a login page anywhere else.
CAMPUS_DOMAIN = "uom.lk"
# Only for the offline test harness: hosts treated as the UoM portal.
TEST_HOSTS = set(filter(None, os.environ.get("UOM_TEST_HOSTS", "").split(",")))

DATA_DIR = os.path.expanduser(os.environ.get("UOM_DATA_DIR", "~/Library/Application Support/UoMAutoLogin"))
STATE_FILE = os.path.join(DATA_DIR, "state.json")
FAIL_BACKOFF = 10 * 60  # after the portal rejects the login, wait before trying again
UA = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
      "(KHTML, like Gecko) Version/18.0 Safari/605.1.15")

VERBOSE = "--verbose" in sys.argv
FORCE = "--now" in sys.argv

# The portal's certificate doesn't match its address; we only talk to it on campus.
_PORTAL_TLS = ssl.create_default_context()
_PORTAL_TLS.check_hostname = False
_PORTAL_TLS.verify_mode = ssl.CERT_NONE


# ---------------------------------------------------------------- utilities

def say(msg):
    """Shows progress when run by hand (Log In Now, Set Up); background runs stay silent."""
    if VERBOSE:
        print(msg, flush=True)


def notify(text):
    script = "display notification %s with title \"UoM Wi-Fi\"" % json.dumps(text, ensure_ascii=False)
    subprocess.run(["osascript", "-e", script], capture_output=True)




def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)


def credentials():
    """Returns (username, password) from the Keychain, or None."""
    def security(*extra):
        r = subprocess.run(["security", "find-generic-password", "-s", KEYCHAIN_SERVICE, *extra],
                           capture_output=True, text=True)
        return r.stdout if r.returncode == 0 else None

    attrs, password = security(), security("-w")
    match = re.search(r'"acct"<blob>="(.*)"', attrs or "")
    if not match or password is None:
        return None
    return match.group(1), password[:-1] if password.endswith("\n") else password


# ------------------------------------------------------------ network checks
#
# Until the portal login is done, macOS keeps the campus Wi-Fi off-limits to
# ordinary programs: name lookups fail even though Apple's own login pop-up can
# reach wlan.uom.lk. So on campus every request here is pinned to the Wi-Fi
# interface, and names are looked up by asking the campus DNS server directly.

IP_BOUND_IF = 25  # <netinet/in.h>: send this socket's traffic through one interface only
Link = collections.namedtuple("Link", "iface dns")
_campus = None


def campus_link():
    """The connection whose DHCP domain is *.uom.lk (en0 / wifi.uom.lk), or None."""
    global _campus
    if _campus is None:
        try:
            ifaces = subprocess.run(["ifconfig", "-l"], capture_output=True, text=True, timeout=5).stdout.split()
            for iface in (i for i in ifaces if i.startswith("en")):
                def option(name):
                    return subprocess.run(["ipconfig", "getoption", iface, name],
                                          capture_output=True, text=True, timeout=5).stdout.strip()
                domain = option("domain_name").lower()
                if domain == CAMPUS_DOMAIN or domain.endswith("." + CAMPUS_DOMAIN):
                    _campus = Link(iface, option("domain_name_server"))
                    break
        except (OSError, subprocess.SubprocessError):
            pass
    return _campus


def on_campus():
    return campus_link() is not None


def _bind(sock, link):
    sock.setsockopt(socket.IPPROTO_IP, IP_BOUND_IF, socket.if_nametoindex(link.iface))


def _skip_name(msg, pos):
    while msg[pos] and msg[pos] < 0xC0:
        pos += msg[pos] + 1
    return pos + (2 if msg[pos] else 1)


def dns_lookup(name, link):
    """Asks the campus DNS server, over the campus interface, for name's IPv4 address."""
    question = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0\0\1\0\1"
    query = struct.pack(">HHHHHH", random.randrange(65536), 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        _bind(s, link)
        s.settimeout(2)
        s.sendto(query, (link.dns, 53))
        reply = s.recv(4096)
    if reply[:2] != query[:2]:
        raise OSError("bad DNS reply for %s" % name)
    pos = 12 + len(question)
    for _ in range(struct.unpack(">H", reply[6:8])[0]):
        pos = _skip_name(reply, pos)
        rtype, _, _, length = struct.unpack(">HHIH", reply[pos:pos + 10])
        pos += 10
        if rtype == 1 and length == 4:  # an A record (CNAMEs before it are skipped)
            return socket.inet_ntoa(reply[pos:pos + 4])
        pos += length
    raise OSError("the campus DNS server has no address for %s" % name)


def _connect(host, port, timeout):
    """A TCP connection to host, pinned to the campus interface when on campus."""
    link = campus_link()
    if not link or host in TEST_HOSTS:
        return socket.create_connection((host, port), timeout)
    try:
        ip = str(ipaddress.IPv4Address(host))
    except ValueError:
        ip = dns_lookup(host, link)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _bind(sock, link)
        sock.settimeout(timeout)
        sock.connect((ip, port))
    except OSError:
        sock.close()
        raise
    return sock


class _HTTPConnection(http.client.HTTPConnection):
    def connect(self):
        self.sock = _connect(self.host, self.port, self.timeout)


class _HTTPSConnection(http.client.HTTPSConnection):
    def connect(self):
        self.sock = self._context.wrap_socket(_connect(self.host, self.port, self.timeout),
                                              server_hostname=self.host)


class _HTTPHandler(urllib.request.HTTPHandler):
    def http_open(self, req):
        return self.do_open(_HTTPConnection, req)


class _HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self):
        super().__init__(context=_PORTAL_TLS)

    def https_open(self, req):
        return self.do_open(_HTTPSConnection, req, context=_PORTAL_TLS)


def trusted_portal(url):
    """True only for a *.uom.lk address while on the campus network."""
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in TEST_HOSTS:
        return True
    return on_campus() and (host == CAMPUS_DOMAIN or host.endswith("." + CAMPUS_DOMAIN))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def probe():
    """Asks Apple's captive-portal check whether the internet works.

    Returns ("online" | "portal" | "offline", detail-for-the-log).
    """
    opener = urllib.request.build_opener(_NoRedirect, _HTTPHandler())
    req = urllib.request.Request(CHECK_URL, headers={"User-Agent": UA, "Cache-Control": "no-cache"})
    try:
        with opener.open(req, timeout=3) as resp:
            body = resp.read(65536).decode("utf-8", "replace")
        if re.search(r"<title>\s*Success\s*</title>", body, re.I):
            return "online", ""
        return "portal", "the check page was replaced"
    except urllib.error.HTTPError as e:  # a 3xx redirect lands here since redirects are disabled
        return "portal", "redirected to %s" % e.headers.get("Location", "?")
    except (urllib.error.URLError, OSError) as e:
        return "offline", str(getattr(e, "reason", e))


# --------------------------------------------------------------- page parsing

class PageParser(HTMLParser):
    """Collects forms (with their fields) and onward links (frames, meta refresh)."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.links = [], []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v if v is not None else "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "button") and self._form is not None:
            self._form["fields"].append(dict(a, tag=tag))
        elif tag in ("frame", "iframe") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\"\s]+)", a.get("content", ""), re.I)
            if m:
                self.links.append(m.group(1))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def field_type(field):
    return (field.get("type") or ("submit" if field["tag"] == "button" else "text")).lower()


def fill_form(fields, username, password):
    """Builds the POST data a browser would send after typing in the credentials."""
    texts = [f for f in fields if f.get("name") and field_type(f) in ("text", "email", "tel", "number")]
    named = [f for f in texts if re.search(r"user|login|uname|mail|account|uid|name|id$", f["name"], re.I)]
    user_field = (named or texts or [None])[0]

    data, clicked = [], False
    for f in fields:
        name, kind = f.get("name"), field_type(f)
        if not name:
            continue
        if kind == "password":
            data.append((name, password))
        elif f is user_field:
            data.append((name, username))
        elif kind in ("submit", "image"):
            if not clicked:  # a browser sends only the button that was pressed
                data.append((name, f.get("value", "")))
                clicked = True
        elif kind == "checkbox" or (kind == "radio" and "checked" in f):
            data.append((name, f.get("value") or "on"))  # e.g. "I accept the terms"
        elif kind not in ("radio", "button", "reset", "file"):
            data.append((name, f.get("value", "")))
    # The Cisco login page's Submit button runs JavaScript that sets buttonClicked=4.
    return [(n, "4" if n == "buttonClicked" else v) for n, v in data]


# ---------------------------------------------------------------------- login

def _request(opener, url, data=None, referer=None):
    headers = {"User-Agent": UA}
    if referer:
        parts = urllib.parse.urlsplit(referer)
        headers.update(Referer=referer, Origin="%s://%s" % (parts.scheme, parts.netloc))
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(data).encode()
    with opener.open(urllib.request.Request(url, data=data, headers=headers), timeout=10) as resp:
        return resp.geturl(), resp.status, resp.read(262144).decode("utf-8", "replace")


_LOGIN_ERROR = re.compile(r"""name=["']?err_flag["']?[^>]*value=["']?1\b""", re.I)


def submit(opener, page_url, form, username, password):
    action = urllib.parse.urljoin(page_url, form["action"] or page_url)
    if not trusted_portal(action):
        say("The login form sends to %s, which isn't the UoM portal; not sending the password." % action)
        return "no-form"
    data = fill_form(form["fields"], username, password)
    say("Submitting the login form to %s (fields: %s)" % (action, ", ".join(n for n, _ in data)))
    if form["method"] == "post":
        _, status, html = _request(opener, action, data, referer=page_url)
    else:
        sep = "&" if "?" in action else "?"
        _, status, html = _request(opener, action.split("#")[0] + sep + urllib.parse.urlencode(data),
                                   referer=page_url)
    if _LOGIN_ERROR.search(html):  # the Cisco page comes back with err_flag=1 on a bad password
        say("The portal says the username or password is wrong.")
        return "rejected"
    say("Portal answered HTTP %s" % status)
    return "sent"


def login(start_url, username, password):
    """Finds the login form (following frames/redirects) and submits it.

    Returns "sent", "rejected" (wrong username/password), "unreachable" or "no-form".
    """
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(CookieJar()),
                                         _HTTPHandler(), _HTTPSHandler())
    url = start_url
    for _hop in range(4):
        if not trusted_portal(url):
            say("Ended up at %s, which isn't the UoM portal; stopping." % url)
            return "no-form"
        try:
            url, _, html = _request(opener, url)
        except (urllib.error.URLError, OSError) as e:
            say("Can't reach the login page yet (%s); will try again shortly." % getattr(e, "reason", e))
            return "unreachable"

        page = PageParser()
        page.feed(html)
        form = next((f for f in page.forms if any(field_type(x) == "password" for x in f["fields"])), None)
        if form and trusted_portal(url):
            try:
                return submit(opener, url, form, username, password)
            except (urllib.error.URLError, OSError) as e:
                say("Sending the login failed (%s); will try again shortly." % getattr(e, "reason", e))
                return "unreachable"
        if not page.links:
            break
        url = urllib.parse.urljoin(url, page.links[0])
    say("No login form found on %s." % url)
    return "no-form"


CNA_PROCESS = "Captive Network Assistant.app/Contents/MacOS/"


def close_login_popup(wait=15):
    """Closes macOS's own "Join UoM_Wireless" pop-up once we're logged in.

    It opens as the Mac wakes and never notices that the login already happened,
    so it would sit there asking for the password. It can also appear a few
    seconds late, so keep watching for `wait` seconds.
    """
    for second in range(wait + 1):
        if subprocess.run(["pgrep", "-f", CNA_PROCESS], capture_output=True).returncode == 0:
            time.sleep(1)  # let it finish opening so it doesn't come straight back
            subprocess.run(["pkill", "-f", CNA_PROCESS], capture_output=True)
            say("Closed macOS's login pop-up (already logged in).")
            return
        if second < wait:
            time.sleep(1)


# ----------------------------------------------------------------------- main

def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    lock = open(os.path.join(DATA_DIR, ".lock"), "a")  # "a": don't rewrite it on every run
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        say("Another check is already running.")
        return 0

    # Right after waking, Wi-Fi may still be joining: keep checking for up to ~20 s on campus.
    for attempt in range(10):
        status, detail = probe()
        if status != "offline" or not on_campus():
            break
        if attempt < 9:
            time.sleep(2)

    if status == "online":
        say("Internet is working; nothing to do.")
        if on_campus():  # a pop-up left over from a wake-up has nothing left to do
            close_login_popup(wait=0)
        return 0
    if not on_campus() and not TEST_HOSTS:
        say("No internet (%s), but this isn't the UoM network; leaving it alone." % detail)
        return 0

    state = load_state()
    if not FORCE and time.time() - state.get("last_failure", 0) < FAIL_BACKOFF:
        say("The last login was rejected less than 10 minutes ago; waiting before trying again.")
        return 0

    creds = credentials()
    if not creds:
        say("No UoM username/password saved in the Keychain. Double-click \"Set Up.command\" to add them.")
        return 1

    say("No internet on the UoM network (%s); logging in as %s" % (detail, creds[0]))
    for attempt in range(3):  # a just-woken Wi-Fi can drop the first try
        result = login(PORTAL_URL, *creds)
        if result != "unreachable":
            break
        time.sleep(2)
    if result == "unreachable":
        return 0  # the network isn't ready yet; the next run (≤30 s) tries again
    if result == "sent":
        for _ in range(8):
            time.sleep(2)
            if probe()[0] == "online":
                say("Logged in. Internet is working.")
                notify("Logged in to UoM Wi-Fi automatically ✓")
                if state.pop("last_failure", None) is not None:
                    save_state(state)
                close_login_popup()
                return 0

    first_failure = "last_failure" not in state
    state["last_failure"] = time.time()
    save_state(state)
    say("Automatic login didn't get the internet working.")
    if first_failure and not FORCE:  # don't nag again every 10 minutes
        if result == "rejected":
            notify("UoM Wi-Fi didn't accept your username/password. Run \"Set Up\" again to fix it.")
        else:
            notify("Automatic login didn't work. Please log in on the page that just opened.")
        subprocess.run(["open", PORTAL_URL], capture_output=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
