"""Tests for path traversal success detection (utils/path_traversal.py).

These cover the false-positive fix from issue #30: the detector used to
report a hit whenever a response merely contained keywords like "password",
"database" or the substring "location{" (present in most sites' CSS/JS), so
ordinary pages and WAF error pages were flagged as path traversal findings.
Detection now requires the actual structure of a leaked file.

Run with:  pytest tests/test_path_traversal_detection.py
"""

from types import SimpleNamespace

import pytest

from utils.path_traversal import PathTraversalScanner

TRAVERSAL_PAYLOAD = "../../../etc/passwd"


def _response(body):
    """Build a stand-in for requests.Response.

    detect_traversal_success only reads ``.text``, so a live HTTP request is
    unnecessary to exercise the detection logic.
    """
    return SimpleNamespace(text=body)


# ---------------------------------------------------------------------------
# False positives: ordinary responses that must NOT be flagged
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "description, body",
    [
        (
            "login page with a password field",
            "<form><label>Password:</label><input name='password'></form>",
        ),
        (
            "CSS/JS containing the substring 'location{'",
            "<style>a{color:red}.nav .location{top:0}</style>"
            "<script>window.location={href:'/'}</script>",
        ),
        (
            "marketing copy mentioning database and server_name",
            "<p>Our database scales with every server_name you configure.</p>",
        ),
        (
            "docs page mentioning Apache directives",
            "<p>Set <code>DocumentRoot</code> and <code>ServerName</code> "
            "then add a <code>LoadModule</code> line.</p>",
        ),
        (
            "generic WAF block page",
            "<html><body><h1>Access Denied</h1>"
            "<p>Request blocked for security reasons.</p></body></html>",
        ),
        (
            "a single passwd-shaped line embedded in prose",
            "<pre>Example entry: root:x:0:0:root:/root:/bin/bash</pre>",
        ),
    ],
)
def test_benign_responses_are_not_flagged(description, body):
    """Ordinary pages and WAF blocks are not reported as traversal hits."""
    scanner = PathTraversalScanner()
    flagged = scanner.detect_traversal_success(_response(body), TRAVERSAL_PAYLOAD)
    assert flagged is False, description


# ---------------------------------------------------------------------------
# True positives: real file disclosures that MUST be flagged
# ---------------------------------------------------------------------------

def test_real_etc_passwd_is_flagged():
    """A genuine /etc/passwd dump is still detected."""
    scanner = PathTraversalScanner()
    body = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    )
    assert scanner.detect_traversal_success(_response(body), TRAVERSAL_PAYLOAD) is True


def test_passwd_needs_more_than_one_line():
    """A lone passwd-format line is not enough; a real file has many."""
    scanner = PathTraversalScanner()
    one_line = "root:x:0:0:root:/root:/bin/bash\n"
    assert scanner.detect_traversal_success(_response(one_line), TRAVERSAL_PAYLOAD) is False


def test_real_boot_ini_is_flagged():
    """A genuine Windows boot.ini dump is still detected."""
    scanner = PathTraversalScanner()
    body = (
        "[boot loader]\n"
        "timeout=30\n"
        "default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS\n"
        "[operating systems]\n"
        "multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS=\"Windows\"\n"
    )
    assert scanner.detect_traversal_success(_response(body), "..\\..\\..\\boot.ini") is True


def test_real_access_log_is_flagged():
    """A genuine access-log dump is still detected."""
    scanner = PathTraversalScanner()
    body = '127.0.0.1 - - [10/Oct/2024:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326\n'
    assert (
        scanner.detect_traversal_success(_response(body), "../../var/log/nginx/access.log")
        is True
    )
