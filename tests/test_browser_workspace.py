"""Opt-in actual Chromium test: SANDWORM_BROWSER_TESTS=1 pytest -k browser."""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
import urllib.request

import pytest

pytestmark = pytest.mark.skipif(os.environ.get("SANDWORM_BROWSER_TESTS") != "1", reason="browser test is opt-in")


def test_browser_workspace_upload_and_inspect(tmp_path):
    playwright = pytest.importorskip("playwright.sync_api")
    from sandworm.platform.store import PlatformStore
    store = PlatformStore(tmp_path / "platform")
    store.create_user("browser-test", "browser-test-password", "lab", "admin")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    env = {**os.environ, "SANDWORM_WORK_DIR": str(tmp_path)}
    server = subprocess.Popen([sys.executable, "-m", "sandworm.cli", "serve", "--local-http", "--port", str(port)], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{port}"
        for _ in range(100):
            try:
                urllib.request.urlopen(url + "/healthz", timeout=1).close()
                break
            except OSError:
                time.sleep(0.1)
        with playwright.sync_playwright() as p:
            browser = p.chromium.launch()
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.goto(url)
            page.get_by_label("Username", exact=True).fill("browser-test")
            page.get_by_label("Password", exact=True).fill("browser-test-password")
            page.get_by_role("button", name="Sign in", exact=True).click()
            playwright.expect(page.get_by_role("heading", name="Investigations", exact=True)).to_be_visible()
            page.get_by_label("Sample", exact=True).set_input_files({"name": "demo.php", "mimeType": "application/octet-stream", "buffer": b"<?php system($_GET['c']); ?>"})
            page.get_by_role("button", name="Queue analysis", exact=True).click()
            playwright.expect(page.locator("#jobs")).to_contain_text("demo.php")
            subprocess.run([sys.executable, "-m", "sandworm.cli", "worker", "--once"], env=env, check=True, timeout=60)
            page.get_by_role("button", name="Refresh", exact=True).click()
            page.get_by_role("button", name="Inspect", exact=True).click()
            playwright.expect(page.locator("#evidence")).to_contain_text("static.php")
            assert page.locator("#graph circle").count() > 0
            page.locator("#graph circle").first.click()
            page.locator("#ask-form input").fill("execution sinks")
            page.get_by_role("button", name="Ask", exact=True).click()
            playwright.expect(page.locator("#answer")).to_contain_text("Evidence:")
            page.screenshot(path="/tmp/sandworm-dashboard.png", full_page=True)
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.evaluate("document.documentElement.scrollWidth <= window.innerWidth")
            assert not errors, errors
            browser.close()
    finally:
        server.terminate()
        server.wait(timeout=10)
