"""Regressions from a real incident sample (an Indonesian "seo1719" webshell with
an embedded HTML/JS admin panel):

1. The IOC extractor must NOT treat JavaScript member access / object paths /
   filenames as domains (they flooded the IOCs and poisoned the Sigma C2 rule).
2. A cleartext webshell (execution sink + attacker-controlled input, no
   obfuscation) must still get the web-shell verdict.
"""

from __future__ import annotations

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.common import extract_iocs
from sandworm.analyzers.static.php import PhpAnalyzer
from sandworm.core.sample import Sample


def test_js_member_access_not_flagged_as_domain():
    js = """
        document.getElementById('x'); a.onclick = f; d.msg; JSON.stringify(o);
        termOut.innerHTML = ''; fileTableBody.appendChild(tr); res.json();
    """
    domains = {v for kind, v, _c, _fp in extract_iocs(js) if kind == "domain"}
    assert domains == set(), f"JS member access leaked as domains: {domains}"


def test_real_domains_and_urls_survive():
    text = "contact seo1719@sayangkamu.id via https://i.ibb.co/VHRN7Gf/seo1719.jpg and c2.evil.ru"
    iocs = extract_iocs(text)
    kinds = {(k, v) for k, v, _c, _fp in iocs}
    assert ("url", "https://i.ibb.co/VHRN7Gf/seo1719.jpg") in kinds
    assert ("domain", "c2.evil.ru") in kinds
    assert ("domain", "sayangkamu.id") in kinds
    # the image *filename* is not a domain
    assert not any(k == "domain" and v == "seo1719.jpg" for k, v in kinds)


def test_cleartext_webshell_verdict(temp_config):
    # No obfuscation, but a command sink fed by attacker input → still a web shell.
    shell = b"<?php if(isset($_POST['cmd'])) { echo proc_open($_POST['cmd'], $d, $p); } ?>"
    sample = Sample.from_bytes("ekb2hv95.php", shell)
    sample.format_hint = "php"
    items = PhpAnalyzer().analyze(sample, Context(run_id="t", config=temp_config))
    verdicts = [i for i in items if i.object.get("verdict") == "php_webshell"]
    assert verdicts, "cleartext webshell should be flagged"
    assert verdicts[0].details["tainted_input"]
    assert verdicts[0].details["layers"] == 0
