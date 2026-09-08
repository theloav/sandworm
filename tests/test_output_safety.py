"""Generated analyst artifacts must treat sample-derived data as hostile."""

from __future__ import annotations

from sandworm.core.pipeline import analyze_sample, build_report_inputs
from sandworm.core.sample import Sample
from sandworm.detect.sigma_gen import SigmaRule
from sandworm.reporting.report import render_html


def test_html_report_escapes_sample_controlled_markup(temp_config):
    payload = "</title><script>globalThis.pwned=true</script>"
    sample = Sample.from_bytes(f"{payload}.php", b"<?php echo 1; ?>")
    result = analyze_sample(sample, config=temp_config, enable_dynamic=False, use_cache=False)

    html = render_html(build_report_inputs(result))

    assert payload not in html
    assert "&lt;script&gt;globalThis.pwned=true&lt;/script&gt;" in html
    assert "Content-Security-Policy" in html
    assert "object-src 'none'" in html


def test_sigma_quotes_yaml_control_characters():
    rule = SigmaRule(
        title="SANDWORM: quoted # title",
        description="line: value # not a comment",
        logsource={"category": "process_creation"},
        detection={
            "selection": {"CommandLine|contains": ["a: b", "# comment", "true"]},
            "condition": "selection",
        },
    )

    rendered = rule.to_yaml()

    assert 'title: "SANDWORM: quoted # title"' in rendered
    assert 'description: "line: value # not a comment"' in rendered
    assert '            - "a: b"' in rendered
    assert '            - "# comment"' in rendered
    assert '            - "true"' in rendered
