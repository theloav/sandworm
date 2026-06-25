"""The PHP differentiator: unwrap nested eval/base64/gzinflate/str_rot13/chr and
flag the dangerous sink in the recovered payload."""

from __future__ import annotations

import base64
import zlib

from sandworm.analyzers.base import Context
from sandworm.analyzers.static.php import PhpAnalyzer, deobfuscate, find_sinks
from sandworm.core.sample import Sample


def _gzinflate_b64(s: str) -> str:
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    comp = co.compress(s.encode()) + co.flush()
    return base64.b64encode(comp).decode()


def test_unwrap_nested_eval_base64_gzinflate():
    inner = "<?php system($_GET['c']); ?>"
    layer1 = f"eval(gzinflate(base64_decode('{_gzinflate_b64(inner)}')))"
    outer = f"<?php eval(base64_decode('{base64.b64encode(layer1.encode()).decode()}')); ?>"

    layers, final = deobfuscate(outer)
    assert len(layers) >= 2
    assert "system($_GET" in final
    # each peel records which decoder it applied
    fns = {layer["function"] for layer in layers}
    assert {"base64_decode", "gzinflate"} & fns or "eval" in str(fns)


def test_str_rot13_and_chr_chain():
    # str_rot13 wrapping (payload chosen so its rot13 has no quote chars), plus a
    # chr() concatenation forming "system".
    payload = "phpinfo();"
    import codecs

    rot = codecs.encode(payload, "rot13")
    assert "'" not in rot
    code = f"<?php eval(str_rot13('{rot}')); ?>"
    layers, final = deobfuscate(code)
    assert payload in final

    chr_expr = ".".join(f"chr({ord(c)})" for c in "system")
    code2 = f"<?php $x = {chr_expr}; ?>"
    layers2, final2 = deobfuscate(code2)
    assert "system" in final2


def test_sink_detection():
    code = "<?php shell_exec($_POST['x']); passthru('id'); ?>"
    sinks = {name for _cat, name, _conf in find_sinks(code)}
    assert "shell_exec" in sinks
    assert "passthru" in sinks


def test_analyzer_emits_layer_and_verdict(temp_config, samples_dir):
    sample = Sample.from_path(samples_dir / "benign_webshell.php")
    sample.format_hint = "php"
    ctx = Context(run_id="t", config=temp_config)
    items = PhpAnalyzer().analyze(sample, ctx)

    decode_layers = [i for i in items if i.operation == "decode" and "layer" in i.object]
    assert len(decode_layers) >= 2
    assert any(i.object.get("verdict") == "php_webshell" for i in items)
    assert any(i.object.get("sink") == "system" for i in items)
    # confidence present and bounded on every emitted item
    assert all(0.0 <= i.confidence <= 1.0 for i in items)


def test_malformed_input_does_not_crash():
    layers, final = deobfuscate("<?php eval(base64_decode( ; ?>")
    assert isinstance(layers, list)
