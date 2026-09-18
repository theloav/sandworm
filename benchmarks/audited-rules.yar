rule SANDWORM_77e23fc54a15
{
    meta:
        author = "SANDWORM"
        sample_sha256 = "77e23fc54a15be50d9c6d038014dabc094dcac7391a34a8a71a82da1493ff689"
        description = "auto-generated from static+behavioral evidence"
    strings:
        $s0 = "https://updates.example.org/script.ps1')" ascii wide
        $s1 = "remote_download" ascii wide
        $s2 = "Invoke-Expression" ascii wide
    condition:
        2 of them
}
rule SANDWORM_43af2e95eba1
{
    meta:
        author = "SANDWORM"
        sample_sha256 = "43af2e95eba167c85323c6a5fb736dd02e7c218f832aa90fa9e2a1b250691b0c"
        description = "auto-generated from static+behavioral evidence"
    strings:
        $s0 = "s7EvyCjg0tdXCHb0cwn3D/JVKK7MK8lILclMVihP" ascii wide
        $s1 = "payload.\\necho" ascii wide
        $s2 = "reached\\n" ascii wide
        $s3 = "hILEyJz8xRY8rNTkjX0EJplXX1zHI2zXICqgoPym" ascii wide
        $s4 = "ttDg5sSQ1BaZYoSg1MTkjNSUmT8maKzNNQSOzuDi" ascii wide
        $s5 = "1REMlPsg1MNQ1OCRaPTk3RT1WU1OhGuiE4pLUXE" ascii wide
        $s6 = "TSrOSM3JUXjUMEUhKTUvMz1PISU1N1" ascii wide
        $s7 = "eval(gzinflate(base64_decode(" ascii wide
        $s8 = "webshell_eval_base64" ascii wide
        $s9 = "(isset($_REQUEST" ascii wide
        $s10 = "system($_REQUEST" ascii wide
        $s11 = "SANDWORM-MARKER:" ascii wide
    condition:
        2 of them
}
