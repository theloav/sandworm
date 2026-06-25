/*
 * Bundled YARA rules used by analyzers/static/common.py when the `yara` Python
 * module is installed. Without it, common.py falls back to substring heuristics
 * mirroring these. Keep these tight — they run on every sample.
 */

rule SANDWORM_php_eval_base64
{
    meta:
        author = "SANDWORM"
        description = "PHP eval/base64 webshell obfuscation stack"
    strings:
        $eval = "eval(" nocase
        $b64  = "base64_decode" nocase
        $gz   = "gzinflate" nocase
    condition:
        $eval and ($b64 or $gz)
}

rule SANDWORM_powershell_encoded
{
    meta:
        author = "SANDWORM"
        description = "PowerShell encoded/download-cradle indicators"
    strings:
        $enc = "-enc" nocase
        $frb = "FromBase64String" nocase
        $dl  = "DownloadString" nocase
    condition:
        2 of them
}

rule SANDWORM_reverse_shell
{
    meta:
        author = "SANDWORM"
        description = "Unix reverse-shell primitive"
    strings:
        $devtcp = "/dev/tcp/"
        $bashi  = "bash -i"
    condition:
        any of them
}
