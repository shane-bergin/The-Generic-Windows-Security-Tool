rule TGWST_Suspicious_Obfuscated_Script_Win {
    meta:
        author      = "TGWST v2.0"
        description = "Heuristic: Obfuscated Windows script loaders (PowerShell-heavy)"
        score       = 70

    strings:
        $ps_header  = "powershell" nocase
        $ps_nop     = /powershell(\.exe)?\s+-nop\b/ nocase

        $b64_1      = "FromBase64String(" nocase
        $b64_2      = "Convert::FromBase64String" nocase
        $b64_3      = "[System.Convert]::FromBase64String" nocase

        $iex_short  = "IEX(" nocase
        $iex_call   = "IEX " nocase
        $invoke_exp = "Invoke-Expression" nocase

        $ps_enc     = /\-enc(odedcommand)?\b/ nocase

    condition:
        ( $ps_header or $ps_nop ) and
        ( any of ($b64_*) ) and
        ( any of ($iex_*, $invoke_exp, $ps_enc) )
}


rule TGWST_Potential_Backdoor_Indicator_WinPE {
    meta:
        author      = "TGWST v2.0"
        description = "Anomalous netconn / PS stager primitives in Windows PE binaries"
        score       = 65

    strings:
        $nc_listen = /nc(\.exe)?\s+-l[v]?[p]?[n]?\s+/ nocase
        $ps_stager = /powershell(\.exe)?\s+-nop\b.*\b(-c|-enc|-encodedcommand)\b/ nocase

    condition:
        uint16(0) == 0x5A4D and
        ( $nc_listen or $ps_stager )
}