rule TGWST_Suspicious_Obfuscated_Shell {
meta:
author = "TGWST v2.0"
description = "Heuristic: Obfuscated shell loaders"
score = 70
strings:
$s1 = "eval $" ascii wide
$s2 = "base64 -d" nocase
condition:
uint8(0) == 0x23 and all of ($s*)
}

rule TGWST_Potential_Backdoor_Indicator {
meta:
author = "TGWST v2.0"
description = "Anomalous netconn primitives"
score = 65
strings:
$s1 = "nc -lvp" nocase
$s2 = "powershell -nop -c" nocase
condition:
$s1 or $s2
}