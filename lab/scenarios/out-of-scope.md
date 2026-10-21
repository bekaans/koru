# Out-of-scope Atomic Red Team Linux techniques (not counted toward the 100)

Koru's scope is decoy/breadcrumb file-access detection (see the README). The techniques
below cannot be represented by file access or are outside Koru's domain:

- T1059 (Command and Scripting Interpreter): not a detection signal on its own; only a carrier in scenarios.
- T1078 (Valid Accounts), T1110 (Brute Force): the authentication layer; WAF/identity domain, outside Koru.
- T1046 (Network Service Discovery), T1048/T1041 (Exfiltration): the network layer; edge-solution domain.
- T1548, T1547, T1574 (persistence/privilege): produce no Koru signal without decoy access; in the rule pack only changes targeting Koru itself (the T1543.002 service unit) are watched; not counted as an attack scenario.
- T1070 (Indicator Removal): covered in the self-protection rules only as Koru store/finding tampering; not counted as a general deletion scenario.
- T1027 (Obfuscation), T1140 (Deobfuscate): content analysis is outside Koru's scope.
