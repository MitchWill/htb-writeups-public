# HackTheBox: Cap

<img src="../assets/icons/cap.png" width="100">

**Difficulty:** Easy
**OS:** Linux

## Overview

Cap is an easy-rated Linux box built around a web application that exposes packet capture files by a predictable numeric ID (IDOR). Enumerating those captures leaks plaintext FTP credentials for a low-privileged user, which are reused for SSH access. Privilege escalation to root is achieved through a Linux capability (`cap_setuid`) misconfigured on the `python3.8` binary.

**Attack chain summary:**
IDOR on `/data/{id}` → leaked FTP credentials in a packet capture → password reuse for SSH → abuse of `cap_setuid` on `python3.8` → root.

---

## Reconnaissance

### Nmap Scan

```
nmap -sC -sV [TARGET_IP] -oN cap.nmap
```

```
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
```

Three services in scope:
- **FTP (21)** — vsftpd 3.0.3
- **SSH (22)** — OpenSSH 8.2p1 on Ubuntu
- **HTTP (80)** — a Flask app served by Gunicorn, titled "Security Dashboard"

An anonymous FTP login attempt was tested and failed, ruling that out as an entry point.

---

## Web Enumeration

Browsing the "Security Dashboard" application revealed functionality for viewing captured network traffic, exposed through URLs of the form:

```
http://[TAGET_IP]/data/<id>
```

Each ID returns a downloadable packet capture (pcap) file. This numeric, sequential ID pattern immediately suggested an **Insecure Direct Object Reference (IDOR)** — there was no indication that access to a given capture was scoped to the current session/user.

### Testing the IDOR

- `/data/1` — returned a capture of my own traffic (visible dirb/enumeration requests), confirming the app captures traffic per session and serves it back by ID.
- `/data/0` — accessible without any authorization check, despite belonging to a different (earlier) session.
- `/data/2` — no capture present.

This confirmed the IDOR: any authenticated dashboard session could pull capture files belonging to other sessions simply by decrementing the ID in the URL.

---

## Credential Discovery

The `/data/0` capture was downloaded and analyzed. Inspecting the traffic revealed an **FTP login sequence in cleartext**, exposing valid credentials:

```
Username: nathan
Password: Buck3tH4TF0RM3!
```

vsftpd does not encrypt authentication traffic by default, so the `USER`/`PASS` exchange was fully visible in the pcap.

---

## Foothold

### FTP Access

The recovered credentials were first validated against FTP:

```
ftp nathan@[TARGET_IP]
```

Login succeeded, confirming the credentials were valid and active.

### SSH via Password Reuse

Given password reuse is common on these environments, the same credentials were tried against SSH:

```
ssh nathan@[TARGET_IP]
```

This also succeeded, providing a full interactive shell as `nathan` — a significant upgrade over FTP access.

### User Flag

```
[REDACTED]
```

Retrieved directly from `nathan`'s home directory (`user.txt`), also visible via the FTP session.

---

## Privilege Escalation

### Enumeration

Standard privesc checks were run from the SSH shell as `nathan`:

```
id
sudo -l
getcap -r / 2>/dev/null
```

**Results:**

```
uid=1001(nathan) gid=1001(nathan) groups=1001(nathan)

Sorry, user nathan may not run sudo on cap.

/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep
```

`sudo -l` was a dead end, but `getcap` revealed that `/usr/bin/python3.8` had the **`cap_setuid`** Linux capability set with the `eip` flags (effective, inheritable, permitted). This means the binary can call `setuid()` and switch to any UID — including root — regardless of who executes it.

### Exploitation

This is a well-known GTFOBins technique for binaries with `cap_setuid`:

```bash
/usr/bin/python3.8 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

This spawned a root shell.

### Root Flag

```
[REDACTED]
```

Retrieved from `/root/root.txt`.

---

## Lessons Learned & Remediation

| Weakness | Impact | Remediation |
|---|---|---|
| **IDOR on `/data/{id}`** | Any authenticated user could view/download packet captures belonging to other sessions, including ones containing credentials. | Enforce server-side authorization checks that scope capture access to the session/user that generated it. Use non-sequential, unguessable identifiers (e.g. UUIDs) as defense in depth — but authorization checks are the actual fix, not obscurity. |
| **Cleartext FTP credentials captured in traffic** | Credentials were trivially recoverable from a plaintext protocol. | Avoid using unencrypted protocols like FTP for authentication; use SFTP/FTPS. More broadly, avoid storing or transmitting live credentials in any traffic that might be logged or captured. |
| **Password reuse across services (FTP → SSH)** | A single credential leak led directly to full shell access. | Enforce unique credentials per service; consider SSH key-based auth only, disabling password authentication entirely. |
| **`cap_setuid` set on `/usr/bin/python3.8`** | Allowed any user able to execute the interpreter to escalate directly to root, bypassing the need for `sudo` misconfiguration or SUID binaries. | Remove unnecessary Linux capabilities from interpreters and general-purpose binaries. Capabilities should be scoped to the specific binary/script that needs them, not applied broadly to something like the system Python interpreter. Regularly audit with `getcap -r /`. |

**Key takeaway:** This box is a good reminder that privilege escalation doesn't always come from SUID binaries or sudo misconfigurations — Linux capabilities (`getcap`) are an equally viable and often-overlooked vector, and should be part of standard enumeration on every engagement.

---

## Tools Used

- `nmap` — service/version enumeration
- Web browser — dashboard exploration and IDOR discovery
- Wireshark / `tshark` — pcap analysis
- `ftp` / `ssh` — credential validation and shell access
- `getcap` — Linux capability enumeration
