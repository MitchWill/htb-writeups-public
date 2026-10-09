# HackTheBox Writeups

A collection of my HackTheBox machine writeups, documenting methodology, exploitation steps, and lessons learned.

## Solved Machines

| Icon | Machine | Difficulty | OS | Techniques | Writeup |
|------|---------|------------|-----|------------|---------|
| <img src="assets/icons/cap.png" width="40"> | **Cap** | Easy | Linux | IDOR, packet analysis, cap_setuid escalation | [Read writeup](writeups/cap-writeup.md) |
| <img src="assets/icons/orion.png" width="40"> | **Orion** | Easy | Linux | Craft CMS pre-auth RCE (CVE-2025-32432), credential reuse, telnetd auth bypass (CVE-2026-24061) | [Read writeup](writeups/orion-writeup.md) |
| <img src="assets/icons/support.png" width="40"> | **Support** | Easy | Windows | LDAP null session, .NET reverse engineering, ACL abuse (GenericAll), RBCD, DCSync | [Read writeup](writeups/support-writeup.md) |
| <img src="assets/icons/legacy.png" width="40"> | **Legacy** | Easy | Windows | MS08-067 SMB RPC stack overflow (CVE-2008-4250), unauthenticated SYSTEM RCE | [Read writeup](writeups/legacy-writeup.md) |

## Notable CVEs Covered

- **CVE-2025-32432** — Craft CMS pre-auth RCE via insecure deserialization ([Orion](writeups/orion-writeup.md))
- **CVE-2026-24061** — GNU InetUtils telnetd authentication bypass ([Orion](writeups/orion-writeup.md))
- **CVE-2008-4250** — MS08-067 SMB Server service stack buffer overflow, pre-auth RCE ([Legacy](writeups/legacy-writeup.md))

## Notable Misconfigurations & Techniques Covered

- **GenericAll ACL abuse on a DC computer object → RBCD → DCSync** ([Support](writeups/support-writeup.md))
- **Custom binary reverse engineering to recover hardcoded credentials** ([Support](writeups/support-writeup.md))

## About

These writeups are maintained for personal reference and portfolio purposes. Each includes enumeration steps, exploitation walkthroughs, and root-cause analysis of the vulnerabilities involved.