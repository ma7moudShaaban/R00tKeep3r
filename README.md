# R00tKeep3r

A comprehensive post-exploitation automation and privilege escalation Toolkit

![GitHub stars](https://img.shields.io/github/stars/ma7moudShaaban/R00tKeep3r?style=social) ![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)

---

## Table of Contents

* [Overview](#overview)
* [Open Source & Support](#open-source--support)
* [Features](#features)
* [Requirements](#requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Output & Reports](#output--reports)
* [Issues & Discussions](#issues--discussions)
* [Contributing](#contributing)
* [License](#license)

---

## Overview

R00tKeep3r is a Python-based post-exploitation toolkit that automates the discovery and exploitation of privilege escalation vectors on Linux targets. It combines system enumeration, GTFOBins-based methods, kernel exploit PoCs, and cron-job persistence into a single, streamlined workflow.

---

## Open Source & Support

R00tKeep3r is fully open-source and hosted on GitHub: [https://github.com/ma7moudShaaban/R00tKeep3r](https://github.com/ma7moudShaaban/R00tKeep3r)

We welcome contributions, bug reports, and feature requests. If you encounter any errors or unexpected behavior:

* **Create an Issue**: Describe the problem, reproduction steps, and environment details.
* **Discussions**: Join our GitHub Discussions to ask questions or propose enhancements.

---

## Features

* **Automated Enumeration**: Gathers system information, running processes, SUID binaries, sudo policies, cron schedules, kernel version, and more.
* **GTFOBins Integration**: Detects and executes suitable SUID and sudo escape methods automatically.
* **Kernel Exploits**: Includes local PoCs for known kernel vulnerabilities (where applicable).
* **Cron-Job Persistence**: Injects and schedules payloads into writable cron jobs for long-term access.
* **Modular Design**: Split into logical modules for enumeration, exploitation, and reporting.

---

## Requirements

* **Python**: 3 or higher
* **Operating System**: Linux target


---

## Installation

- **Clone repository**

   ```bash
   git clone https://github.com/ma7moudShaaban/R00tKeep3r.git
   cd R00tKeep3r
   ```
---

## Usage

Run the full automation workflow with a single command:

```bash
python3 src/R00tKeep3r.py --help
 ____   ___   ___  _     _  __              _____      
|  _ \ / _ \ / _ \| |_  | |/ /___  ___ _ __|___ / _ __ 
| |_) | | | | | | | __| | ' // _ \/ _ \ '_ \ |_ \| '__|
|  _ <| |_| | |_| | |_  | . \  __/  __/ |_) |__) | |   
|_| \_\\___/ \___/ \__| |_|\_\___|\___| .__/____/|_|   
                                      |_|              

₍^. .^₎⟆ R00tKeep3r: Automated Post-Exploitation Toolkit ₍^. .^₎⟆
usage: R00tKeep3r.py [-h] [-m | -a] [-v] [-j JSON] [-o OUTPUT]

R00tKeep3r: Automated Post-Exploitation Toolkit

options:
  -h, --help           show this help message and exit
  -m, --manual         Interactive escalation vector selection
  -a, --all            Fully automated mode with verbose output (no prompts)
  -v, --verbose        Enable verbose output (auto-enabled with -a)
  -j, --json JSON      Custom JSON output path (default: /tmp/keep3rs.json)
  -o, --output OUTPUT  Custom JSON output path (default: ./report.txt)

Example: python3 R00tKeep3r.py -m -v --output /path/to/report.txt

```



---

## Output & Reports

After execution, R00tKeep3r generates:

* **Report** (`report.txt`):

  * Sections for each phase: Enumeration, SUID Exploits, Sudo Escapes, Kernel PoCs, Cron Jobs
  * Timestamped entries and `whoami` verification results

**Example Report Snippet**:

```
 ____   ___   ___  _     _  __              _____      
|  _ \ / _ \ / _ \| |_  | |/ /___  ___ _ __|___ / _ __ 
| |_) | | | | | | | __| | ' // _ \/ _ \ '_ \ |_ \| '__|
|  _ <| |_| | |_| | |_  | . \  __/  __/ |_) |__) | |   
|_| \_\\___/ \___/ \__| |_|\_\___|\___| .__/____/|_|   
                                      |_|

[09:52:42] 1. TOOL START
========================
  • Command: /usr/bin/python3 R00tKeep3r.py -m -v
  • Mode:    manual
  • Verbose: True


[09:52:42] 2. ENUMERATION
========================
  • Start Time:   09:52:42
  • Findings JSON: /tmp/keep3rs.json

[09:52:42] 3. Running LinPEAS
[09:56:09] 4. Parsing LinPEAS


[09:56:09] 5. PRIVILEGE ESCALATION
==================================
  • Start Time: 09:56:09

[09:56:09] 6. SUID EXPLOITATION
  • Vectors:
    /usr/libexec/polkit-agent-helper-1
    /usr/bin/kismet_cap_nrf_51822
    /usr/bin/newgrp
    /usr/bin/sudo
    /usr/bin/umount
    /usr/bin/bash
    /usr/bin/chsh
    /usr/bin/find
    /usr/bin/kismet_cap_ti_cc_2531
    /usr/bin/chfn
    /usr/bin/kismet_cap_linux_bluetooth
    /usr/bin/gpasswd
    /usr/bin/vmware-user-suid-wrapper
    /usr/bin/kismet_cap_nrf_mousejack
    /usr/bin/passwd
    /usr/bin/kismet_cap_linux_wifi
    /usr/bin/kismet_cap_ti_cc_2540
    /usr/bin/kismet_cap_ubertooth_one
    /usr/bin/pkexec
    /usr/bin/su
    /usr/bin/ntfs-3g
    /usr/bin/bwrap
    /usr/bin/mount
    /usr/bin/kismet_cap_nxp_kw41z
    /usr/bin/fusermount3
    /usr/sbin/mount.cifs
    /usr/sbin/mount.nfs
    /usr/sbin/pppd
    /usr/share/code/chrome-sandbox
    /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    /usr/lib/openssh/ssh-keysign
    /usr/lib/xorg/Xorg.wrap
  • Results:
    (no GTFOBins entry: first 5 candidates)
    /usr/bin/bash: success
  • Success: Success


[--:--:--] 7. SUDO EXPLOITATION
  • Vectors:
    (ALL : ALL) NOPASSWD: ALL
  • Results:
    <none>
  • Success: Skipped


[--:--:--] 8. KERNEL EXPLOITATION
  • CVEs:
    CVE-2021-3490
    CVE-2022-0847
    CVE-2021-4034
    CVE-2021-3156
    CVE-2021-3156
    CVE-2021-22555
    CVE-2017-5618
  • Results:
    <none>
  • Success: Skipped


[--:--:--] 9. CRON INJECTION
  • Jobs Extracted:
    /home/kali/Desktop/backup.sh
    /etc/cron.d/e2scrub_all
    /etc/cron.d/geoipupdate
    /etc/cron.d/john
    /etc/cron.d/php
    /etc/cron.d/sysstat
    /etc/cron.daily/apache2
    /etc/cron.daily/apt-compat
    /etc/cron.daily/calendar
    /etc/cron.daily/chkrootkit
    /etc/cron.daily/debtags
    /etc/cron.daily/dpkg
    /etc/cron.daily/logrotate
    /etc/cron.daily/man-db
    /etc/cron.daily/mlocate
    /etc/cron.daily/ntp
    /etc/cron.daily/samba
    /etc/cron.daily/sysstat
    /etc/cron.monthly/rwhod
    /etc/cron.weekly/man-db
  • Injection Results:
    <none>
  • Success: Skipped


[09:56:15] 10. PERSISTENCE
==========================
  • Choice: Not chosen

  

Privilege Escalation Result: Succeeded
---
Generated by Session Management Module

```

---



## Issues & Discussions

If you discover any bugs or want to propose features, please:

* Open a GitHub Issue: [Issues](https://github.com/ma7moudShaaban/R00tKeep3r/issues)
* Start a Discussion: [Discussions](https://github.com/ma7moudShaaban/R00tKeep3r/discussions)

Your feedback helps improve R00tKeep3r for everyone!


---

## Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feature/my-feature`
3. Implement changes and commit: `git commit -m "Add new exploit module"`
4. Push to your fork: `git push origin feature/my-feature`
5. Open a Pull Request

---

## License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
