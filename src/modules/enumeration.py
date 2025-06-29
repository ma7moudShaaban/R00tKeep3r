import subprocess
import os
import json
import re
from modules.logger import logger


class Enumeration:
    def __init__(self, verbose = False):
        self.tools_dir = os.path.join(os.path.dirname(__file__), "../../tools")
        self.verbose = verbose
        # logger.info("Starting system enumeration")

    def run_full_enumeration(self, json_path):
        """Run all tools and parse outputs into JSON."""
        findings = {}
        
        # 1. Run and parse LinPEAS
        linpeas_log = self._run_linpeas()
        # linpeas_log = os.path.join(self.tools_dir, "linpeas_output.log")
        if os.path.exists(linpeas_log):
            findings.update(self._parse_linpeas(linpeas_log))
        else:
            #log file is missing > re-run linpeas and capture stdout directly
            
            logger.warning(f"[!]{linpeas_log} not found – re-running linpeas for live output")
            live_output = self._run_linpeas_capture()
            findings.update(self._parse_linpeas(live_output))
        
        
        
        # # 2. Run and parse pspy
        # pspy_log = self._run_pspy()
        # findings["Processes"] = self._parse_pspy(pspy_log)

        # Sort findings using dedicated function
        sorted_findings = self._sort_findings(findings)
        
        # Save to JSON
        with open(json_path, "w") as f:
            json.dump(sorted_findings, f, indent=2)
        return json_path

    def _strip_ansi_escape(self, text):
        """Remove ANSI escape sequences from text"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
    
    def remove_ansi_codes(self , text):
        """Removes ANSI escape codes from text"""
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)
        
    #region LinPEAS Execution & Parsing
    def _run_linpeas(self):

        linpeas_path = os.path.join(self.tools_dir, "linpeas.sh")
        output_path = os.path.join(self.tools_dir, "linpeas_output.log")

        # Check if LinPEAS script exists
        if not os.path.exists(linpeas_path):
            logger.error(f"LinPEAS script not found at: {linpeas_path}")
            raise SystemExit(1)

      
        # Check if file has execute permissions
        if not os.access(linpeas_path, os.X_OK):
            
            logger.warning(f"[~] linpeas.sh is not executable. Adding execution permission...")
            os.chmod(linpeas_path, 0o755)

        
        logger.debug("[~] Running LinPEAS...")

        try:
            # Redirect stdout to the logfile, discard stderr
            with open(output_path, "w", encoding="utf-8") as out_file:
                subprocess.run(
                    ["bash", linpeas_path],
                    stdout=out_file,
                    stderr=subprocess.DEVNULL,
                    text=True
                )
            
            logger.debug("[~] Saving LinPEAS output into /tools/linpeas_output.log...")
        

        except Exception as e:
            logger.error(f"[!] Unexpected error occurred: {str(e)}")
            raise SystemExit(1)

        return output_path
    
    def _run_linpeas_capture(self):
        """
        Runs linpeas.sh and returns its stdout as a string,
        without writing to a log file.
        """
        linpeas_path = os.path.join(self.tools_dir, "linpeas.sh")
        # Check if LinPEAS script exists
        if not os.path.exists(linpeas_path):
            logger.error(f"LinPEAS script not found at: {linpeas_path}")
            raise SystemExit(1)

      
        # Check if file has execute permissions
        if not os.access(linpeas_path, os.X_OK):
            
            logger.warning(f"[~] linpeas.sh is not executable. Adding execution permission...")
            os.chmod(linpeas_path, 0o755)


        # ensure exists & executable as before…
        
        logger.debug("[~] Running LinPEAS (capture mode)…")
        try:
            result = subprocess.run(
                ["bash", linpeas_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                check=True
            )
        except:
            logger.error(f"[!] Unexpected error occurred: {str(e)}")
            raise SystemExit(1)
        
        return result.stdout
            
    def _parse_linpeas(self, log_source):
        """
        Read and extract security-relevant information from LinPEAS output.
        
        :param log_source: Either a filesystem path to a LinPEAS log file,
                        or a raw string of LinPEAS output.
        :return: dict of parsed findings.
        """
        logger.debug("[~] Parsing LinPEAS...")
        # 1) Acquire raw text
        if isinstance(log_source, str) and os.path.isfile(log_source):
            # Treat as filepath
            
            logger.debug(f"[~] Reading LinPEAS log from file: {log_source}")
            with open(log_source, "r", encoding="utf-8") as f:
                raw = f.read()
        else:
            # Treat as raw text
            raw = log_source
            
            logger.debug("[~] Parsing LinPEAS output from provided text")

        # 2) Strip ANSI color codes
        log = self._strip_ansi_escape(raw)
        parsed = {
            "SudoPermissions": [],
            "SUID": [],
            "CronJobs": {},
            "Kernel": {
                "Exploits": []
            },
            "OS": ""
        }

        # # ================= Sudo Permissions =================
        sudo_section = re.search(
            r'╔══════════╣ Checking \'sudo -l\', /etc/sudoers.*?\n(.*?)(?=\n╚ )', 
            log, 
            re.DOTALL
        )
        if sudo_section:
            parsed["SudoPermissions"] = [
                line.strip() for line in sudo_section.group(1).split('\n')
                if any(x in line.lower() for x in ['nopasswd', '(root)'])  # Only look for permissions
                or (
                    'may run' in line.lower() and 
                    not re.match(r'^User \S+ may run the following commands on \S+:$', line.strip())
                )
            ]

        # ================== SUID Binaries ===================
        suid_section = re.search(
            r'╔══════════╣ SUID.*?\n(.*?)(?=\n╚ )',
            log,
            re.DOTALL
        )
        if suid_section:
            for line in suid_section.group(1).split('\n'):
                if line.startswith('-rws') and '/usr' in line:
                    # Extract path using fixed position parsing
                    path_part = line.split('--->')[0].strip() if '--->' in line else line
                    parts = path_part.split()
                    if len(parts) >= 9:  # Ensure valid format
                        path = parts[8]  # Path is always 9th column in linpeas output
                        parsed["SUID"].append(path)

        # ==================== Cron Jobs =====================
        # Regex for matching any 5‑field cron schedule, then user, then command
        CRON_LINE_RE = re.compile(
            r'^'                     # start of line
            r'(\S+(?:\s+\S+){4})'    # group1: five fields (minute…day-of-week)
            r'\s+(\S+)'              # group2: the user
            r'\s+(.+)$'              # group3: the rest (the command)
        )

        cron_section = re.search(
            r'╔══════════╣ Cron jobs.*?\n(.*?)(?=\n╚ )', 
            log, 
            re.DOTALL
        )
        if cron_section:
            current_dir = None
            system_job_keywords = [
                'run-parts',
                'anacron',
                'test -x'
            ]
            
            for line in cron_section.group(1).split('\n'):
                line = line.strip()
                
                # Switch context when encountering environment variables (assume these are part of /etc/crontab)
                if line.startswith("SHELL=") or line.startswith("PATH="):
                    current_dir = "/etc/crontab"
                    continue
                    
                # Detect cron directories and crontab file headers
                if line.startswith('/etc/cron') and line.endswith(':'):
                    current_dir = line[:-1]
                    parsed["CronJobs"][current_dir] = []
                    continue
                elif line.startswith('-rw') and '/etc/crontab' in line:
                    current_dir = '/etc/crontab'
                    parsed["CronJobs"][current_dir] = []
                    continue
                
                if not current_dir or not line:
                    continue
                    
                # Skip non-job lines
                if line.startswith(('drw', 'total', '#', '<-->')):
                    continue
                    
                # Process file entries (from ls output)
                if line.startswith('-rw'):
                    parts = line.split()
                    if len(parts) >= 9:
                        filename = parts[-1]
                        parsed["CronJobs"][current_dir].append(filename)

                # process with /etc/crontab
                elif current_dir == "/etc/crontab":
                    # Match exactly 5 schedule fields, then user, then command
                    m = CRON_LINE_RE.match(line)
                    if m and not any(kw in line for kw in system_job_keywords):
                        schedule, user, command = m.group(1), m.group(2), m.group(3)
                        parsed["CronJobs"][current_dir].append({
                            "schedule": schedule,
                            "user": user,
                            "command": command
                        })
                    elif line.startswith('@'):
                        parts = line.split()
                        if len(parts) >= 3 and not any(kw in line for kw in system_job_keywords):
                                schedule = parts[0]
                                user     = parts[1]
                                command  = ' '.join(parts[2:])
                                parsed["CronJobs"][current_dir].append({
                                "schedule": schedule,
                                "user":     user,
                                    "command":  command
                            })
                        continue

                else:
                    # For other directories, use the original strict regex
                    if re.match(r'^(\*|\d+)(\s+(\*|\d+)){4}\s+\S+', line):
                        parts = line.split()
                        if len(parts) >= 6:
                            command = ' '.join(parts[5:]).split('#')[0].strip()
                            if command and not any(kw in command for kw in system_job_keywords):
                                parsed["CronJobs"][current_dir].append(command)

        # ================ Kernel Information ================
        kernel_match = re.search(r'Kernel version:\s+(\S+)', log) or \
                      re.search(r'Uname:\s+(\S+)', log)
        if kernel_match:
            parsed["Kernel"]["Version"] = kernel_match.group(1)
        
        # Kernel Exploit Suggestions
        exploit_section = re.search(
            r'╔══════════╣ Executing Linux Exploit Suggester.*?\n(.*?)(?=\n╚ )', 
            log, 
            re.DOTALL
        )
        if exploit_section:
            parsed["Kernel"]["Exploits"] = [
                {
                    "CVE": re.search(r'(CVE-\d+-\d+)', entry).group(1),
                    "Description": re.sub(r'\[\+\]\s*', '', entry.split('\n')[0]),
                    "URL": re.search(r'Download URL:\s*(\S+)', entry).group(1)
                }
                for entry in re.split(r'\n\[\+\]', exploit_section.group(1))
                if 'CVE' in entry
            ]

        # ==================== OS Info =======================
        os_info = re.search(r'OS:\s+(.*)', log)
        if os_info:
            parsed["OS"] = os_info.group(1)

        return parsed


    #region pspy Execution & Parsing
    def _run_pspy(self):
        pspy_path = os.path.join(self.tools_dir, "pspy")
        result = subprocess.run(
            [pspy_path], 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        return result.stdout

    def _parse_pspy(self, log):
        """Extract process start times, UID, and commands."""
        processes = []
        for line in log.split("\n"):
            if "CMD" in line:
                parts = line.split()
                if len(parts) >= 5:
                    processes.append({
                        "timestamp": parts[0],
                        "uid": parts[2],
                        "cmd": " ".join(parts[4:])
                    })
        return processes
    
    def _sort_findings(self, findings):
        """Sort findings by priority: sudo > suid > cron > kernel . Processes"""
        priority_order = [
            "SudoPermissions",  # Highest priority
            "SUID", 
            "CronJobs", 
            "Kernel",
            "Processes"            # Includes version + exploits
        ]
        
        sorted_data = {}
        # Add priority keys first
        for key in priority_order:
            if key in findings:
                sorted_data[key] = findings[key]
        
        # Add non-priority keys (OS, Writable, etc.)
        for key in findings:
            if key not in priority_order:
                sorted_data[key] = findings[key]
        
        return sorted_data

    #endregion
