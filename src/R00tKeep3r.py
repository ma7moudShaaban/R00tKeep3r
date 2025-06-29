import os
import subprocess
import argparse 
from modules.enumeration import Enumeration
from modules.escalation import Escalation  
from modules.logger import setup_logging, logger
from modules.session import SessionManager
import sys
import time
from modules.json_api import JSONHandler
from modules.persistence import execute_persistence
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def display_banner():
    banner_path = os.path.join(os.path.dirname(__file__), "banner.txt")
    with open(banner_path, "r") as banner_file:
        print(banner_file.read())

def main():
    display_banner()
    print("₍^. .^₎⟆ R00tKeep3r: Automated Post-Exploitation Toolkit ₍^. .^₎⟆")
    parser = argparse.ArgumentParser(
        description="R00tKeep3r: Automated Post-Exploitation Toolkit",
        epilog="Example: python3 cli.py -m -v --output /path/to/report.txt",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-m", "--manual", action="store_true",
                      help="Interactive escalation vector selection")
    group.add_argument("-a", "--all", action="store_true",
                      help="Fully automated mode with verbose output (no prompts)")
    
    # General arguments
    parser.add_argument("-v", "--verbose", action="store_true",
                      help="Enable verbose output (auto-enabled with -a)")
    parser.add_argument("-j", "--json", default="/tmp/keep3rs.json",
                      help="Custom JSON output path (default: /tmp/keep3rs.json)")
    
    parser.add_argument("-o", "--output", default="report.txt",
                      help="Custom JSON output path (default: ./report.txt)")
    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    if args.all:
        args.verbose = True 
        setup_logging(verbose=args.verbose)   

    # Initialize modules
    enumerator = Enumeration(verbose=args.verbose)            # Enumeration module instance
    escalator = Escalation()                                  # Escalation module instance

    json_path = args.json

    #Enumeration
    logger.info(f"[*] Starting enumeration (output: {json_path})...")
    enumerator.run_full_enumeration(json_path)
    

    #Escalation
    logger.info("[*] Starting privilege escalation...")
    if args.manual:
        logger.info("[*] Manual escalation mode")
        escalator.manual_escalate(json_path)
    else:
        logger.info("[*] Auto escalation mode")
        escalator.execute_escalation(json_path)

    # Persistence
    # load JSON to see if the user asked for persistence
    data = JSONHandler().read_json()
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
                time.sleep(2) # Give it a moment to spawn
                if args.manual:
                    print("[*] Manual mode")
                    execute_persistence(root_proc, manual_mode=True)
                else:
                    print("[*] Auto mode")
                    execute_persistence(root_proc, manual_mode=False)
                # # It's important to close the subprocess to avoid resource leaks
                # root_proc.stdin.close()
                # root_proc.stdout.close()
                # root_proc.stderr.close()
                root_proc.wait(timeout=5) # Wait for the process to finish
            except FileNotFoundError:
                logger.error(f"Error: Command not found: {expl}")
            except Exception as e:
                logger.error(f"✅Persistence Setup Successful")
        else:
            logger.error("Error: 'exploit_command' not found in persistence configuration.")
    else:
        logger.info("[*] No persistence requested—skipping persistence module.")
# -------------------------------------------------------------------------------------------------------

    #Generate final report
    logger.debug("[~] Initializing session manager")
    session = SessionManager(
        json_path,
        log_path="/tmp/debug.log", 
        report_path=args.output,
    )
    # reconstruct the exact command‐line
    cmd = sys.executable + " " + " ".join(sys.argv)
    mode = "all" if args.all else "manual" if args.manual else "automatic"
    session.generate_report(cmd, mode, args.verbose)
    logger.info(f"Report generated at: {args.output}")
    


if __name__ == "__main__":
    main()
