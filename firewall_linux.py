import os
import subprocess
import psutil
import logging
from pathlib import Path
import iptc

logger = logging.getLogger(__name__)

class LinuxFirewall:
    """Linux firewall implementation using iptables"""
    
    def __init__(self):
        self.chain_name = "PERSONAL_FIREWALL"
        self._check_admin()
        self._ensure_chain_exists()
    
    def _check_admin(self):
        """Check if the application is running with root privileges"""
        if os.geteuid() != 0:
            logger.error("Root privileges required for Linux firewall operations")
            return False
        return True
    
    def _ensure_chain_exists(self):
        """Ensure our custom iptables chain exists"""
        if not self._check_admin():
            return False
            
        try:
            # Check if our chain exists
            table = iptc.Table(iptc.Table.FILTER)
            if self.chain_name not in table.chains:
                # Create our chain
                chain = iptc.Chain(table, self.chain_name)
                table.create_chain(chain)
                
                # Add rules to the INPUT and OUTPUT chains to jump to our chain
                for base_chain_name in ["INPUT", "OUTPUT"]:
                    base_chain = iptc.Chain(table, base_chain_name)
                    rule = iptc.Rule()
                    rule.target = iptc.Target(rule, self.chain_name)
                    base_chain.insert_rule(rule)
                    
            return True
            
        except Exception as e:
            logger.error(f"Failed to setup iptables chain: {e}")
            return False
    
    def get_all_rules(self):
        """Get all firewall rules created by this application"""
        if not self._check_admin():
            return []
            
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            rules = []
            
            for rule in chain.rules:
                if rule.target.name == "DROP" and rule.src:
                    match = next((m for m in rule.matches if m.name == "owner"), None)
                    if match and hasattr(match, "pid"):
                        pid = match.pid
                        try:
                            process = psutil.Process(int(pid))
                            rules.append({
                                "name": Path(process.exe()).name,
                                "program": process.exe(),
                                "action": "block",
                                "pid": pid
                            })
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            # Process no longer exists or we can't access it
                            pass
            
            return rules
            
        except Exception as e:
            logger.error(f"Failed to list firewall rules: {e}")
            return []
    
    def block_application(self, app_path):
        """Block an application from accessing the internet"""
        if not self._check_admin():
            return False
            
        app_path = Path(app_path).resolve()
        if not app_path.exists():
            logger.error(f"Application not found: {app_path}")
            return False
            
        # Find all PIDs for this application
        pids = []
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                if proc.info['exe'] == str(app_path):
                    pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if not pids:
            logger.error(f"No running processes found for {app_path}")
            return False
            
        app_name = app_path.name
        
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            
            # Check if rule already exists
            for existing_rule in chain.rules:
                if existing_rule.target.name == "DROP":
                    match = next((m for m in existing_rule.matches if m.name == "owner"), None)
                    if match and hasattr(match, "pid") and int(match.pid) in pids:
                        # Rule already exists
                        return True
            
            # Create rules for each PID
            for pid in pids:
                # Outbound rule
                rule = iptc.Rule()
                rule.target = iptc.Target(rule, "DROP")
                match = rule.create_match("owner")
                match.pid = str(pid)
                chain.insert_rule(rule)
                
                # Inbound rule (for established connections)
                rule = iptc.Rule()
                rule.target = iptc.Target(rule, "DROP")
                match = rule.create_match("owner")
                match.pid = str(pid)
                match = rule.create_match("state")
                match.state = "ESTABLISHED,RELATED"
                chain.insert_rule(rule)
                
            logger.info(f"Successfully blocked application: {app_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to block application {app_name}: {e}")
            return False
    
    def unblock_application(self, app_path):
        """Unblock an application that was previously blocked"""
        if not self._check_admin():
            return False
            
        app_path = Path(app_path).resolve()
        
        # Find all PIDs for this application
        pids = []
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                if proc.info['exe'] == str(app_path):
                    pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if not pids:
            # Application might not be running, try to find rules based on path
            return self._unblock_by_path(app_path)
            
        app_name = app_path.name
        
        try:
            table = iptc.Table(iptc.Table.FILTER)
            chain = iptc.Chain(table, self.chain_name)
            
            # Find and delete rules for each PID
            for pid in pids:
                for rule in chain.rules:
                    if rule.target.name == "DROP":
                        match = next((m for m in rule.matches if m.name == "owner"), None)
                        if match and hasattr(match, "pid") and match.pid == str(pid):
                            chain.delete_rule(rule)
            
            logger.info(f"Successfully unblocked application: {app_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to unblock application {app_name}: {e}")
            return False
    
    def _unblock_by_path(self, app_path):
        """Fallback method to unblock an application by path when it's not running"""
        try:
            # Use iptables command directly to search for comment metadata
            app_name = app_path.name
            cmd = ["iptables", "-L", self.chain_name, "--line-numbers", "-v"]
            output = subprocess.check_output(cmd, text=True)
            
            # Find rule numbers
            rule_nums = []
            for line in output.splitlines():
                if app_name in line:
                    parts = line.split()
                    if parts and parts[0].isdigit():
                        rule_nums.append(int(parts[0]))
            
            # Delete rules from highest number to lowest to avoid index shifting
            rule_nums.sort(reverse=True)
            for num in rule_nums:
                cmd = ["iptables", "-D", self.chain_name, str(num)]
                subprocess.check_call(cmd)
            
            return len(rule_nums) > 0
            
        except Exception as e:
            logger.error(f"Failed to unblock application by path: {e}")
            return False
    
    def is_application_blocked(self, app_path):
        """Check if an application is currently blocked"""
        app_path = Path(app_path).resolve()
        
        # Find PIDs for this application
        pids = []
        for proc in psutil.process_iter(['pid', 'exe']):
            try:
                if proc.info['exe'] == str(app_path):
                    pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        if not pids:
            return False
            
        rules = self.get_all_rules()
        for rule in rules:
            if rule.get("program") == str(app_path) and rule.get("action", "").lower() == "block":
                return True
        
        return False
    
    def get_all_applications(self):
        """Get a list of applications that can access the internet"""
        apps = []
        
        # Get all running processes with network connections
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                proc_info = proc.info
                if proc_info['exe'] and os.path.exists(proc_info['exe']):
                    # Check if it has internet connections
                    connections = proc.connections(kind='inet')
                    if connections:
                        blocked = self.is_application_blocked(proc_info['exe'])
                        apps.append({
                            'name': proc_info['name'],
                            'path': proc_info['exe'],
                            'blocked': blocked,
                            'pid': proc_info['pid']
                        })
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
        
        return apps