import subprocess
import os
import sys
import re
import psutil
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class WindowsFirewall:
    """Windows firewall implementation using Windows Firewall with Advanced Security"""
    
    def __init__(self):
        self.rule_prefix = "PersonalFirewall-"
        self._check_admin()
    
    def _check_admin(self):
        """Check if the application is running with administrative privileges"""
        if not self._is_admin():
            logger.error("Administrative privileges required for Windows Firewall operations")
            return False
        return True
    
    def _is_admin(self):
        """Check if the current process has administrative privileges"""
        try:
            return os.getuid() == 0
        except AttributeError:
            try:
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            except:
                return False
    
    def get_all_rules(self):
        """Get all firewall rules created by this application"""
        try:
            cmd = ['netsh', 'advfirewall', 'firewall', 'show', 'rule', 'name=all']
            output = subprocess.check_output(cmd, text=True)
            
            rules = []
            current_rule = {}
            rule_pattern = re.compile(fr"^Rule Name:\s+{self.rule_prefix}(.*)")
            
            for line in output.split('\n'):
                rule_match = rule_pattern.match(line.strip())
                if rule_match:
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {"name": rule_match.group(1)}
                elif "Program:" in line and current_rule:
                    program = line.split("Program:")[1].strip()
                    current_rule["program"] = program
                elif "Action:" in line and current_rule:
                    action = line.split("Action:")[1].strip()
                    current_rule["action"] = action
            
            if current_rule:
                rules.append(current_rule)
                
            return rules
        except subprocess.CalledProcessError as e:
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
            
        app_name = app_path.name
        rule_name = f"{self.rule_prefix}{app_name}"
        
        # Check if rule already exists
        existing_rules = self.get_all_rules()
        for rule in existing_rules:
            if rule["name"] == app_name:
                # Rule already exists
                return True
        
        # Create outbound block rule
        try:
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}"',
                'dir=out',
                'action=block',
                f'program="{app_path}"',
                'enable=yes',
                'profile=any'
            ]
            subprocess.check_call(cmd)
            
            # Also create an inbound block rule
            cmd = [
                'netsh', 'advfirewall', 'firewall', 'add', 'rule',
                f'name="{rule_name}-In"',
                'dir=in',
                'action=block',
                f'program="{app_path}"',
                'enable=yes',
                'profile=any'
            ]
            subprocess.check_call(cmd)
            
            logger.info(f"Successfully blocked application: {app_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to block application {app_name}: {e}")
            return False
    
    def unblock_application(self, app_path):
        """Unblock an application that was previously blocked"""
        if not self._check_admin():
            return False
            
        app_path = Path(app_path).resolve()
        app_name = app_path.name
        rule_name = f"{self.rule_prefix}{app_name}"
        
        try:
            # Remove outbound rule
            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name="{rule_name}"']
            subprocess.check_call(cmd)
            
            # Remove inbound rule
            cmd = ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name="{rule_name}-In"']
            subprocess.check_call(cmd)
            
            logger.info(f"Successfully unblocked application: {app_name}")
            return True
            
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to unblock application {app_name}: {e}")
            return False
    
    def is_application_blocked(self, app_path):
        """Check if an application is currently blocked"""
        app_path = Path(app_path).resolve()
        app_name = app_path.name
        
        rules = self.get_all_rules()
        for rule in rules:
            if rule["name"] == app_name:
                # Check if the rule is a block rule
                return rule.get("action", "").lower() == "block"
        
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