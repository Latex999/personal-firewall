import os
import sys
import logging
import platform
from pathlib import Path

logger = logging.getLogger(__name__)

def is_admin():
    """Check if the current process has administrative privileges"""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Linux/Unix
            return os.geteuid() == 0
    except Exception as e:
        logger.error(f"Failed to check admin privileges: {e}")
        return False

def restart_as_admin():
    """Restart the application with administrative privileges"""
    try:
        if platform.system() == "Windows":
            import ctypes
            import win32con
            
            if not is_admin():
                # Get the script filename
                script = sys.argv[0]
                args = " ".join(sys.argv[1:])
                
                # Use ShellExecute to run as admin
                ctypes.windll.shell32.ShellExecuteW(
                    None, 
                    "runas", 
                    sys.executable, 
                    f'"{script}" {args}', 
                    None, 
                    win32con.SW_SHOWNORMAL
                )
                
                # Exit the current instance
                sys.exit(0)
        else:  # Linux/Unix
            if not is_admin():
                # Get the script filename
                script = sys.argv[0]
                args = " ".join(sys.argv[1:])
                
                # Use pkexec, sudo, or similar
                try:
                    from elevate import elevate
                    elevate(graphical=True)
                except ImportError:
                    os.execvp("sudo", ["sudo", sys.executable, script] + sys.argv[1:])
                
                # If we get here, it means execution failed
                print("Failed to restart with elevated privileges. Please run as root/sudo.")
                sys.exit(1)
    except Exception as e:
        logger.error(f"Failed to restart as admin: {e}")
        return False