import platform
import logging

logger = logging.getLogger(__name__)

def get_firewall():
    """Factory function to get the appropriate firewall implementation for the current platform"""
    system = platform.system()
    
    if system == "Windows":
        try:
            from firewall_windows import WindowsFirewall
            return WindowsFirewall()
        except ImportError as e:
            logger.error(f"Failed to import Windows firewall module: {e}")
            raise ImportError("Windows firewall module not available")
            
    elif system == "Linux":
        try:
            from firewall_linux import LinuxFirewall
            return LinuxFirewall()
        except ImportError as e:
            logger.error(f"Failed to import Linux firewall module: {e}")
            raise ImportError("Linux firewall module not available")
            
    else:
        raise NotImplementedError(f"Firewall not implemented for platform: {system}")