import json
import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

class ConfigManager:
    """Manages configuration and app data for the Personal Firewall application"""
    
    def __init__(self):
        """Initialize the configuration manager"""
        # Define platform-specific config paths
        if os.name == "nt":  # Windows
            self.config_dir = Path(os.environ.get("APPDATA")) / "PersonalFirewall"
        else:  # Linux/Unix
            self.config_dir = Path.home() / ".config" / "personal-firewall"
            
        self.config_file = self.config_dir / "config.json"
        self.blocked_apps_file = self.config_dir / "blocked_apps.json"
        
        # Create directories if they don't exist
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        # Load or create default configurations
        self.config = self._load_or_create_config()
        self.blocked_apps = self._load_or_create_blocked_apps()
    
    def _load_or_create_config(self):
        """Load config from file or create default config"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse config file: {self.config_file}")
                return self._get_default_config()
        else:
            default_config = self._get_default_config()
            self.save_config(default_config)
            return default_config
    
    def _get_default_config(self):
        """Return the default configuration"""
        return {
            "startup_enabled": False,
            "show_notifications": True,
            "theme": "system",
            "refresh_interval": 60,  # seconds
            "auto_block_new_apps": False
        }
    
    def save_config(self, config=None):
        """Save configuration to file"""
        if config is not None:
            self.config = config
            
        try:
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            return False
    
    def _load_or_create_blocked_apps(self):
        """Load blocked apps from file or create empty list"""
        if self.blocked_apps_file.exists():
            try:
                with open(self.blocked_apps_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse blocked apps file: {self.blocked_apps_file}")
                return []
        else:
            return []
    
    def save_blocked_apps(self, blocked_apps=None):
        """Save blocked apps to file"""
        if blocked_apps is not None:
            self.blocked_apps = blocked_apps
            
        try:
            with open(self.blocked_apps_file, 'w') as f:
                json.dump(self.blocked_apps, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to save blocked apps: {e}")
            return False
    
    def add_blocked_app(self, app_path):
        """Add an application to the blocked list"""
        if app_path not in self.blocked_apps:
            self.blocked_apps.append(app_path)
            return self.save_blocked_apps()
        return True
    
    def remove_blocked_app(self, app_path):
        """Remove an application from the blocked list"""
        if app_path in self.blocked_apps:
            self.blocked_apps.remove(app_path)
            return self.save_blocked_apps()
        return True
    
    def get_config_value(self, key, default=None):
        """Get a configuration value"""
        return self.config.get(key, default)
    
    def set_config_value(self, key, value):
        """Set a configuration value and save the config"""
        self.config[key] = value
        return self.save_config()