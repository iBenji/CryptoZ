import json
import os
import logging
from typing import Dict, Any, Optional
from threading import Lock

class AppSettings:
    """Enhanced application settings management with thread safety"""
    
    # Enhanced default settings with more options
    DEFAULT_SETTINGS = {
        "security": {
            "default_algorithm": "fernet",
            "key_derivation_iterations": 310000,  # OWASP recommended
            "password_length": 16,
            "min_password_length": 8,
            "max_password_length": 128,
            "secure_memory_clearing": True,
            "session_timeout_minutes": 30
        },
        "ui": {
            "show_password_strength": True,
            "confirm_before_operations": True,
            "auto_clear_passwords": True,
            "theme": "dark",
            "language": "en"
        },
        "files": {
            "default_output_extension": ".encrypted",
            "auto_backup_before_encryption": True,
            "max_file_size_mb": 100,
            "allowed_extensions": [".txt", ".pdf", ".doc", ".docx", ".xls", ".xlsx"]
        },
        "performance": {
            "enable_key_caching": True,
            "cache_size": 100,
            "parallel_operations": False
        },
        "logging": {
            "level": "INFO",
            "max_file_size_mb": 10,
            "backup_count": 5
        }
    }
    
    def __init__(self, config_file: str = "cryptoz_config.json"):
        self.config_file = config_file
        self._lock = Lock()
        self.logger = logging.getLogger(__name__)
        self.settings = self._load_settings()
    
    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from file with enhanced error handling"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    loaded_settings = json.load(f)
                    
                    # Validate loaded settings
                    if self._validate_settings(loaded_settings):
                        # Deep merge with defaults
                        merged_settings = self._deep_merge(self.DEFAULT_SETTINGS, loaded_settings)
                        self.logger.info("Settings loaded successfully from %s", self.config_file)
                        return merged_settings
                    else:
                        self.logger.warning("Invalid settings detected in %s, using defaults", self.config_file)
                        
        except json.JSONDecodeError as e:
            self.logger.error("Settings file %s corrupted: %s", self.config_file, e)
        except Exception as e:
            self.logger.error("Settings loading error for %s: %s", self.config_file, e)
        
        # Return defaults on any error
        self.logger.info("Using default settings")
        return self.DEFAULT_SETTINGS.copy()
    
    def save_settings(self) -> bool:
        """Save settings to file with atomic write"""
        try:
            with self._lock:
                # Create backup if file exists
                if os.path.exists(self.config_file):
                    backup_file = self.config_file + '.bak'
                    try:
                        import shutil
                        shutil.copy2(self.config_file, backup_file)
                    except Exception as e:
                        self.logger.warning("Could not create backup for %s: %s", self.config_file, e)
                
                # Atomic write to temporary file first
                temp_file = self.config_file + '.tmp'
                with open(temp_file, 'w', encoding='utf-8') as f:
                    json.dump(self.settings, f, indent=4, ensure_ascii=False, sort_keys=True)
                
                # Replace original file
                import shutil
                shutil.move(temp_file, self.config_file)
                
                self.logger.info("Settings saved successfully to %s", self.config_file)
                return True
                
        except Exception as e:
            self.logger.error("Settings saving error for %s: %s", self.config_file, e)
            # Clean up temporary file
            try:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
            except:
                pass
            return False
    
    def get(self, key: str, default=None) -> Any:
        """Get setting value by key with enhanced error handling"""
        if not key or not isinstance(key, str):
            return default
        
        keys = key.split('.')
        value = self.settings
        
        try:
            for k in keys:
                if not isinstance(value, dict) or k not in value:
                    return default
                value = value[k]
            return value
        except (KeyError, TypeError, AttributeError):
            return default
    
    def set(self, key: str, value: Any, auto_save: bool = True) -> bool:
        """Set setting value with validation"""
        if not key or not isinstance(key, str):
            return False
        
        # Validate the value based on key
        if not self._validate_setting(key, value):
            self.logger.warning(f"Invalid value for setting {key}: {value}")
            return False
        
        keys = key.split('.')
        settings_ref = self.settings
        
        try:
            # Navigate to the parent level
            for k in keys[:-1]:
                if k not in settings_ref or not isinstance(settings_ref[k], dict):
                    settings_ref[k] = {}
                settings_ref = settings_ref[k]
            
            # Set the value
            settings_ref[keys[-1]] = value
            
            # Auto-save if requested
            if auto_save:
                return self.save_settings()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error setting {key}: {e}")
            return False
    
    def reset_to_defaults(self) -> bool:
        """Reset all settings to defaults"""
        try:
            with self._lock:
                self.settings = self.DEFAULT_SETTINGS.copy()
                return self.save_settings()
        except Exception as e:
            self.logger.error(f"Error resetting settings: {e}")
            return False
    
    def export_settings(self, export_path: str) -> bool:
        """Export settings to specified path"""
        try:
            with open(export_path, 'w', encoding='utf-8') as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False, sort_keys=True)
            self.logger.info(f"Settings exported to {export_path}")
            return True
        except Exception as e:
            self.logger.error(f"Settings export error: {e}")
            return False
    
    def import_settings(self, import_path: str) -> bool:
        """Import settings from specified path"""
        try:
            if not os.path.exists(import_path):
                self.logger.error(f"Import file not found: {import_path}")
                return False
            
            with open(import_path, 'r', encoding='utf-8') as f:
                imported_settings = json.load(f)
            
            if self._validate_settings(imported_settings):
                self.settings = self._deep_merge(self.DEFAULT_SETTINGS, imported_settings)
                return self.save_settings()
            else:
                self.logger.error("Imported settings validation failed")
                return False
                
        except Exception as e:
            self.logger.error(f"Settings import error: {e}")
            return False
    
    def _validate_settings(self, settings: Dict) -> bool:
        """Validate settings structure and values"""
        if not isinstance(settings, dict):
            return False
        
        # Check required sections exist
        required_sections = ['security', 'ui', 'files']
        for section in required_sections:
            if section not in settings or not isinstance(settings[section], dict):
                return False
        
        # Validate specific values
        try:
            iterations = settings['security'].get('key_derivation_iterations')
            if iterations and (not isinstance(iterations, int) or iterations < 1000):
                return False
            
            password_len = settings['security'].get('password_length')
            if password_len and (not isinstance(password_len, int) or password_len < 8):
                return False
                
        except (KeyError, TypeError):
            return False
        
        return True
    
    def _validate_setting(self, key: str, value: Any) -> bool:
        """Validate individual setting value"""
        validation_rules = {
            'security.key_derivation_iterations': lambda v: isinstance(v, int) and 1000 <= v <= 1000000,
            'security.password_length': lambda v: isinstance(v, int) and 8 <= v <= 128,
            'security.min_password_length': lambda v: isinstance(v, int) and 4 <= v <= 128,
            'files.max_file_size_mb': lambda v: isinstance(v, int) and v > 0,
            'ui.theme': lambda v: v in ['dark', 'light', 'system'],
            'ui.language': lambda v: v in ['en', 'ru', 'es', 'fr', 'de']
        }
        
        validator = validation_rules.get(key)
        if validator:
            return validator(value)
        
        return True  # No specific validation rule
    
    def _deep_merge(self, base: Dict, update: Dict) -> Dict:
        """Enhanced recursive dictionary merge"""
        result = base.copy()
        
        for key, value in update.items():
            if isinstance(value, dict) and key in result and isinstance(result[key], dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def get_all_settings(self) -> Dict[str, Any]:
        """Get all settings as a copy"""
        import copy
        return copy.deepcopy(self.settings)
    
    def __enter__(self):
        """Context manager support"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Auto-save on context exit"""
        if exc_type is None:  # Only save if no exception occurred
            self.save_settings()