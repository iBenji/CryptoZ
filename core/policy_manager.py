import json
import os
import logging
import threading
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path

class PolicyManager:
    """Advanced policy management system for automated encryption operations"""
    
    def __init__(self, crypto_engine, settings):
        self.crypto_engine = crypto_engine
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        self._lock = threading.Lock()
        self.policies_file = "encryption_policies.json"
        self.policies = self._load_policies()
    
    def _load_policies(self) -> Dict[str, Any]:
        """Load policies from file"""
        try:
            if os.path.exists(self.policies_file):
                with open(self.policies_file, 'r', encoding='utf-8') as f:
                    policies = json.load(f)
                    if self._validate_policies(policies):
                        return policies
                    else:
                        self.logger.warning("Invalid policies detected, using defaults")
        except Exception as e:
            self.logger.error(f"Policy loading error: {e}")
        
        return {
            "version": "1.0",
            "policies": {},
            "schedules": {}
        }
    
    def save_policies(self) -> bool:
        """Save policies to file"""
        try:
            with self._lock:
                with open(self.policies_file, 'w', encoding='utf-8') as f:
                    json.dump(self.policies, f, indent=4, ensure_ascii=False)
                return True
        except Exception as e:
            self.logger.error(f"Policy saving error: {e}")
            return False
    
    def create_policy(self, name: str, rules: Dict[str, Any]) -> bool:
        """Create new encryption policy"""
        try:
            with self._lock:
                if name in self.policies["policies"]:
                    self.logger.warning(f"Policy {name} already exists")
                    return False
                
                # Validate policy rules
                if not self._validate_policy_rules(rules):
                    return False
                
                self.policies["policies"][name] = {
                    "name": name,
                    "rules": rules,
                    "created": datetime.now().isoformat(),
                    "enabled": True
                }
                
                return self.save_policies()
                
        except Exception as e:
            self.logger.error(f"Policy creation error: {e}")
            return False
    
    def update_policy(self, name: str, rules: Dict[str, Any]) -> bool:
        """Update existing policy"""
        try:
            with self._lock:
                if name not in self.policies["policies"]:
                    self.logger.error(f"Policy {name} not found")
                    return False
                
                if not self._validate_policy_rules(rules):
                    return False
                
                self.policies["policies"][name]["rules"] = rules
                self.policies["policies"][name]["modified"] = datetime.now().isoformat()
                
                return self.save_policies()
                
        except Exception as e:
            self.logger.error(f"Policy update error: {e}")
            return False
    
    def delete_policy(self, name: str) -> bool:
        """Delete policy"""
        try:
            with self._lock:
                if name in self.policies["policies"]:
                    del self.policies["policies"][name]
                    
                    # Remove from schedules
                    schedules_to_remove = []
                    for schedule_name, schedule in self.policies["schedules"].items():
                        if schedule.get("policy") == name:
                            schedules_to_remove.append(schedule_name)
                    
                    for schedule_name in schedules_to_remove:
                        del self.policies["schedules"][schedule_name]
                    
                    return self.save_policies()
                return False
                
        except Exception as e:
            self.logger.error(f"Policy deletion error: {e}")
            return False
    
    def _validate_policy_rules(self, rules: Dict[str, Any]) -> bool:
        """Validate policy rules structure"""
        required_fields = ["target", "algorithm", "password"]
        
        for field in required_fields:
            if field not in rules:
                self.logger.error(f"Missing required field: {field}")
                return False
        
        # Validate target
        target = rules["target"]
        if not isinstance(target, (str, list)):
            self.logger.error("Target must be string or list")
            return False
        
        # Validate algorithm
        algorithm = rules["algorithm"]
        if algorithm not in self.crypto_engine.get_available_algorithms():
            self.logger.error(f"Unsupported algorithm: {algorithm}")
            return False
        
        return True
    
    def _validate_policies(self, policies: Dict[str, Any]) -> bool:
        """Validate entire policies structure"""
        if not isinstance(policies, dict):
            return False
        
        required_sections = ["version", "policies", "schedules"]
        for section in required_sections:
            if section not in policies:
                return False
        
        return True
    
    def apply_policy(self, policy_name: str) -> Dict[str, Any]:
        """Apply policy to its targets"""
        try:
            with self._lock:
                if policy_name not in self.policies["policies"]:
                    return {"success": False, "error": f"Policy {policy_name} not found"}
                
                policy = self.policies["policies"][policy_name]
                if not policy.get("enabled", True):
                    return {"success": False, "error": f"Policy {policy_name} is disabled"}
                
                rules = policy["rules"]
                target = rules["target"]
                algorithm = rules["algorithm"]
                password = rules["password"]
                
                # Handle different target types
                if isinstance(target, str):
                    # Single file or folder
                    if os.path.isfile(target):
                        return self._apply_to_file(target, algorithm, password)
                    elif os.path.isdir(target):
                        return self._apply_to_folder(target, algorithm, password, rules.get("patterns"))
                    else:
                        return {"success": False, "error": f"Target not found: {target}"}
                
                elif isinstance(target, list):
                    # Multiple targets
                    results = {}
                    for t in target:
                        if os.path.isfile(t):
                            results[t] = self._apply_to_file(t, algorithm, password)
                        elif os.path.isdir(t):
                            results[t] = self._apply_to_folder(t, algorithm, password, rules.get("patterns"))
                    
                    return {
                        "success": all(r["success"] for r in results.values()),
                        "results": results
                    }
                
                return {"success": False, "error": "Invalid target type"}
                
        except Exception as e:
            self.logger.error(f"Policy application error: {e}")
            return {"success": False, "error": str(e)}
    
    def _apply_to_file(self, file_path: str, algorithm: str, password: str) -> Dict[str, Any]:
        """Apply policy to single file"""
        try:
            output_path = file_path + ".encrypted"
            success = self.crypto_engine.encrypt_file(file_path, output_path, password, algorithm)
            
            return {
                "success": success,
                "input": file_path,
                "output": output_path if success else None
            }
            
        except Exception as e:
            self.logger.error(f"File policy application error: {e}")
            return {"success": False, "error": str(e)}
    
    def _apply_to_folder(self, folder_path: str, algorithm: str, password: str, patterns: List[str] = None) -> Dict[str, Any]:
        """Apply policy to folder"""
        try:
            output_folder = folder_path + "_encrypted"
            result = self.crypto_engine.encrypt_folder(folder_path, output_folder, password, algorithm, patterns)
            
            return {
                "success": result["success"],
                "processed": result["processed"],
                "total": result["total"],
                "errors": result["errors"],
                "output": output_folder
            }
            
        except Exception as e:
            self.logger.error(f"Folder policy application error: {e}")
            return {"success": False, "error": str(e)}
    
    def create_schedule(self, name: str, policy_name: str, schedule_config: Dict[str, Any]) -> bool:
        """Create scheduled policy execution"""
        try:
            with self._lock:
                if policy_name not in self.policies["policies"]:
                    self.logger.error(f"Policy {policy_name} not found")
                    return False
                
                # Validate schedule config
                if not self._validate_schedule_config(schedule_config):
                    return False
                
                self.policies["schedules"][name] = {
                    "name": name,
                    "policy": policy_name,
                    "schedule": schedule_config,
                    "enabled": True,
                    "last_run": None,
                    "next_run": self._calculate_next_run(schedule_config),
                    "created": datetime.now().isoformat()
                }
                
                return self.save_policies()
                
        except Exception as e:
            self.logger.error(f"Schedule creation error: {e}")
            return False
    
    def _validate_schedule_config(self, config: Dict[str, Any]) -> bool:
        """Validate schedule configuration"""
        schedule_type = config.get("type")
        
        if schedule_type == "interval":
            interval = config.get("interval_minutes")
            if not isinstance(interval, (int, float)) or interval <= 0:
                self.logger.error("Invalid interval")
                return False
        
        elif schedule_type == "daily":
            time_str = config.get("time")
            if not self._validate_time_string(time_str):
                self.logger.error("Invalid time format")
                return False
        
        elif schedule_type == "weekly":
            time_str = config.get("time")
            days = config.get("days")
            if not self._validate_time_string(time_str) or not isinstance(days, list):
                self.logger.error("Invalid weekly schedule")
                return False
        
        else:
            self.logger.error(f"Unsupported schedule type: {schedule_type}")
            return False
        
        return True
    
    def _validate_time_string(self, time_str: str) -> bool:
        """Validate time string (HH:MM)"""
        try:
            datetime.strptime(time_str, "%H:%M")
            return True
        except ValueError:
            return False
    
    def _calculate_next_run(self, schedule_config: Dict[str, Any]) -> str:
        """Calculate next run time for schedule"""
        now = datetime.now()
        schedule_type = schedule_config["type"]
        
        if schedule_type == "interval":
            interval = schedule_config["interval_minutes"]
            next_run = now + timedelta(minutes=interval)
        
        elif schedule_type == "daily":
            time_str = schedule_config["time"]
            next_run = datetime.strptime(time_str, "%H:%M").replace(
                year=now.year, month=now.month, day=now.day
            )
            if next_run <= now:
                next_run += timedelta(days=1)
        
        elif schedule_type == "weekly":
            time_str = schedule_config["time"]
            days = schedule_config["days"]
            today_weekday = now.weekday()
            
            # Find next scheduled day
            next_day = None
            for day_offset in range(8):  # Check next 7 days + today
                check_day = (today_weekday + day_offset) % 7
                if check_day in days:
                    next_day = day_offset
                    break
            
            if next_day is not None:
                next_run = datetime.strptime(time_str, "%H:%M").replace(
                    year=now.year, month=now.month, day=now.day
                ) + timedelta(days=next_day)
                
                if next_run <= now and next_day == 0:
                    next_run += timedelta(days=7)
            else:
                next_run = now + timedelta(days=7)
        
        return next_run.isoformat()
    
    def get_policies(self) -> Dict[str, Any]:
        """Get all policies"""
        return self.policies["policies"]
    
    def get_schedules(self) -> Dict[str, Any]:
        """Get all schedules"""
        return self.policies["schedules"]
    
    def toggle_policy(self, policy_name: str, enabled: bool) -> bool:
        """Enable/disable policy"""
        try:
            with self._lock:
                if policy_name in self.policies["policies"]:
                    self.policies["policies"][policy_name]["enabled"] = enabled
                    return self.save_policies()
                return False
        except Exception as e:
            self.logger.error(f"Policy toggle error: {e}")
            return False
    
    def toggle_schedule(self, schedule_name: str, enabled: bool) -> bool:
        """Enable/disable schedule"""
        try:
            with self._lock:
                if schedule_name in self.policies["schedules"]:
                    self.policies["schedules"][schedule_name]["enabled"] = enabled
                    return self.save_policies()
                return False
        except Exception as e:
            self.logger.error(f"Schedule toggle error: {e}")
            return False