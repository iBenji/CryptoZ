import re
import string
#import random
import secrets
#import hashlib
from typing import Dict, List

class SecurityUtils:
    """Security utilities and password checking with enhanced security"""
    
    # Common passwords list for validation
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "123456789", "qwerty",
        "abc123", "password1", "12345", "1234567", "111111",
        "admin", "welcome", "monkey", "letmein", "master"
    }
    
    # Sequential patterns for detection
    SEQUENTIAL_PATTERNS = [
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz", 
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "9876543210"
    ]

    @staticmethod
    def password_strength(password: str) -> Dict:
        """Comprehensive password strength assessment with enhanced checks"""
        if not password or not isinstance(password, str):
            return {
                "score": 0, 
                "level": "Invalid", 
                "feedback": ["Password cannot be empty"],
                "length": 0
            }
        
        score = 0
        feedback: List[str] = []
        
        # Password length with enhanced scoring
        length = len(password)
        if length >= 16:
            score += 3
        elif length >= 12:
            score += 2
        elif length >= 8:
            score += 1
            feedback.append("Use at least 12 characters for better security")
        else:
            feedback.append("Password too short (minimum 8 characters)")
        
        # Enhanced character diversity checks
        checks = {
            "uppercase": (r"[A-Z]", "Add uppercase letters"),
            "lowercase": (r"[a-z]", "Add lowercase letters"), 
            "digits": (r"\d", "Add digits"),
            "special": (r"[!@#$%^&*(),.?\":{}|<>\[\]_\-+=~`]", "Add special characters")
        }
        
        for check_type, (pattern, message) in checks.items():
            if re.search(pattern, password):
                score += 1
            else:
                feedback.append(message)
        
        # Advanced pattern detection
        if SecurityUtils._has_sequential_chars(password):
            score = max(0, score - 2)  # More severe penalty for sequences
            feedback.append("Avoid sequential keyboard patterns")
        
        if SecurityUtils._has_repeated_chars(password):
            score = max(0, score - 1)
            feedback.append("Avoid repeated characters")
        
        if SecurityUtils._is_common_password(password):
            score = 0
            feedback = ["This password is too common and easily guessable"]
        
        # Entropy-based scoring
        entropy_score = SecurityUtils._calculate_password_entropy(password)
        if entropy_score >= 4.0:
            score += 1
        elif entropy_score < 2.0:
            score = max(0, score - 1)
            feedback.append("Password lacks complexity")
        
        # Normalize score
        score = max(0, min(score, 6))
        
        strength_levels = {
            0: "Very Weak",
            1: "Weak",
            2: "Weak", 
            3: "Fair",
            4: "Good",
            5: "Strong",
            6: "Very Strong"
        }
        
        return {
            'score': score,
            'level': strength_levels.get(score, "Unknown"),
            'feedback': feedback[:3],  # Limit feedback items
            'length': length,
            'entropy': round(entropy_score, 2)
        }
    
    @staticmethod
    def _has_sequential_chars(password: str) -> bool:
        """Check for sequential characters with enhanced detection"""
        password_lower = password.lower()
        
        for seq in SecurityUtils.SEQUENTIAL_PATTERNS:
            # Check forward sequences
            for i in range(len(seq) - 3):
                if seq[i:i+4] in password_lower:
                    return True
            
            # Check reverse sequences
            seq_reverse = seq[::-1]
            for i in range(len(seq_reverse) - 3):
                if seq_reverse[i:i+4] in password_lower:
                    return True
        
        return False
    
    @staticmethod
    def _has_repeated_chars(password: str) -> bool:
        """Check for repeated characters"""
        return bool(re.search(r'(.)\1{2,}', password))
    
    @staticmethod
    def _is_common_password(password: str) -> bool:
        """Check for common passwords with case insensitivity"""
        return password.lower() in SecurityUtils.COMMON_PASSWORDS
    
    @staticmethod
    def _calculate_password_entropy(password: str) -> float:
        """Calculate password entropy for complexity assessment"""
        if not password:
            return 0.0
        
        char_pool = 0
        if re.search(r'[a-z]', password):
            char_pool += 26
        if re.search(r'[A-Z]', password):
            char_pool += 26
        if re.search(r'\d', password):
            char_pool += 10
        if re.search(r'[^a-zA-Z0-9]', password):
            char_pool += 33  # Common special characters
        
        if char_pool == 0:
            return 0.0
        
        entropy = len(password) * (char_pool ** 0.5) / 10
        return entropy
    
    @staticmethod
    def generate_password(length: int = 16) -> str:
        """Generate cryptographically secure random password"""
        if length < 8:
            length = 8
        elif length > 128:
            length = 128
        
        # Character sets with enhanced special characters
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"
        
        # Ensure minimum requirements using secrets module
        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]
        
        # Fill the rest with cryptographically secure random choices
        all_chars = lowercase + uppercase + digits + special
        password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))
        
        # Cryptographically secure shuffle
        secrets.SystemRandom().shuffle(password_chars)
        
        return ''.join(password_chars)
    
    @staticmethod
    def secure_clear(data: str) -> None:
        """Securely clear sensitive data from memory"""
        if not data or not isinstance(data, str):
            return
        
        # Convert to bytearray for in-place modification
        import ctypes
        data_bytes = bytearray(data.encode('utf-8'))
        
        # Overwrite multiple times
        for pattern in [b'\x00', b'\xFF', b'\xAA', b'\x55']:
            for i in range(len(data_bytes)):
                data_bytes[i] = pattern[0]
        
        # Prevent compiler optimization
        ctypes.memset(ctypes.addressof(ctypes.c_char.from_buffer(data_bytes)), 0, len(data_bytes))
        
        # Explicit deletion
        del data_bytes
    
    @staticmethod
    def generate_secure_salt(length: int = 16) -> bytes:
        """Generate cryptographically secure salt"""
        return secrets.token_bytes(length)
    
    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """Constant time comparison to prevent timing attacks"""
        if len(val1) != len(val2):
            return False
        
        result = 0
        for x, y in zip(val1, val2):
            result |= ord(x) ^ ord(y)
        return result == 0