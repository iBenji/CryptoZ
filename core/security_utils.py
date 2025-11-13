# CryptoZ/core/security_utils.py

"""
Security utilities for password strength evaluation, secure memory wiping,
random generation, and side-channel attack protection.
"""

import re
import string
import ctypes
import secrets
from typing import Dict, List


class SecurityUtils:
    """
    Security utilities and password checking with enhanced security.
    Provides tools for password analysis, secure generation, and memory safety.
    """

    # Common passwords list for validation
    COMMON_PASSWORDS = {
        "password", "123456", "12345678", "123456789", "qwerty",
        "abc123", "password1", "12345", "1234567", "111111",
        "admin", "welcome", "monkey", "letmein", "master"
    }

    # Sequential patterns for detection (keyboard walks)
    SEQUENTIAL_PATTERNS = [
        "0123456789",
        "abcdefghijklmnopqrstuvwxyz",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
        "9876543210"
    ]

    @staticmethod
    def password_strength(password: str) -> Dict[str, any]:
        """
        Comprehensive password strength assessment with enhanced checks.
        :param password: password string to evaluate
        :return: dictionary with score, level, feedback, and entropy
        """
        if not password or not isinstance(password, str):
            return {
                "score": 0,
                "level": "Invalid",
                "feedback": ["Password cannot be empty"],
                "length": 0,
                "entropy": 0.0
            }

        score = 0
        feedback: List[str] = []
        length = len(password)

        # Length scoring
        if length >= 16:
            score += 3
        elif length >= 12:
            score += 2
        elif length >= 8:
            score += 1
            feedback.append("Use at least 12 characters for better security")
        else:
            feedback.append("Password too short (minimum 8 characters)")

        # Character diversity
        checks = {
            "uppercase": (r"[A-Z]", "Add uppercase letters"),
            "lowercase": (r"[a-z]", "Add lowercase letters"),
            "digits": (r"\d", "Add digits"),
            "special": (r"[!@#$%^&*(),.?\":{}|<>\[\]_\-+=~`]", "Add special characters")
        }

        for pattern, (regex, message) in checks.items():
            if re.search(regex, password):
                score += 1
            else:
                feedback.append(message)

        # Advanced pattern detection
        if SecurityUtils._has_sequential_chars(password):
            score = max(0, score - 2)
            feedback.append("Avoid sequential keyboard patterns")

        if SecurityUtils._has_repeated_chars(password):
            score = max(0, score - 1)
            feedback.append("Avoid repeated characters")

        if SecurityUtils._is_common_password(password):
            score = 0
            feedback = ["This password is too common and easily guessable"]

        # Entropy scoring
        entropy_score = SecurityUtils._calculate_password_entropy(password)
        if entropy_score >= 4.0:
            score += 1
        elif entropy_score < 2.0:
            score = max(0, score - 1)
            feedback.append("Password lacks complexity")

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
            "score": score,
            "level": strength_levels.get(score, "Unknown"),
            "feedback": feedback[:3],
            "length": length,
            "entropy": round(entropy_score, 2)
        }

    @staticmethod
    def _has_sequential_chars(password: str) -> bool:
        """
        Check for sequences of 4 or more characters from common patterns.
        :param password: password to check
        :return: True if sequential pattern found
        """
        password_lower = password.lower()
        for seq in SecurityUtils.SEQUENTIAL_PATTERNS:
            for i in range(len(seq) - 3):
                if seq[i:i+4] in password_lower:
                    return True
                if seq[::-1][i:i+4] in password_lower:
                    return True
        return False

    @staticmethod
    def _has_repeated_chars(password: str) -> bool:
        """
        Check for 3 or more repeated characters in a row.
        :param password: password to check
        :return: True if repeated characters found
        """
        return bool(re.search(r'(.)\1{2,}', password))

    @staticmethod
    def _is_common_password(password: str) -> bool:
        """
        Check if password is in the list of common passwords.
        :param password: password to check
        :return: True if common
        """
        return password.lower() in SecurityUtils.COMMON_PASSWORDS

    @staticmethod
    def _calculate_password_entropy(password: str) -> float:
        """
        Estimate password entropy based on character set and length.
        :param password: password to evaluate
        :return: entropy score
        """
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
            char_pool += 33

        if char_pool == 0:
            return 0.0

        # Approximate entropy
        entropy = len(password) * (char_pool ** 0.5) / 10
        return entropy

    @staticmethod
    def generate_password(length: int = 16) -> str:
        """
        Generate cryptographically secure random password.
        :param length: desired password length (8–128)
        :return: generated password
        """
        if length < 8:
            length = 8
        elif length > 128:
            length = 128

        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

        all_chars = lowercase + uppercase + digits + special

        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special)
        ]

        password_chars.extend(secrets.choice(all_chars) for _ in range(length - 4))
        secrets.SystemRandom().shuffle(password_chars)

        return ''.join(password_chars)

    @staticmethod
    def generate_secure_salt(length: int = 16) -> bytes:
        """
        Generate cryptographically secure salt.
        :param length: number of bytes
        :return: random bytes
        """
        return secrets.token_bytes(length)

    @staticmethod
    def constant_time_compare(val1: str, val2: str) -> bool:
        """
        Compare strings in constant time to prevent timing attacks.
        :param val1: first string
        :param val2: second string
        :return: True if equal
        """
        if len(val1) != len(val2):
            return False
        result = 0
        for x, y in zip(val1, val2):
            result |= ord(x) ^ ord(y)
        return result == 0

    @staticmethod
    def secure_wipe(data: bytearray) -> None:
        """
        Securely overwrite a bytearray in memory.
        :param data: mutable bytearray to wipe
        """
        if not isinstance(data, bytearray):
            return

        # Overwrite with zeros
        for i in range(len(data)):
            data[i] = 0

        # Use ctypes to bypass potential optimizations
        try:
            buffer = (ctypes.c_char * len(data)).from_buffer(data)
            ctypes.memset(buffer, 0, len(data))
        except Exception:
            pass  # Ignore if direct memory access fails

        # Force garbage collection
        import gc
        gc.collect()

    @staticmethod
    def secure_wipe_string(s: str) -> None:
        """
        Securely wipe a string by copying to mutable buffer and erasing.
        :param s: string to wipe (copy will be wiped)
        """
        if not s:
            return
        data = bytearray(s.encode('utf-8'))
        SecurityUtils.secure_wipe(data)

    @staticmethod
    def secure_wipe_bytes(b: bytes) -> None:
        """
        Securely wipe a bytes object.
        :param b: bytes to wipe (copy will be wiped)
        """
        if not b:
            return
        data = bytearray(b)
        SecurityUtils.secure_wipe(data)
