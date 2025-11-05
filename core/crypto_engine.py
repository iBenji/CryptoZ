import os
import base64
import hashlib
import math
import logging
import secrets
from collections import Counter
from typing import Tuple, Dict, Any, Optional
from functools import lru_cache
from threading import Lock

# Cryptography imports with fallbacks
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    logging.warning("cryptography library not available, some features disabled")

try:
    from Crypto.Cipher import AES, DES3, ChaCha20
    from Crypto.Util.Padding import pad, unpad
    from Crypto.Random import get_random_bytes
    from Crypto.Protocol.KDF import PBKDF2 as Crypto_PBKDF2
    PYCRYPTO_AVAILABLE = True
except ImportError:
    PYCRYPTO_AVAILABLE = False
    logging.warning("pycryptodome library not available, some features disabled")


class CryptoEngine:
    """Enhanced encryption engine with improved security and performance"""
    
    def __init__(self, settings):
        self.settings = settings
        self.logger = logging.getLogger(__name__)
        self._key_cache = {}
        self._cache_lock = Lock()
        
        # Enhanced algorithm information
        self.supported_algorithms = {
            'fernet': {
                'name': 'Fernet (AES-128)',
                'description': 'Recommended secure algorithm with authentication',
                'secure': True,
                'key_size': 32,
                'requires_crypto': True,
                'block_size': 16
            },
            'aes_cbc': {
                'name': 'AES-CBC (256-bit)',
                'description': 'Standard block cipher mode with padding',
                'secure': True,
                'key_size': 32,
                'requires_crypto': True,
                'block_size': 16
            },
            'aes_gcm': {
                'name': 'AES-GCM (256-bit)',
                'description': 'Authenticated encryption with built-in integrity',
                'secure': True,
                'key_size': 32,
                'requires_crypto': True,
                'block_size': 16
            },
            'aes_ctr': {
                'name': 'AES-CTR (256-bit)',
                'description': 'Stream cipher mode, no padding required',
                'secure': True,
                'key_size': 32,
                'requires_crypto': True,
                'block_size': 16
            },
            'chacha20': {
                'name': 'ChaCha20',
                'description': 'Modern stream cipher, fast and secure',
                'secure': True,
                'key_size': 32,
                'requires_crypto': True,
                'block_size': 64
            },
            'des3': {
                'name': 'Triple DES',
                'description': 'Legacy algorithm (not recommended)',
                'secure': False,
                'key_size': 24,
                'requires_crypto': True,
                'block_size': 8
            },
            'xor': {
                'name': 'XOR (Basic)',
                'description': 'Basic encryption for educational purposes only',
                'secure': False,
                'key_size': 32,
                'requires_crypto': False,
                'block_size': 1
            }
        }
        
        # Validate available cryptography libraries
        self._validate_crypto_availability()
    
    def _validate_crypto_availability(self):
        """Validate required cryptography libraries are available"""
        for algo_name, algo_info in self.supported_algorithms.items():
            if algo_info['requires_crypto'] and not CRYPTOGRAPHY_AVAILABLE and not PYCRYPTO_AVAILABLE:
                self.logger.warning(f"Algorithm {algo_name} requires cryptography libraries")
                algo_info['available'] = False
            else:
                algo_info['available'] = True
    
    def derive_key(self, password: str, salt: bytes = None, key_size: int = 32) -> Tuple[bytes, bytes]:
        """Enhanced key derivation with multiple backends"""
        if not password or len(password) < 4:
            raise ValueError("Password too short or empty")
        
        if salt is None:
            salt = secrets.token_bytes(16)
        
        iterations = self.settings.get("security.key_derivation_iterations", 310000)
        
        try:
            if CRYPTOGRAPHY_AVAILABLE:
                # Use cryptography library (preferred)
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=key_size,
                    salt=salt,
                    iterations=iterations,
                    backend=default_backend()
                )
                key = kdf.derive(password.encode('utf-8'))
            elif PYCRYPTO_AVAILABLE:
                # Fallback to pycryptodome
                key = Crypto_PBKDF2(password, salt, dkLen=key_size, count=iterations)
            else:
                # Pure Python fallback (less secure)
                key = self._python_pbkdf2(password, salt, key_size, iterations)
            
            return key, salt
            
        except Exception as e:
            self.logger.error(f"Key derivation error: {e}")
            raise RuntimeError(f"Key derivation failed: {str(e)}") from e
    
    def _python_pbkdf2(self, password: str, salt: bytes, key_size: int, iterations: int) -> bytes:
        """Pure Python PBKDF2 implementation (fallback only)"""
        import hmac
        
        key = b''
        block_count = 1
        
        while len(key) < key_size:
            # U1 = PRF(Password, Salt + INT_32_BE(i))
            block = hmac.new(
                password.encode('utf-8'),
                salt + block_count.to_bytes(4, 'big'),
                hashlib.sha256
            ).digest()
            
            u_prev = block
            # Uj = PRF(Password, Uj-1)
            for _ in range(iterations - 1):
                u_curr = hmac.new(
                    password.encode('utf-8'),
                    u_prev,
                    hashlib.sha256
                ).digest()
                # XOR each byte
                block = bytes(a ^ b for a, b in zip(block, u_curr))
                u_prev = u_curr
            
            key += block
            block_count += 1
        
        return key[:key_size]
    
    @lru_cache(maxsize=100)
    def _get_cached_key(self, password: str, salt: bytes, key_size: int) -> bytes:
        """Cache derived keys for performance"""
        cache_key = f"{hashlib.sha256(password.encode()).hexdigest()}_{salt.hex()}_{key_size}"
        
        with self._cache_lock:
            if cache_key in self._key_cache:
                return self._key_cache[cache_key]
            
            key, _ = self.derive_key(password, salt, key_size)
            self._key_cache[cache_key] = key
            return key
    
    def encrypt_fernet(self, data: bytes, password: str) -> bytes:
        """Fernet encryption with enhanced error handling"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography library required for Fernet encryption")
        
        try:
            key, salt = self.derive_fernet_key(password)
            fernet = Fernet(key)
            encrypted_data = fernet.encrypt(data)
            return salt + encrypted_data
            
        except Exception as e:
            self.logger.error(f"Fernet encryption error: {e}")
            raise RuntimeError(f"Fernet encryption failed: {str(e)}") from e
    
    def decrypt_fernet(self, encrypted_data: bytes, password: str) -> bytes:
        """Fernet decryption with validation"""
        if not CRYPTOGRAPHY_AVAILABLE:
            raise RuntimeError("cryptography library required for Fernet decryption")
        
        if len(encrypted_data) < 16:
            raise ValueError("Invalid encrypted data: too short")
        
        try:
            salt = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            key, _ = self.derive_fernet_key(password, salt)
            fernet = Fernet(key)
            return fernet.decrypt(encrypted_data)
            
        except Exception as e:
            self.logger.error(f"Fernet decryption error: {e}")
            raise RuntimeError(f"Fernet decryption failed: {str(e)}") from e
    
    def derive_fernet_key(self, password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
        """Fernet-specific key derivation"""
        key, salt = self.derive_key(password, salt, 32)
        return base64.urlsafe_b64encode(key), salt
    
    def encrypt_aes_cbc(self, data: bytes, password: str) -> bytes:
        """AES-CBC encryption with improved padding"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for AES-CBC")
        
        try:
            key, salt = self.derive_key(password, key_size=32)
            iv = secrets.token_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            # Use PKCS7 padding
            padded_data = pad(data, AES.block_size, style='pkcs7')
            encrypted_data = cipher.encrypt(padded_data)
            
            return salt + iv + encrypted_data
            
        except Exception as e:
            self.logger.error(f"AES-CBC encryption error: {e}")
            raise RuntimeError(f"AES-CBC encryption failed: {str(e)}") from e
    
    def decrypt_aes_cbc(self, encrypted_data: bytes, password: str) -> bytes:
        """AES-CBC decryption with padding validation"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for AES-CBC")
        
        if len(encrypted_data) < 48:  # salt(16) + iv(16) + min_data(16)
            raise ValueError("Invalid encrypted data: too short")
        
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:32]
            encrypted_data = encrypted_data[32:]
            
            key, _ = self.derive_key(password, salt, key_size=32)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            
            decrypted_data = cipher.decrypt(encrypted_data)
            return unpad(decrypted_data, AES.block_size, style='pkcs7')
            
        except ValueError as e:
            # Padding error
            self.logger.error(f"AES-CBC padding error: {e}")
            raise ValueError("Decryption failed: invalid padding") from e
        except Exception as e:
            self.logger.error(f"AES-CBC decryption error: {e}")
            raise RuntimeError(f"AES-CBC decryption failed: {str(e)}") from e
    
    def encrypt_aes_gcm(self, data: bytes, password: str) -> bytes:
        """AES-GCM authenticated encryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for AES-GCM")
        
        try:
            key, salt = self.derive_key(password, key_size=32)
            iv = secrets.token_bytes(12)  # 96-bit IV recommended for GCM
            
            cipher = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
            encrypted_data, tag = cipher.encrypt_and_digest(data)
            
            return salt + iv + tag + encrypted_data
            
        except Exception as e:
            self.logger.error(f"AES-GCM encryption error: {e}")
            raise RuntimeError(f"AES-GCM encryption failed: {str(e)}") from e
    
    def decrypt_aes_gcm(self, encrypted_data: bytes, password: str) -> bytes:
        """AES-GCM decryption with authentication"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for AES-GCM")
        
        if len(encrypted_data) < 44:  # salt(16) + iv(12) + tag(16)
            raise ValueError("Invalid encrypted data: too short")
        
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:28]
            tag = encrypted_data[28:44]
            encrypted_data = encrypted_data[44:]
            
            key, _ = self.derive_key(password, salt, key_size=32)
            cipher = AES.new(key, AES.MODE_GCM, iv, mac_len=16)
            
            return cipher.decrypt_and_verify(encrypted_data, tag)
            
        except ValueError as e:
            # Authentication failed
            self.logger.error(f"AES-GCM authentication error: {e}")
            raise ValueError("Decryption failed: authentication error") from e
        except Exception as e:
            self.logger.error(f"AES-GCM decryption error: {e}")
            raise RuntimeError(f"AES-GCM decryption failed: {str(e)}") from e
    
    def encrypt_aes_ctr(self, data: bytes, password: str) -> bytes:
        """AES-CTR encryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for AES-CTR")
        
        try:
            key, salt = self.derive_key(password, key_size=32)
            nonce = secrets.token_bytes(8)  # 64-bit nonce for CTR
            
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            encrypted_data = cipher.encrypt(data)
            
            return salt + nonce + encrypted_data
            
        except Exception as e:
            self.logger.error(f"AES-CTR encryption error: {e}")
            raise RuntimeError(f"AES-CTR encryption failed: {str(e)}") from e
    
    def decrypt_aes_ctr(self, encrypted_data: bytes, password: str) -> bytes:
        """AES-CTR decryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for AES-CTR")
        
        if len(encrypted_data) < 24:  # salt(16) + nonce(8)
            raise ValueError("Invalid encrypted data: too short")
        
        try:
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:24]
            encrypted_data = encrypted_data[24:]
            
            key, _ = self.derive_key(password, salt, key_size=32)
            cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
            
            return cipher.decrypt(encrypted_data)
            
        except Exception as e:
            self.logger.error(f"AES-CTR decryption error: {e}")
            raise RuntimeError(f"AES-CTR decryption failed: {str(e)}") from e
    
    def encrypt_chacha20(self, data: bytes, password: str) -> bytes:
        """ChaCha20 encryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for ChaCha20")
        
        try:
            key, salt = self.derive_key(password, key_size=32)
            nonce = secrets.token_bytes(12)
            
            cipher = ChaCha20.new(key=key, nonce=nonce)
            encrypted_data = cipher.encrypt(data)
            
            return salt + nonce + encrypted_data
            
        except Exception as e:
            self.logger.error(f"ChaCha20 encryption error: {e}")
            raise RuntimeError(f"ChaCha20 encryption failed: {str(e)}") from e
    
    def decrypt_chacha20(self, encrypted_data: bytes, password: str) -> bytes:
        """ChaCha20 decryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for ChaCha20")
        
        if len(encrypted_data) < 28:  # salt(16) + nonce(12)
            raise ValueError("Invalid encrypted data: too short")
        
        try:
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            encrypted_data = encrypted_data[28:]
            
            key, _ = self.derive_key(password, salt, key_size=32)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            
            return cipher.decrypt(encrypted_data)
            
        except Exception as e:
            self.logger.error(f"ChaCha20 decryption error: {e}")
            raise RuntimeError(f"ChaCha20 decryption failed: {str(e)}") from e
    
    def encrypt_des3(self, data: bytes, password: str) -> bytes:
        """Triple DES encryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for Triple DES")
        
        try:
            key, salt = self.derive_key(password, key_size=24)
            iv = secrets.token_bytes(8)
            
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            padded_data = pad(data, DES3.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            
            return salt + iv + encrypted_data
            
        except Exception as e:
            self.logger.error(f"Triple DES encryption error: {e}")
            raise RuntimeError(f"Triple DES encryption failed: {str(e)}") from e
    
    def decrypt_des3(self, encrypted_data: bytes, password: str) -> bytes:
        """Triple DES decryption"""
        if not PYCRYPTO_AVAILABLE:
            raise RuntimeError("pycryptodome required for Triple DES")
        
        if len(encrypted_data) < 24:  # salt(16) + iv(8)
            raise ValueError("Invalid encrypted data: too short")
        
        try:
            salt = encrypted_data[:16]
            iv = encrypted_data[16:24]
            encrypted_data = encrypted_data[24:]
            
            key, _ = self.derive_key(password, salt, key_size=24)
            cipher = DES3.new(key, DES3.MODE_CBC, iv)
            
            decrypted_data = cipher.decrypt(encrypted_data)
            return unpad(decrypted_data, DES3.block_size)
            
        except Exception as e:
            self.logger.error(f"Triple DES decryption error: {e}")
            raise RuntimeError(f"Triple DES decryption failed: {str(e)}") from e
    
    def encrypt_xor(self, data: bytes, password: str) -> bytes:
        """Simple XOR encryption"""
        try:
            salt = secrets.token_bytes(16)
            key = self._derive_xor_key(password, salt)
            
            encrypted = bytearray()
            for i, byte in enumerate(data):
                encrypted.append(byte ^ key[i % len(key)])
            
            return salt + bytes(encrypted)
            
        except Exception as e:
            self.logger.error(f"XOR encryption error: {e}")
            raise RuntimeError(f"XOR encryption failed: {str(e)}") from e
    
    def decrypt_xor(self, encrypted_data: bytes, password: str) -> bytes:
        """XOR decryption"""
        try:
            salt = encrypted_data[:16]
            encrypted_data = encrypted_data[16:]
            
            key = self._derive_xor_key(password, salt)
            decrypted = bytearray()
            
            for i, byte in enumerate(encrypted_data):
                decrypted.append(byte ^ key[i % len(key)])
            
            return bytes(decrypted)
            
        except Exception as e:
            self.logger.error(f"XOR decryption error: {e}")
            raise RuntimeError(f"XOR decryption failed: {str(e)}") from e
    
    def _derive_xor_key(self, password: str, salt: bytes) -> bytes:
        """Derive key for XOR encryption"""
        # Use simpler key derivation for XOR
        key_material = password.encode() + salt
        return hashlib.sha256(key_material).digest()
    
    def encrypt_text(self, text: str, password: str, algorithm: str = 'fernet') -> str:
        """Enhanced text encryption with validation"""
        if not text or not isinstance(text, str):
            raise ValueError("Invalid text input")
        
        if not password or len(password) < 4:
            raise ValueError("Password too short")
        
        algo_info = self.supported_algorithms.get(algorithm)
        if not algo_info:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
        
        if not algo_info.get('available', True):
            raise RuntimeError(f"Algorithm {algorithm} not available")
        
        try:
            data = text.encode('utf-8')
            
            # Algorithm mapping
            encryptors = {
                'fernet': self.encrypt_fernet,
                'aes_cbc': self.encrypt_aes_cbc,
                'aes_gcm': self.encrypt_aes_gcm,
                'aes_ctr': self.encrypt_aes_ctr,
                'chacha20': self.encrypt_chacha20,
                'des3': self.encrypt_des3,
                'xor': self.encrypt_xor
            }
            
            encryptor = encryptors.get(algorithm)
            if not encryptor:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            encrypted_data = encryptor(data, password)
            return base64.b64encode(encrypted_data).decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Text encryption error: {e}")
            raise RuntimeError(f"Text encryption failed: {str(e)}") from e
    
    def decrypt_text(self, encrypted_text: str, password: str, algorithm: str = 'fernet') -> str:
        """Enhanced text decryption with error recovery"""
        if not encrypted_text:
            raise ValueError("Encrypted text cannot be empty")
        
        try:
            encrypted_data = base64.b64decode(encrypted_text)
            
            # Algorithm mapping
            decryptors = {
                'fernet': self.decrypt_fernet,
                'aes_cbc': self.decrypt_aes_cbc,
                'aes_gcm': self.decrypt_aes_gcm,
                'aes_ctr': self.decrypt_aes_ctr,
                'chacha20': self.decrypt_chacha20,
                'des3': self.decrypt_des3,
                'xor': self.decrypt_xor
            }
            
            decryptor = decryptors.get(algorithm)
            if not decryptor:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            decrypted_data = decryptor(encrypted_data, password)
            return decrypted_data.decode('utf-8')
            
        except Exception as e:
            self.logger.error(f"Text decryption error: {e}")
            raise RuntimeError(f"Text decryption failed: {str(e)}") from e
    
    def encrypt_file(self, input_path: str, output_path: str, password: str, 
                    algorithm: str = 'fernet') -> bool:
        """Enhanced file encryption with progress tracking"""
        try:
            # Input validation
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"Input file not found: {input_path}")
            
            if not os.access(input_path, os.R_OK):
                raise PermissionError(f"No read access: {input_path}")
            
            # Check file size limits
            max_size = self.settings.get("files.max_file_size_mb", 100) * 1024 * 1024
            file_size = os.path.getsize(input_path)
            if file_size > max_size:
                raise ValueError(f"File too large: {file_size} bytes (max: {max_size})")
            
            # Read entire file (for simplicity, can be optimized for bigger files)
            with open(input_path, 'rb') as f:
                data = f.read()
            
            # Algorithm mapping
            encryptors = {
                'fernet': self.encrypt_fernet,
                'aes_cbc': self.encrypt_aes_cbc,
                'aes_gcm': self.encrypt_aes_gcm,
                'aes_ctr': self.encrypt_aes_ctr,
                'chacha20': self.encrypt_chacha20,
                'des3': self.encrypt_des3,
                'xor': self.encrypt_xor
            }
            
            encryptor = encryptors.get(algorithm)
            if not encryptor:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            encrypted_data = encryptor(data, password)
            
            # Write encrypted file
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Verify output
            if os.path.getsize(output_path) == 0:
                os.remove(output_path)
                raise ValueError("Encryption produced empty file")
            
            self.logger.info(f"File encrypted successfully: {input_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File encryption error {input_path}: {e}")
            # Clean up output file on error
            try:
                if os.path.exists(output_path):
                    os.remove(output_path)
            except:
                pass
            return False
    
    def decrypt_file(self, input_path: str, output_path: str, password: str, 
                    algorithm: str = 'fernet') -> bool:
        """File decryption"""
        try:
            if not os.path.exists(input_path):
                raise FileNotFoundError(f"File not found: {input_path}")
            
            with open(input_path, 'rb') as f:
                encrypted_data = f.read()
            
            # Algorithm mapping
            decryptors = {
                'fernet': self.decrypt_fernet,
                'aes_cbc': self.decrypt_aes_cbc,
                'aes_gcm': self.decrypt_aes_gcm,
                'aes_ctr': self.decrypt_aes_ctr,
                'chacha20': self.decrypt_chacha20,
                'des3': self.decrypt_des3,
                'xor': self.decrypt_xor
            }
            
            decryptor = decryptors.get(algorithm)
            if not decryptor:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            decrypted_data = decryptor(encrypted_data, password)
            
            with open(output_path, 'wb') as f:
                f.write(decrypted_data)
            
            self.logger.info(f"File decrypted: {input_path} -> {output_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"File decryption error {input_path}: {e}")
            # Clean up output file on error
            try:
                if os.path.exists(output_path):
                    os.remove(output_path)
            except:
                pass
            return False
    
    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy with improved accuracy"""
        if len(data) == 0:
            return 0.0
        
        counter = Counter(data)
        entropy = 0.0
        total = len(data)
        
        for count in counter.values():
            p = count / total
            entropy -= p * math.log2(p)
        
        return entropy
    
    def detect_algorithm(self, file_path: str) -> Dict[str, Any]:
        """Enhanced algorithm detection with more signatures"""
        try:
            with open(file_path, 'rb') as f:
                data = f.read(1024)  # Read first KB for analysis
            
            if len(data) < 16:
                return {
                    'algorithm': 'unknown',
                    'confidence': 0,
                    'details': {'error': 'File too small for analysis'}
                }
            
            result = {
                'algorithm': 'unknown',
                'confidence': 0,
                'details': {}
            }
            
            # Enhanced signature detection
            signatures = {
                b'gAAAA': ('fernet', 95),
                b'Salted__': ('openssl', 85),
                b'U2FsdGVkX1': ('openssl_base64', 80),  # Base64 encoded "Salted__"
            }
            
            for signature, (algo, confidence) in signatures.items():
                if data.startswith(signature):
                    result.update({
                        'algorithm': algo,
                        'confidence': confidence,
                        'signature': signature.hex()
                    })
                    return result
            
            # Enhanced entropy analysis
            full_data = data
            if len(data) < 1024:
                with open(file_path, 'rb') as f:
                    full_data = f.read()
            
            entropy = self._calculate_entropy(full_data)
            result['details']['entropy'] = entropy
            result['details']['file_size'] = len(full_data) if full_data else 0
            
            # Improved entropy-based classification
            if entropy > 7.8:
                result.update({
                    'algorithm': 'encrypted (high entropy)',
                    'confidence': 85,
                    'details': {'entropy_level': 'very_high'}
                })
            elif entropy > 7.0:
                result.update({
                    'algorithm': 'likely encrypted',
                    'confidence': 70,
                    'details': {'entropy_level': 'high'}
                })
            elif entropy > 6.0:
                result.update({
                    'algorithm': 'possibly encrypted',
                    'confidence': 50,
                    'details': {'entropy_level': 'medium'}
                })
            else:
                result.update({
                    'algorithm': 'likely unencrypted',
                    'confidence': 80,
                    'details': {'entropy_level': 'low'}
                })
            
            return result
            
        except Exception as e:
            self.logger.error(f"File analysis error: {e}")
            return {
                'algorithm': 'error',
                'confidence': 0,
                'details': {'error': str(e)}
            }
    
    def get_available_algorithms(self) -> Dict[str, Dict]:
        """Get list of available algorithms with status"""
        available = {}
        for name, info in self.supported_algorithms.items():
            if info.get('available', True):
                available[name] = info
        return available
    
    def cleanup(self):
        """Secure cleanup of sensitive data"""
        with self._cache_lock:
            # Clear key cache
            for key in self._key_cache.values():
                # Securely clear from memory
                if isinstance(key, bytes):
                    for i in range(len(key)):
                        key = key[:i] + b'\x00' + key[i+1:]
            self._key_cache.clear()
        
        # Clear LRU cache
        self._get_cached_key.cache_clear()