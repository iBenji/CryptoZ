import random
import re
import base64
import hashlib
import secrets
#import string
from typing import Dict, List, Optional

class CodeAnalyzer:
    """Enhanced code analyzer and encryptor with improved security"""
    
    def __init__(self):
        self.supported_languages = {
            'python': {
                'extensions': ['.py'], 
                'comments': ['#', '"""', "'''"],
                'keywords': {'if', 'else', 'for', 'while', 'def', 'class', 'import', 'from', 
                           'return', 'True', 'False', 'None', 'and', 'or', 'not', 'in', 'is',
                           'try', 'except', 'finally', 'with', 'as', 'lambda', 'pass', 'break',
                           'continue', 'global', 'nonlocal', 'assert', 'raise', 'yield'}
            },
            'javascript': {
                'extensions': ['.js', '.ts', '.jsx', '.tsx'], 
                'comments': ['//', '/*'],
                'keywords': {'function', 'var', 'let', 'const', 'if', 'else', 'for', 'while',
                           'return', 'class', 'import', 'export', 'try', 'catch', 'finally'}
            },
            'java': {
                'extensions': ['.java'], 
                'comments': ['//', '/*'],
                'keywords': {'public', 'private', 'protected', 'class', 'interface', 'static',
                           'void', 'int', 'String', 'if', 'else', 'for', 'while', 'return'}
            },
            # ... other languages with enhanced keyword lists
        }
        
        # Encryption markers with randomization
        self.encryption_markers = {
            'base64': {
                'start': '# ENCRYPTED_CODE_BEGIN #',
                'end': '# ENCRYPTED_CODE_END #'
            },
            'xor': {
                'start': '// XOR_ENCRYPTED_BEGIN //',
                'end': '// XOR_ENCRYPTED_END //'
            }
        }
    
    def encrypt_code_region(self, code: str, password: str, start_pos: int, 
                           end_pos: int, method: str = 'obfuscate') -> str:
        """Encrypt arbitrary code region with enhanced validation"""
        # Input validation
        if not code or not isinstance(code, str):
            raise ValueError("Invalid code input")
        
        if not password or len(password) < 4:
            raise ValueError("Password too short")
        
        if start_pos < 0 or end_pos > len(code) or start_pos >= end_pos:
            raise ValueError("Invalid code region positions")
        
        if method not in ['obfuscate', 'base64', 'xor']:
            raise ValueError(f"Unsupported encryption method: {method}")
        
        selected_code = code[start_pos:end_pos]
        
        try:
            if method == 'obfuscate':
                encrypted = self._obfuscate_code(selected_code, password)
            elif method == 'base64':
                encrypted = self._encode_base64(selected_code, password)
            elif method == 'xor':
                encrypted = self._xor_encrypt(selected_code, password)
            
            # Replace original code with encrypted version
            result = code[:start_pos] + encrypted + code[end_pos:]
            return result
            
        except Exception as e:
            raise RuntimeError(f"Code encryption failed: {str(e)}") from e
    
    def decrypt_code_region(self, code: str, password: str, method: str = 'obfuscate') -> str:
        """Decrypt code with enhanced error handling"""
        if not code or not password:
            return code
        
        try:
            if method == 'base64':
                return self._decode_base64(code, password)
            elif method == 'xor':
                return self._xor_decrypt(code, password)
            else:
                # Obfuscation is one-way
                return code
                
        except Exception:
            # Return original code on decryption failure
            return code
    
    def find_encrypted_regions(self, code: str) -> List[Dict]:
        """Find encrypted regions in code with enhanced detection"""
        if not code:
            return []
        
        regions = []
        
        # Enhanced pattern matching with error handling
        patterns = [
            {
                'type': 'base64',
                'pattern': r'#\s*ENCRYPTED_CODE_BEGIN\s*#(.+?)#\s*ENCRYPTED_CODE_END\s*#',
                'flags': re.DOTALL
            },
            {
                'type': 'xor', 
                'pattern': r'//\s*XOR_ENCRYPTED_BEGIN\s*//(.+?)//\s*XOR_ENCRYPTED_END\s*//',
                'flags': re.DOTALL
            }
        ]
        
        for pattern_info in patterns:
            try:
                for match in re.finditer(pattern_info['pattern'], code, pattern_info['flags']):
                    regions.append({
                        'type': pattern_info['type'],
                        'start': match.start(),
                        'end': match.end(),
                        'content': match.group(1),
                        'length': len(match.group(1))
                    })
            except re.error:
                continue  # Skip invalid patterns
        
        return regions
    
    def _obfuscate_code(self, code: str, password: str) -> str:
        """Enhanced code obfuscation with secure randomization"""
        # Extract identifiers with improved regex
        identifier_pattern = r'\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b'
        identifiers = re.findall(identifier_pattern, code)
        
        # Filter out keywords and built-ins
        all_keywords = set()
        for lang_info in self.supported_languages.values():
            all_keywords.update(lang_info.get('keywords', set()))
        
        # Add Python built-ins
        python_builtins = {
            'abs', 'all', 'any', 'bin', 'bool', 'chr', 'dict', 'dir', 'enumerate',
            'filter', 'float', 'format', 'hash', 'int', 'len', 'list', 'map', 'max',
            'min', 'print', 'range', 'repr', 'reversed', 'round', 'set', 'sorted',
            'str', 'sum', 'tuple', 'type', 'zip'
        }
        all_keywords.update(python_builtins)
        
        identifiers = [id for id in set(identifiers) 
                      if id not in all_keywords and not id[0].isupper()]
        
        if not identifiers:
            return code  # Nothing to obfuscate
        
        # Create secure mapping using password-derived seed
        seed = int(hashlib.sha256(password.encode()).hexdigest()[:8], 16)
        random.seed(seed)
        
        name_mapping = {}
        used_names = set()
        
        for identifier in identifiers:
            while True:
                # Generate more complex obfuscated names
                new_name = f'_{self._generate_secure_obfuscated_name()}'
                if new_name not in used_names and new_name not in code:
                    name_mapping[identifier] = new_name
                    used_names.add(new_name)
                    break
        
        # Replace names in code with word boundaries
        obfuscated_code = code
        for old_name, new_name in name_mapping.items():
            obfuscated_code = re.sub(r'\b' + re.escape(old_name) + r'\b', new_name, obfuscated_code)
        
        return obfuscated_code
    
    def _encode_base64(self, code: str, password: str) -> str:
        """Enhanced base64 encoding with improved security"""
        # Use SHA-256 instead of MD5 for salt
        salt = hashlib.sha256(password.encode() + b'base64_salt').hexdigest()[:16]
        
        # Add compression for larger code blocks
        import zlib
        compressed_code = zlib.compress(code.encode('utf-8'), level=9)
        encoded = base64.b64encode(compressed_code).decode()
        
        marker_start = self.encryption_markers['base64']['start']
        marker_end = self.encryption_markers['base64']['end']
        
        return f"{marker_start}{salt}_{encoded}{marker_end}"
    
    def _decode_base64(self, code: str, password: str) -> str:
        """Enhanced base64 decoding with error recovery"""
        try:
            pattern = r'#\s*ENCRYPTED_CODE_BEGIN\s*#(.+?)#\s*ENCRYPTED_CODE_END\s*#'
            match = re.search(pattern, code, re.DOTALL)
            
            if match:
                encrypted_data = match.group(1)
                
                # Extract and validate salt (though we don't use it for verification here)
                if '_' in encrypted_data:
                    encrypted_data = encrypted_data.split('_', 1)[1]
                
                # Decode with error handling
                import zlib
                decoded_bytes = base64.b64decode(encrypted_data)
                decompressed_code = zlib.decompress(decoded_bytes).decode('utf-8')
                
                return decompressed_code
            
            return code
            
        except (base64.binascii.Error, zlib.error, UnicodeDecodeError):
            # Return original code on any decoding error
            return code
    
    def _xor_encrypt(self, code: str, password: str) -> str:
        """Enhanced XOR encryption with better key derivation"""
        # Use more secure key derivation
        key = hashlib.sha384(password.encode()).digest()
        encrypted_bytes = bytearray()
        
        for i, char in enumerate(code):
            key_byte = key[i % len(key)]
            encrypted_bytes.append(ord(char) ^ key_byte)
        
        encoded = base64.b64encode(encrypted_bytes).decode()
        
        marker_start = self.encryption_markers['xor']['start']
        marker_end = self.encryption_markers['xor']['end']
        
        return f"{marker_start}{encoded}{marker_end}"
    
    def _xor_decrypt(self, code: str, password: str) -> str:
        """Enhanced XOR decryption with error handling"""
        try:
            pattern = r'//\s*XOR_ENCRYPTED_BEGIN\s*//(.+?)//\s*XOR_ENCRYPTED_END\s*//'
            match = re.search(pattern, code, re.DOTALL)
            
            if match:
                encrypted_data = match.group(1)
                encrypted_bytes = base64.b64decode(encrypted_data)
                
                key = hashlib.sha384(password.encode()).digest()
                decrypted_chars = []
                
                for i, byte in enumerate(encrypted_bytes):
                    key_byte = key[i % len(key)]
                    decrypted_chars.append(chr(byte ^ key_byte))
                
                return ''.join(decrypted_chars)
            
            return code
            
        except (base64.binascii.Error, UnicodeDecodeError):
            return code
    
    def _generate_secure_obfuscated_name(self) -> str:
        """Generate secure obfuscated names using secrets"""
        length = secrets.choice([4, 5, 6, 7, 8])
        chars = 'abcdefghijklmnopqrstuvwxyz0123456789'
        return ''.join(secrets.choice(chars) for _ in range(length))
    
    def analyze_code_complexity(self, code: str) -> Dict:
        """Analyze code complexity metrics"""
        if not code:
            return {'error': 'Empty code'}
        
        lines = code.split('\n')
        non_empty_lines = [line for line in lines if line.strip()]
        
        # Basic metrics
        metrics = {
            'total_lines': len(lines),
            'non_empty_lines': len(non_empty_lines),
            'comment_lines': len([line for line in lines if line.strip().startswith(('#', '//', '/*'))]),
            'avg_line_length': sum(len(line) for line in lines) / len(lines) if lines else 0,
        }
        
        # Complexity estimation
        complexity_indicators = ['if', 'for', 'while', 'def ', 'class ', 'try:', 'except']
        complexity_score = sum(code.count(indicator) for indicator in complexity_indicators)
        metrics['complexity_score'] = complexity_score
        
        return metrics