#import base64
import os
#import struct
import logging
from typing import Optional, Tuple, Dict, Any
import zlib
from PIL import Image, ImageFile
import wave
import hashlib
from cryptography.fernet import Fernet

# Разрешаем загрузку поврежденных изображений (для стеганографии)
ImageFile.LOAD_TRUNCATED_IMAGES = True

class SteganographyEngine:
    """Advanced steganography engine for hiding data in various file types"""
    
    def __init__(self, crypto_engine=None):
        self.crypto_engine = crypto_engine
        self.logger = logging.getLogger(__name__)
        
        # Поддерживаемые форматы
        self.supported_formats = {
            'image': ['png', 'bmp', 'tiff', 'jpg', 'jpeg'],
            'audio': ['wav'],
            'text': ['txt', 'csv', 'xml', 'json']
        }
    
    def hide_in_image(self, data: bytes, carrier_path: str, output_path: str, 
                password: Optional[str] = None, method: str = 'lsb',
                progress_callback=None, compress: bool = False,
                log_callback=None) -> Dict[str, Any]:
        """Hide data in image - WITH PROGRESS CALLBACK"""
        try:
            if progress_callback:
                progress_callback(0.0, "Checking carrier file...")

            if not os.path.exists(carrier_path):
                return {"success": False, "error": "Carrier file not found"}
            
            original_size = os.path.getsize(carrier_path)
            
            # Инициализация
            is_compressed = False
            is_encrypted = False
            work_data = data  # будем модифицировать

            # --- СЖАТИЕ: до шифрования ---
            if compress:
                compressed_data = zlib.compress(work_data)
                if len(compressed_data) < len(work_data):
                    work_data = compressed_data
                    is_compressed = True
                    if log_callback:
                        log_callback(f"Compressed: {len(data)} -> {len(compressed_data)} bytes")
                    else:
                        self.logger.info(f"Compression: {len(data)} -> {len(compressed_data)} bytes")

            # --- ШИФРОВАНИЕ: над сжатыми данными ---
            if password:
                try:
                    data_to_hide = self._encrypt_binary_data(work_data, password)
                    is_encrypted = True
                    if log_callback:
                        log_callback(f"Encrypted: {len(work_data)} -> {len(data_to_hide)} bytes")
                except Exception as e:
                    return {"success": False, "error": f"Encryption failed: {str(e)}"}
            else:
                data_to_hide = work_data

            # --- ПРОДОЛЖЕНИЕ: capacity, image load, etc. ---
            if progress_callback:
                progress_callback(0.1, "Calculating capacity...")

            max_data_size = self._calculate_max_image_capacity(carrier_path, method)
            if len(data_to_hide) > max_data_size:
                return {
                    "success": False, 
                    "error": f"Data too large. Max: {max_data_size}, Got: {len(data_to_hide)}"
                }

            if progress_callback:
                progress_callback(0.2, "Loading carrier image...")

            # Открываем изображение
            with Image.open(carrier_path) as img:
                if img.mode not in ['RGB', 'RGBA']:
                    img = img.convert('RGB')
                
                img_copy = img.copy()
                pixels = img_copy.load()
                width, height = img_copy.size

                # Добавляем заголовок
                header = self._create_data_header(data_to_hide, method, is_encrypted, is_compressed)
                full_data = header + data_to_hide
                
                if progress_callback:
                    progress_callback(0.3, "Starting data hiding...")

                # Скрываем данные
                success = False
                if method == 'lsb':
                    success = self._hide_lsb_with_progress(pixels, width, height, full_data, progress_callback)
                else:
                    success = self._hide_lsb_with_progress(pixels, width, height, full_data, progress_callback)
                
                if not success:
                    return {"success": False, "error": "Failed to hide data in image"}
                
                if progress_callback:
                    progress_callback(0.9, "Saving output image...")

                # Сохраняем
                img_copy.save(output_path, format='PNG')
                
                if not os.path.exists(output_path):
                    return {"success": False, "error": "Output file was not created"}
                
                output_size = os.path.getsize(output_path)
                
                if progress_callback:
                    progress_callback(1.0, "Hiding completed!")

                return {
                    "success": True,
                    "output_path": output_path,
                    "data_size": len(data),
                    "hidden_size": len(full_data),
                    "method": method,
                    "encrypted": is_encrypted,
                    "original_size": original_size,
                    "output_size": output_size
                }
                
        except Exception as e:
            self.logger.error(f"Image steganography error: {e}")
            if progress_callback:
                progress_callback(0.0, f"Error: {str(e)}")
            return {"success": False, "error": str(e)}

    def _hide_lsb_with_progress(self, pixels, width: int, height: int, data: bytes, 
                          progress_callback=None) -> bool:
        """LSB hiding with progress reporting"""
        try:
            data_bits = ''.join(format(byte, '08b') for byte in data)
            total_bits = len(data_bits)
            data_index = 0
            
            if total_bits == 0:
                if progress_callback:
                    progress_callback(1.0, "No data to hide (empty)")
                return True

            bits_per_update = max(1, total_bits // 20)  # 20 обновлений
            last_update = 0

            self.logger.info(f"Hiding {total_bits} bits in {width}x{height} image")

            for y in range(height):
                for x in range(width):
                    if data_index >= total_bits:
                        if progress_callback:
                            progress_callback(1.0, "Hiding completed.")
                        return True
                    
                    r, g, b = pixels[x, y][:3]
                    new_r, new_g, new_b = r, g, b
                    pixel_modified = False
                    
                    if data_index < total_bits:
                        new_r = (r & 0xFE) | int(data_bits[data_index])
                        if new_r != r: pixel_modified = True
                        data_index += 1
                    if data_index < total_bits:
                        new_g = (g & 0xFE) | int(data_bits[data_index])
                        if new_g != g: pixel_modified = True
                        data_index += 1
                    if data_index < total_bits:
                        new_b = (b & 0xFE) | int(data_bits[data_index])
                        if new_b != b: pixel_modified = True
                        data_index += 1
                    
                    if pixel_modified:
                        pixels[x, y] = (new_r, new_g, new_b)

                    # Отправляем прогресс
                    progress = data_index / total_bits
                    if progress_callback and (data_index - last_update) >= bits_per_update:
                        progress_callback(progress, f"Hiding... {int(progress * 100)}%")
                        last_update = data_index
            
            # На случай, если цикл завершился, но не дошёл до 100%
            if progress_callback and data_index < total_bits:
                progress_callback(1.0, "Completed (partial)")

            return data_index >= total_bits
            
        except Exception as e:
            self.logger.error(f"LSB hiding progress error: {e}")
            if progress_callback:
                progress_callback(0.0, f"Error: {str(e)}")
            return False


    def _hide_lsb_debug(self, pixels, width: int, height: int, data: bytes) -> bool:
        """LSB hiding with detailed debugging"""
        try:
            self.logger.info(f"DEBUG: Data to hide: {data.hex()}")
            
            data_bits = ''.join(format(byte, '08b') for byte in data)
            self.logger.info(f"DEBUG: Data as bits: {data_bits}")
            self.logger.info(f"DEBUG: Total bits to hide: {len(data_bits)}")
            
            data_index = 0
            total_bits = len(data_bits)
            
            # Логируем первые 10 пикселей ДО изменения
            self.logger.info("DEBUG: First 10 pixels BEFORE:")
            for y in range(min(2, height)):
                for x in range(min(5, width)):
                    r, g, b = pixels[x, y][:3]
                    self.logger.info(f"  Pixel ({x},{y}): R={r:08b}, G={g:08b}, B={b:08b}")
            
            for y in range(height):
                for x in range(width):
                    if data_index >= total_bits:
                        self.logger.info(f"DEBUG: Hiding completed at pixel ({x},{y})")
                        # Логируем первые 10 пикселей ПОСЛЕ изменения
                        self.logger.info("DEBUG: First 10 pixels AFTER:")
                        for y2 in range(min(2, height)):
                            for x2 in range(min(5, width)):
                                r, g, b = pixels[x2, y2][:3]
                                self.logger.info(f"  Pixel ({x2},{y2}): R={r:08b}, G={g:08b}, B={b:08b}")
                        return True
                    
                    r, g, b = pixels[x, y][:3]
                    
                    # Modify LSB
                    if data_index < total_bits:
                        new_r = (r & 0xFE) | int(data_bits[data_index])
                        data_index += 1
                    if data_index < total_bits:
                        new_g = (g & 0xFE) | int(data_bits[data_index])
                        data_index += 1
                    if data_index < total_bits:
                        new_b = (b & 0xFE) | int(data_bits[data_index])
                        data_index += 1
                    
                    pixels[x, y] = (new_r, new_g, new_b)
            
            return True
            
        except Exception as e:
            self.logger.error(f"LSB hiding debug error: {e}")
            return False
    
    def _hide_lsb_simple(self, pixels, width: int, height: int, data: bytes) -> bool:
        """Simple LSB hiding - VERIFIED"""
        try:
            data_bits = ''.join(format(byte, '08b') for byte in data)
            data_index = 0
            total_bits = len(data_bits)
            
            self.logger.info(f"Hiding {total_bits} bits in {width}x{height} image")
            
            for y in range(height):
                for x in range(width):
                    if data_index >= total_bits:
                        self.logger.info(f"Hiding completed: {data_index}/{total_bits} bits")
                        return True
                    
                    r, g, b = pixels[x, y][:3]
                    
                    # Логируем первые несколько изменений для отладки
                    if data_index < 10:
                        self.logger.info(f"Bit {data_index}: hiding in pixel ({x},{y})")
                    
                    # Modify LSB of each color channel
                    if data_index < total_bits:
                        new_r = (r & 0xFE) | int(data_bits[data_index])
                        data_index += 1
                    if data_index < total_bits:
                        new_g = (g & 0xFE) | int(data_bits[data_index])
                        data_index += 1
                    if data_index < total_bits:
                        new_b = (b & 0xFE) | int(data_bits[data_index])
                        data_index += 1
                    
                    pixels[x, y] = (new_r, new_g, new_b)
            
            self.logger.info(f"Hiding finished: {data_index}/{total_bits} bits")
            return data_index == total_bits
            
        except Exception as e:
            self.logger.error(f"LSB hiding error: {e}")
            return False

    def _extract_lsb_simple(self, pixels, width: int, height: int, data_size: int, offset: int = 0) -> bytes:
        """Simple LSB extraction - FIXED for data_size = 0"""
        try:
            if data_size == 0:
                self.logger.info(f"Extracting 0 bytes (data_size=0)")
                return b''

            bits_to_skip = offset * 8
            bits_needed = data_size * 8
            total_bits_to_extract = bits_needed + bits_to_skip

            self.logger.info(f"Extracting {data_size} bytes from offset {offset} (skipping {bits_to_skip} bits)")

            bits = []
            total_bits_extracted = 0

            for y in range(height):
                for x in range(width):
                    if total_bits_extracted >= total_bits_to_extract:
                        break

                    r, g, b = pixels[x, y][:3]
                    channel_bits = [r & 1, g & 1, b & 1]

                    for bit in channel_bits:
                        if total_bits_extracted < bits_to_skip:
                            total_bits_extracted += 1
                            continue

                        if len(bits) < bits_needed:
                            bits.append(str(bit))
                            total_bits_extracted += 1
                        else:
                            break

                    if len(bits) >= bits_needed:
                        break

            self.logger.info(f"Extracted {len(bits)} bits (needed: {bits_needed})")

            if len(bits) < bits_needed:
                self.logger.warning(f"Not enough bits extracted: {len(bits)} < {bits_needed}")
                return None

            # Convert bits to bytes
            byte_data = bytearray()
            for i in range(0, len(bits), 8):
                if i + 8 <= len(bits):
                    byte_bits = ''.join(bits[i:i+8])
                    try:
                        byte_data.append(int(byte_bits, 2))
                    except ValueError:
                        self.logger.error(f"Invalid bits: {byte_bits}")
                        continue

            result = bytes(byte_data)
            self.logger.info(f"Converted to {len(result)} bytes: {result.hex() if result else '(empty)'}")
            return result

        except Exception as e:
            self.logger.error(f"LSB extraction error: {e}")
            return None

    def _encrypt_binary_data(self, data: bytes, password: str) -> bytes:
        """Simple and reliable encryption using XOR with key derivation"""
        try:
            # Создаем ключ из пароля
            key = hashlib.sha256(password.encode()).digest()
            
            # Добавляем соль для уникальности
            salt = b'cryptoz_stego_'
            
            # Шифруем данные
            encrypted = bytearray()
            for i, byte in enumerate(data):
                # Используем байты из ключа циклически
                key_byte = key[i % len(key)]
                # Также используем соль для усложнения
                salt_byte = salt[i % len(salt)]
                encrypted.append(byte ^ key_byte ^ salt_byte)
            
            return bytes(encrypted)
            
        except Exception as e:
            self.logger.error(f"Encryption error: {e}")
            return data  # В случае ошибки возвращаем оригинальные данные

    def _decrypt_binary_data(self, encrypted_data: bytes, password: str) -> bytes:
        """Decryption - XOR symmetric"""
        # XOR шифрование симметрично, используем тот же метод
        return self._encrypt_binary_data(encrypted_data, password)

    def _hide_lsb_improved(self, pixels, width: int, height: int, data: bytes) -> bool:
        """Improved LSB hiding with better data integrity"""
        try:
            # Добавляем контрольную сумму к данным
            data_hash = hashlib.sha256(data).digest()[:4]  # 4 байта для контроля целостности
            data_with_hash = data_hash + data
            total_data_size = len(data_with_hash)
            
            data_bits = ''.join(format(byte, '08b') for byte in data_with_hash)
            data_index = 0
            total_bits = len(data_bits)
            total_pixels = width * height
            max_bits = total_pixels * 3  # 3 bits per pixel (RGB)
            
            self.logger.info(f"Hiding {total_bits} bits ({total_data_size} bytes with hash) in {width}x{height} image")
            
            if total_bits > max_bits:
                self.logger.error(f"Data too large: {total_bits} > {max_bits}")
                return False
            
            modified_pixels = 0
            
            for y in range(height):
                for x in range(width):
                    if data_index >= total_bits:
                        break
                    
                    r, g, b = pixels[x, y][:3]
                    pixel_modified = False
                    
                    # Modify LSB of each color channel
                    if data_index < total_bits:
                        new_r = (r & 0xFE) | int(data_bits[data_index])
                        if new_r != r:
                            pixel_modified = True
                            r = new_r
                        data_index += 1
                        
                    if data_index < total_bits:
                        new_g = (g & 0xFE) | int(data_bits[data_index])
                        if new_g != g:
                            pixel_modified = True
                            g = new_g
                        data_index += 1
                        
                    if data_index < total_bits:
                        new_b = (b & 0xFE) | int(data_bits[data_index])
                        if new_b != b:
                            pixel_modified = True
                            b = new_b
                        data_index += 1
                    
                    if pixel_modified:
                        pixels[x, y] = (r, g, b)
                        modified_pixels += 1
            
            self.logger.info(f"Successfully hidden {data_index} bits in {modified_pixels} pixels")
            return data_index == total_bits
            
        except Exception as e:
            self.logger.error(f"LSB hiding error: {e}")
            return False

    def _hide_lsb_enhanced_improved(self, pixels, width: int, height: int, data: bytes):
        """Enhanced LSB with better distribution - IMPROVED"""
        data_bits = ''.join(format(byte, '08b') for byte in data)
        data_index = 0
        total_bits = len(data_bits)
        
        self.logger.info(f"Hiding {total_bits} bits using enhanced method")
        
        # Use a pattern to distribute bits more evenly
        for y in range(0, height, 2):
            for x in range(0, width, 2):
                if data_index >= total_bits:
                    return
                
                # Modify pixels in 2x2 blocks
                for dy in range(2):
                    for dx in range(2):
                        if y + dy < height and x + dx < width:
                            if data_index >= total_bits:
                                return
                            
                            r, g, b = pixels[x + dx, y + dy][:3]
                            
                            # Modify only one channel per pixel based on position
                            channel_selector = (x + y) % 3
                            if channel_selector == 0:  # Red channel
                                r = (r & 0xFE) | int(data_bits[data_index])
                            elif channel_selector == 1:  # Green channel
                                g = (g & 0xFE) | int(data_bits[data_index])
                            else:  # Blue channel
                                b = (b & 0xFE) | int(data_bits[data_index])
                            
                            pixels[x + dx, y + dy] = (r, g, b)
                            data_index += 1
        
        self.logger.info(f"Enhanced: Hidden {data_index} bits out of {total_bits}")

    def extract_from_image(self, stego_path: str, output_path: str, 
                    password: Optional[str] = None,
                    progress_callback=None,
                    log_callback=None) -> Dict[str, Any]:
        """Extract hidden data from image - WITH PROGRESS"""
        try:
            if progress_callback:
                progress_callback(0.0, "Loading stego file...")
            if log_callback:
                log_callback("Starting extraction process...")

            if not os.path.exists(stego_path):
                error_msg = "Stego file not found"
                if log_callback:
                    log_callback(f"Error: {error_msg}")
                return {"success": False, "error": error_msg}

            with Image.open(stego_path) as img:
                if img.mode not in ['RGB', 'RGBA']:
                    img = img.convert('RGB')
                
                pixels = img.load()
                width, height = img.size
                
                if progress_callback:
                    progress_callback(0.2, "Extracting header...")
                if log_callback:
                    log_callback("Extracting header (64 bytes)...")

                # Извлекаем заголовок
                header_data = self._extract_lsb_with_progress(pixels, width, height, 64, offset=0, progress_callback=progress_callback)
                if not header_data:
                    error_msg = "Failed to extract header data"
                    if log_callback:
                        log_callback(f"{error_msg}")
                    return {"success": False, "error": error_msg}

                header = self._parse_data_header(header_data)
                if not header:
                    error_msg = "Invalid or missing header"
                    if log_callback:
                        log_callback(f"{error_msg}")
                    return {"success": False, "error": error_msg}

                if log_callback:
                    log_callback(f"Header parsed: size={header['data_size']}, enc={header.get('encrypted')}, cmp={header.get('compressed')}")

                data_size = header['data_size']
                is_encrypted = header.get('encrypted', False)
                is_compressed = header.get('compressed', False)

                if data_size == 0:
                    if log_callback:
                        log_callback("No data to extract (empty file)")
                    with open(output_path, 'wb') as f:
                        f.write(b'')
                    if progress_callback:
                        progress_callback(1.0, "Done (empty)")
                    return {
                        "success": True,
                        "output_path": output_path,
                        "data_size": 0,
                        "encrypted": is_encrypted,
                        "compressed": is_compressed
                    }

                if progress_callback:
                    progress_callback(0.4, f"Extracting {data_size} bytes...")
                if log_callback:
                    log_callback(f"Extracting hidden data ({data_size} bytes)...")

                # Извлекаем данные
                hidden_data = self._extract_lsb_with_progress(
                    pixels, width, height, data_size, offset=64, progress_callback=progress_callback
                )
                if not hidden_data:
                    error_msg = "Failed to extract hidden data"
                    if log_callback:
                        log_callback(f"{error_msg}")
                    return {"success": False, "error": error_msg}

                final_data = hidden_data

                # Расшифровка
                if is_encrypted:
                    if not password:
                        error_msg = "Password required for decryption"
                        if log_callback:
                            log_callback(f"{error_msg}")
                        return {"success": False, "error": error_msg}
                    try:
                        if progress_callback:
                            progress_callback(0.7, "Decrypting...")
                        if log_callback:
                            log_callback("Decrypting data...")
                        final_data = self._decrypt_binary_data(hidden_data, password)
                        if log_callback:
                            log_callback(f"Decrypted: {len(final_data)} bytes")
                    except Exception as e:
                        error_msg = f"Decryption failed: {str(e)}"
                        if log_callback:
                            log_callback(f"{error_msg}")
                        return {"success": False, "error": error_msg}

                # Распаковка — ТОЛЬКО ОДИН РАЗ!
                if is_compressed:
                    try:
                        if progress_callback:
                            progress_callback(0.85, "Decompressing...")
                        if log_callback:
                            log_callback(f"Decompressing {len(final_data)} bytes...")
                        decompressed_data = zlib.decompress(final_data)
                        final_data = decompressed_data
                        if log_callback:
                            log_callback(f"Decompressed: {len(final_data)} bytes")
                    except zlib.error as e:
                        error_msg = "Corrupted or invalid compressed data"
                        if log_callback:
                            log_callback(f"Decompression failed: {error_msg}")
                        return {"success": False, "error": error_msg}
                    except Exception as e:
                        error_msg = f"Unexpected decompression error: {str(e)}"
                        if log_callback:
                            log_callback(f"{error_msg}")
                        return {"success": False, "error": error_msg}

                # Сохранение
                try:
                    if progress_callback:
                        progress_callback(0.95, "Saving output...")
                    with open(output_path, 'wb') as f:
                        f.write(final_data)
                    if log_callback:
                        log_callback(f"Saved: {len(final_data)} bytes -> {os.path.basename(output_path)}")
                except Exception as e:
                    error_msg = f"Save failed: {str(e)}"
                    if log_callback:
                        log_callback(f"{error_msg}")
                    return {"success": False, "error": error_msg}

                if progress_callback:
                    progress_callback(1.0, "Extraction completed!")
                if log_callback:
                    log_callback("Extraction successful!")

                return {
                    "success": True,
                    "output_path": output_path,
                    "data_size": len(final_data),
                    "encrypted": is_encrypted,
                    "compressed": is_compressed
                }

        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.logger.error(error_msg)
            if log_callback:
                log_callback(f"{error_msg}")
            if progress_callback:
                progress_callback(0.0, "Failed")
            return {"success": False, "error": str(e)}


    def _extract_lsb_with_progress(self, pixels, width: int, height: int, data_size: int, 
                             offset: int = 0, progress_callback=None) -> bytes:
        """LSB extraction with progress reporting"""
        try:
            if data_size == 0:
                return b''

            bits_to_skip = offset * 8
            bits_needed = data_size * 8
            total_bits = bits_needed + bits_to_skip
            bits = []
            total_bits_extracted = 0

            bits_per_update = max(1, total_bits // 20)
            last_update = 0

            for y in range(height):
                for x in range(width):
                    if total_bits_extracted >= total_bits:
                        break

                    r, g, b = pixels[x, y][:3]
                    channel_bits = [r & 1, g & 1, b & 1]

                    for bit in channel_bits:
                        if total_bits_extracted < bits_to_skip:
                            total_bits_extracted += 1
                            continue

                        if len(bits) < bits_needed:
                            bits.append(str(bit))
                            total_bits_extracted += 1
                        else:
                            break

                    if len(bits) >= bits_needed:
                        break

                    # Прогресс
                    if progress_callback and (total_bits_extracted - last_update) >= bits_per_update:
                        progress = total_bits_extracted / total_bits
                        progress_callback(min(0.99, progress), f"Extracting... {int(progress * 100)}%")
                        last_update = total_bits_extracted

            if len(bits) < bits_needed:
                return None

            # Convert bits to bytes
            byte_data = bytearray()
            for i in range(0, len(bits), 8):
                if i + 8 <= len(bits):
                    byte_bits = ''.join(bits[i:i+8])
                    try:
                        byte_data.append(int(byte_bits, 2))
                    except ValueError:
                        continue

            return bytes(byte_data)
            
        except Exception as e:
            self.logger.error(f"LSB extraction progress error: {e}")
            return None


    def _extract_lsb_improved(self, pixels, width: int, height: int, data_size: int, offset: int = 0) -> bytes:
        """Improved LSB extraction with data integrity check"""
        try:
            # Извлекаем данные с контрольной суммой
            total_size_to_extract = 4 + data_size  # 4 байта hash + данные
            bits_needed = total_size_to_extract * 8
            
            self.logger.info(f"Extracting {total_size_to_extract} bytes ({bits_needed} bits) with integrity check")
            
            bits = []
            extracted_bits = 0
            
            for y in range(height):
                for x in range(width):
                    if extracted_bits >= bits_needed:
                        break
                    
                    r, g, b = pixels[x, y][:3]
                    
                    # Extract LSB from each color channel
                    if extracted_bits < bits_needed:
                        bits.append(str(r & 1))
                        extracted_bits += 1
                    if extracted_bits < bits_needed:
                        bits.append(str(g & 1))
                        extracted_bits += 1
                    if extracted_bits < bits_needed:
                        bits.append(str(b & 1))
                        extracted_bits += 1
            
            self.logger.info(f"Extracted {extracted_bits} bits, needed {bits_needed}")
            
            if extracted_bits < bits_needed:
                self.logger.warning(f"Not enough bits extracted: {extracted_bits} < {bits_needed}")
                return None
            
            # Convert bits to bytes
            byte_data = bytearray()
            for i in range(0, len(bits), 8):
                if i + 8 <= len(bits):
                    byte_bits = ''.join(bits[i:i+8])
                    try:
                        byte_data.append(int(byte_bits, 2))
                    except ValueError:
                        self.logger.error(f"Invalid bit sequence at position {i}")
                        continue
            
            extracted_data = bytes(byte_data[:total_size_to_extract])
            
            # Проверяем целостность данных
            if len(extracted_data) >= 5:  # Минимум hash + 1 байт данных
                extracted_hash = extracted_data[:4]
                actual_data = extracted_data[4:4 + data_size]
                
                # Вычисляем хеш извлеченных данных
                computed_hash = hashlib.sha256(actual_data).digest()[:4]
                
                if extracted_hash == computed_hash:
                    self.logger.info("✓ Data integrity verified")
                    return actual_data
                else:
                    self.logger.error("✗ Data integrity check failed")
                    self.logger.error(f"Expected hash: {extracted_hash.hex()}")
                    self.logger.error(f"Computed hash: {computed_hash.hex()}")
                    return None
            else:
                self.logger.error("Extracted data too short for integrity check")
                return None
            
        except Exception as e:
            self.logger.error(f"LSB extraction error: {e}")
            return None

    def _hide_lsb(self, pixels, width: int, height: int, data: bytes):
        """Hide data using basic LSB method"""
        data_bits = ''.join(format(byte, '08b') for byte in data)
        data_index = 0
        
        for y in range(height):
            for x in range(width):
                if data_index >= len(data_bits):
                    return
                
                r, g, b = pixels[x, y][:3]
                
                # Modify LSB of each color channel
                if data_index < len(data_bits):
                    r = (r & 0xFE) | int(data_bits[data_index])
                    data_index += 1
                if data_index < len(data_bits):
                    g = (g & 0xFE) | int(data_bits[data_index])
                    data_index += 1
                if data_index < len(data_bits):
                    b = (b & 0xFE) | int(data_bits[data_index])
                    data_index += 1
                
                pixels[x, y] = (r, g, b)
    
    def _hide_lsb_enhanced(self, pixels, width: int, height: int, data: bytes):
        """Enhanced LSB with better distribution"""
        data_bits = ''.join(format(byte, '08b') for byte in data)
        data_index = 0
        
        # Use a simple pattern to distribute bits
        for y in range(0, height, 2):
            for x in range(0, width, 2):
                if data_index >= len(data_bits):
                    return
                
                # Modify pixels in 2x2 blocks
                for dy in range(2):
                    for dx in range(2):
                        if y + dy < height and x + dx < width:
                            if data_index >= len(data_bits):
                                return
                            
                            r, g, b = pixels[x + dx, y + dy][:3]
                            
                            # Modify only one channel per pixel for better stealth
                            if (x + dx + y + dy) % 3 == 0:  # Red channel
                                r = (r & 0xFE) | int(data_bits[data_index])
                            elif (x + dx + y + dy) % 3 == 1:  # Green channel
                                g = (g & 0xFE) | int(data_bits[data_index])
                            else:  # Blue channel
                                b = (b & 0xFE) | int(data_bits[data_index])
                            
                            pixels[x + dx, y + dy] = (r, g, b)
                            data_index += 1
    
    def _extract_lsb(self, pixels, width: int, height: int, data_size: int, offset: int = 0) -> bytes:
        """Extract data using LSB method"""
        bits = []
        bytes_needed = data_size
        bits_needed = bytes_needed * 8
        
        bit_count = 0
        for y in range(height):
            for x in range(width):
                if bit_count >= bits_needed + offset * 8:
                    break
                
                r, g, b = pixels[x, y][:3]
                
                # Skip offset bytes
                if bit_count < offset * 8:
                    bit_count += 3
                    continue
                
                # Extract LSB from each channel
                bits.append(str(r & 1))
                bit_count += 1
                if bit_count >= bits_needed + offset * 8:
                    break
                    
                bits.append(str(g & 1))
                bit_count += 1
                if bit_count >= bits_needed + offset * 8:
                    break
                    
                bits.append(str(b & 1))
                bit_count += 1
                if bit_count >= bits_needed + offset * 8:
                    break
        
        # Convert bits to bytes
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_bits = ''.join(bits[i:i+8])
                byte_data.append(int(byte_bits, 2))
        
        return bytes(byte_data[:data_size])
    
    def _extract_lsb_enhanced(self, pixels, width: int, height: int, data_size: int, offset: int = 0) -> bytes:
        """Extract data using enhanced LSB method"""
        bits = []
        bytes_needed = data_size
        bits_needed = bytes_needed * 8
        
        bit_count = 0
        for y in range(0, height, 2):
            for x in range(0, width, 2):
                if bit_count >= bits_needed + offset * 8:
                    break
                
                for dy in range(2):
                    for dx in range(2):
                        if y + dy < height and x + dx < width:
                            if bit_count >= bits_needed + offset * 8:
                                break
                            
                            # Skip offset bytes
                            if bit_count < offset * 8:
                                bit_count += 1
                                continue
                            
                            r, g, b = pixels[x + dx, y + dy][:3]
                            
                            # Extract from the same channel used for hiding
                            if (x + dx + y + dy) % 3 == 0:  # Red channel
                                bits.append(str(r & 1))
                            elif (x + dx + y + dy) % 3 == 1:  # Green channel
                                bits.append(str(g & 1))
                            else:  # Blue channel
                                bits.append(str(b & 1))
                            
                            bit_count += 1
        
        # Convert bits to bytes
        byte_data = bytearray()
        for i in range(0, len(bits), 8):
            if i + 8 <= len(bits):
                byte_bits = ''.join(bits[i:i+8])
                byte_data.append(int(byte_bits, 2))
        
        return bytes(byte_data[:data_size])
    
    def _create_data_header(self, data: bytes, method: str, encrypted: bool, compressed: bool = False) -> bytes:
        """Create header with compression flag"""
        magic = b'STEGO'
        data_size = len(data).to_bytes(4, 'big')
        method_byte = method.encode('ascii').ljust(10, b'\x00')[:10]
        encrypted_byte = b'\x01' if encrypted else b'\x00'
        compressed_byte = b'\x01' if compressed else b'\x00'
        reserved = b'\x00' * 39  # теперь 39 байт (было 40)
        data_hash = hashlib.sha256(data).digest()[:4]

        return magic + data_size + method_byte + encrypted_byte + compressed_byte + reserved + data_hash


    def _parse_data_header(self, header_data: bytes) -> Optional[Dict[str, Any]]:
        if len(header_data) < 64:
            return None
        if header_data[:5] != b'STEGO':
            return None

        data_size = int.from_bytes(header_data[5:9], 'big')
        method = header_data[9:19].rstrip(b'\x00').decode('ascii', errors='ignore')
        encrypted = header_data[19] == 1
        compressed = header_data[20] == 1  # ← читаем сжатие
        data_hash = header_data[60:64]

        return {
            'data_size': data_size,
            'method': method,
            'encrypted': encrypted,
            'compressed': compressed,
            'data_hash': data_hash
        }

    
    def _calculate_max_image_capacity(self, image_path: str, method: str) -> int:
        """Calculate maximum data capacity for image"""
        try:
            with Image.open(image_path) as img:
                width, height = img.size
                
                if method == 'lsb':
                    # 3 bits per pixel (RGB)
                    total_bits = width * height * 3
                elif method == 'lsb_enhanced':
                    # 1 bit per pixel in 2x2 blocks
                    total_bits = (width * height) // 4
                else:
                    total_bits = width * height * 3  # Default to basic LSB
                
                # Subtract header size (64 bytes = 512 bits)
                available_bits = total_bits - 512
                return max(0, available_bits // 8)
                
        except Exception as e:
            self.logger.error(f"Capacity calculation error: {e}")
            return 0
    
    def hide_in_audio(self, data: bytes, carrier_path: str, output_path: str,
                     password: Optional[str] = None) -> Dict[str, Any]:
        """Hide data in audio file (WAV format)"""
        try:
            if not os.path.exists(carrier_path):
                return {"success": False, "error": "Carrier file not found"}
            
            # Encrypt data if password provided
            if password and self.crypto_engine:
                encrypted_data = self.crypto_engine.encrypt_text(data.decode('utf-8'), password, 'fernet')
                data_to_hide = encrypted_data.encode('utf-8')
            else:
                data_to_hide = data
            
            with wave.open(carrier_path, 'rb') as carrier:
                params = carrier.getparams()
                frames = carrier.readframes(params.nframes)
                
                # Check capacity
                max_capacity = len(frames) // 8  # 1 bit per sample
                if len(data_to_hide) > max_capacity:
                    return {
                        "success": False,
                        "error": f"Data too large. Max: {max_capacity}, Got: {len(data_to_hide)}"
                    }
                
                # Convert frames to bytearray for modification
                frame_bytes = bytearray(frames)
                data_bits = ''.join(format(byte, '08b') for byte in data_to_hide)
                
                # Hide data in LSB of audio samples
                data_index = 0
                for i in range(0, len(frame_bytes), 2):  # 16-bit samples
                    if data_index >= len(data_bits):
                        break
                    
                    # Modify LSB of the sample
                    sample = int.from_bytes(frame_bytes[i:i+2], 'little', signed=True)
                    sample = (sample & 0xFFFE) | int(data_bits[data_index])
                    frame_bytes[i:i+2] = sample.to_bytes(2, 'little', signed=True)
                    data_index += 1
                
                # Write modified audio
                with wave.open(output_path, 'wb') as output:
                    output.setparams(params)
                    output.writeframes(bytes(frame_bytes))
                
                return {
                    "success": True,
                    "output_path": output_path,
                    "data_size": len(data),
                    "hidden_size": len(data_to_hide),
                    "encrypted": password is not None
                }
                
        except Exception as e:
            self.logger.error(f"Audio steganography error: {e}")
            return {"success": False, "error": str(e)}
    
    def extract_from_audio(self, stego_path: str, output_path: str,
                        password: Optional[str] = None) -> Dict[str, Any]:
        """Extract hidden data from audio file"""
        try:
            if not os.path.exists(stego_path):
                return {"success": False, "error": "Stego file not found"}
            
            with wave.open(stego_path, 'rb') as stego:
                params = stego.getparams()
                frames = stego.readframes(params.nframes)
                
                # Extract bits from LSB of audio samples
                bits = []
                for i in range(0, len(frames), 2):
                    if len(bits) >= 8 * 1024 * 1024:  # Limit extraction to 1MB
                        break
                    
                    sample = int.from_bytes(frames[i:i+2], 'little', signed=True)
                    bits.append(str(sample & 1))
                
                # Convert bits to bytes
                extracted_data = bytearray()
                for i in range(0, len(bits), 8):
                    if i + 8 <= len(bits):
                        byte_bits = ''.join(bits[i:i+8])
                        extracted_data.append(int(byte_bits, 2))
                
                # Для аудио нет заголовка, поэтому пробуем оба варианта
                # Сначала пытаемся расшифровать если есть пароль
                decryption_attempted = False
                if password and self.crypto_engine:
                    try:
                        # Пытаемся расшифровать как текст
                        decrypted_text = self.crypto_engine.decrypt_text(
                            extracted_data.decode('utf-8'), password, 'fernet'
                        )
                        extracted_data = decrypted_text.encode('utf-8')
                        decryption_attempted = True
                    except (UnicodeDecodeError, Exception):
                        # Если не получилось - оставляем как есть
                        pass
                
                # Сохраняем извлеченные данные
                with open(output_path, 'wb') as f:
                    f.write(extracted_data)
                
                return {
                    "success": True,
                    "output_path": output_path,
                    "data_size": len(extracted_data),
                    "encrypted": decryption_attempted
                }
                
        except Exception as e:
            self.logger.error(f"Audio extraction error: {e}")
            return {"success": False, "error": str(e)}
    
    def analyze_stego_file(self, file_path: str) -> Dict[str, Any]:
        """Analyze file for potential steganography - FIXED RETURN FORMAT"""
        try:
            if not os.path.exists(file_path):
                return {
                    "file_type": "unknown",
                    "file_size": 0,
                    "potential_stego": False,
                    "confidence": 0,
                    "methods": [],
                    "notes": ["File not found"],
                    "analysis_complete": False
                }
            
            file_ext = file_path.lower().split('.')[-1]
            analysis_result = {
                "file_type": file_ext,
                "file_size": os.path.getsize(file_path),
                "potential_stego": False,
                "confidence": 0,
                "methods": [],
                "notes": [],
                "analysis_complete": True
            }
            
            if file_ext in self.supported_formats['image']:
                return self._analyze_image_stego(file_path, analysis_result)
            elif file_ext in self.supported_formats['audio']:
                return self._analyze_audio_stego(file_path, analysis_result)
            else:
                analysis_result["notes"].append("File type not supported for stego analysis")
                return analysis_result
                
        except Exception as e:
            self.logger.error(f"Stego analysis error: {e}")
            return {
                "file_type": "unknown", 
                "file_size": 0,
                "potential_stego": False,
                "confidence": 0,
                "methods": [],
                "notes": [f"Analysis error: {str(e)}"],
                "analysis_complete": False
            }
    
    def _analyze_image_stego(self, file_path: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze image for steganography - FIXED"""
        try:
            with Image.open(file_path) as img:
                if img.mode not in ['RGB', 'RGBA']:
                    img = img.convert('RGB')
                
                pixels = img.load()
                width, height = img.size
                
                analysis["image_dimensions"] = f"{width}x{height}"
                analysis["color_mode"] = img.mode
                
                # Проверяем наличие заголовка стеганографии
                header_data = self._extract_lsb_simple(pixels, width, height, 5)  # Только magic bytes
                if header_data and header_data == b'STEGO':
                    analysis["potential_stego"] = True
                    analysis["confidence"] = 95
                    analysis["methods"].append("CryptoZ LSB Steganography")
                    analysis["notes"].append("CryptoZ signature detected - file contains hidden data")
                    
                    # Пытаемся извлечь полный заголовок для дополнительной информации
                    full_header = self._extract_lsb_simple(pixels, width, height, 64)
                    if full_header:
                        header = self._parse_data_header(full_header)
                        if header:
                            analysis["detected_data_size"] = header.get('data_size', 0)
                            analysis["detected_method"] = header.get('method', 'unknown')
                            analysis["is_encrypted"] = header.get('encrypted', False)
                            
                            if analysis["is_encrypted"]:
                                analysis["notes"].append("Hidden data is encrypted")
                            else:
                                analysis["notes"].append("Hidden data is not encrypted")
                
                # Если не нашли сигнатуру CryptoZ, проверяем общие LSB паттерны
                else:
                    lsb_analysis = self._analyze_lsb_pattern(pixels, width, height)
                    if lsb_analysis["suspicious"]:
                        analysis["potential_stego"] = True
                        analysis["confidence"] = lsb_analysis["confidence"]
                        analysis["methods"].append("Generic LSB Steganography")
                        analysis["notes"].append("Suspicious LSB patterns detected")
                    else:
                        analysis["notes"].append("No steganography signatures detected")
                
                return analysis
                
        except Exception as e:
            analysis["notes"].append(f"Image analysis error: {str(e)}")
            analysis["analysis_complete"] = False
            return analysis
    
    def _analyze_lsb_pattern(self, pixels, width: int, height: int) -> Dict[str, Any]:
        """Analyze LSB patterns for steganography detection"""
        lsb_count = 0
        total_pixels = width * height
        
        # Sample analysis on first 10000 pixels
        sample_size = min(10000, total_pixels)
        sample_count = 0
        
        for y in range(min(100, height)):
            for x in range(min(100, width)):
                if sample_count >= sample_size:
                    break
                
                r, g, b = pixels[x, y][:3]
                lsb_count += (r & 1) + (g & 1) + (b & 1)
                sample_count += 1
        
        # Calculate LSB distribution
        lsb_ratio = lsb_count / (sample_count * 3)
        
        # In natural images, LSB should be roughly 50% 0s and 50% 1s
        deviation = abs(lsb_ratio - 0.5)
        
        result = {
            "suspicious": deviation > 0.1,  # More than 10% deviation
            "confidence": min(100, int(deviation * 200)),  # Scale to 0-100
            "notes": [f"LSB distribution: {lsb_ratio:.3f} (deviation: {deviation:.3f})"]
        }
        
        if result["suspicious"]:
            result["notes"].append("Unusual LSB pattern detected - potential steganography")
        
        return result
    
    def _analyze_audio_stego(self, file_path: str, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze audio file for steganography"""
        try:
            with wave.open(file_path, 'rb') as audio:
                params = audio.getparams()
                frames = audio.readframes(min(params.nframes, 44100))  # First second
                
                # Analyze LSB patterns in audio samples
                lsb_count = 0
                total_samples = len(frames) // 2
                
                for i in range(0, len(frames), 2):
                    sample = int.from_bytes(frames[i:i+2], 'little', signed=True)
                    lsb_count += sample & 1
                
                lsb_ratio = lsb_count / total_samples
                deviation = abs(lsb_ratio - 0.5)
                
                if deviation > 0.1:
                    analysis["potential_stego"] = True
                    analysis["confidence"] = min(100, int(deviation * 200))
                    analysis["methods"].append("Audio LSB Steganography")
                    analysis["notes"].append(f"Unusual audio LSB pattern: {lsb_ratio:.3f}")
                
                return analysis
                
        except Exception as e:
            analysis["notes"].append(f"Audio analysis error: {str(e)}")
            return analysis