from datetime import datetime
from tkinter import Image
import dearpygui.dearpygui as dpg
import os
import threading
import time
import json
import logging
import sys
from typing import Optional, Dict, Any, Callable, List
from pathlib import Path

from core.crypto_engine import CryptoEngine
from core.security_utils import SecurityUtils
from core.code_analyzer import CodeAnalyzer
from config.settings import AppSettings
from core.policy_manager import PolicyManager
from core.steganography_engine import SteganographyEngine


class OperationManager:
    """Manager for background operations with improved threading"""
    
    def __init__(self):
        self._operations: Dict[str, threading.Thread] = {}
        self._results: Dict[str, Any] = {}
        self._lock = threading.RLock()
        self._logger = logging.getLogger(__name__)
    
    def start_operation(self, op_id: str, target: Callable, 
                       args: tuple = (), kwargs: Dict = None) -> bool:
        """Start a background operation"""
        if kwargs is None:
            kwargs = {}
        
        with self._lock:
            if op_id in self._operations:
                self._logger.warning(f"Operation {op_id} already running")
                return False
            
            def wrapped_target():
                try:
                    result = target(*args, **kwargs)
                    with self._lock:
                        self._results[op_id] = ('success', result)
                except Exception as e:
                    with self._lock:
                        self._results[op_id] = ('error', str(e))
                    self._logger.error(f"Operation {op_id} failed: {e}")
                finally:
                    with self._lock:
                        if op_id in self._operations:
                            del self._operations[op_id]
            
            thread = threading.Thread(target=wrapped_target, daemon=True)
            self._operations[op_id] = thread
            thread.start()
            return True
    
    def get_result(self, op_id: str) -> Optional[tuple]:
        """Get operation result if available"""
        with self._lock:
            return self._results.pop(op_id, None)
    
    def is_running(self, op_id: str) -> bool:
        """Check if operation is running"""
        with self._lock:
            return op_id in self._operations
    
    def stop_operation(self, op_id: str) -> bool:
        """Stop a running operation"""
        with self._lock:
            if op_id in self._operations:
                del self._operations[op_id]
                if op_id in self._results:
                    del self._results[op_id]
                return True
            return False
    
    def stop_all(self):
        """Stop all operations"""
        with self._lock:
            self._operations.clear()
            self._results.clear()


class FileDialogHandler:
    """File dialog handling for Dear PyGui with automatic format detection"""
    
    def __init__(self, main_window):
        self.main_window = main_window
        self.current_target = None
    
    def show_open_dialog(self, target: str):
        """Show file open dialog"""
        self.current_target = target
        
        def file_callback(sender, app_data):
            self._handle_file_selection(app_data)
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=file_callback,
            width=700, 
            height=400
        ):
            dpg.add_file_extension("All Files (*.*){.*}")
            dpg.add_file_extension("Encrypted Files (*.encrypted){.encrypted}")
            dpg.add_file_extension("Text Files (*.txt){.txt}")
            dpg.add_file_extension("Python Files (*.py){.py}")
            dpg.add_file_extension("CSV Files (*.csv){.csv}")
            dpg.add_file_extension("PDF Files (*.pdf){.pdf}")
            dpg.add_file_extension("")
    
    def show_save_dialog(self, target: str):
        """Show file save dialog for DPG 2.1"""
        self.current_target = target
        
        def file_callback(sender, app_data):
            self._handle_save_selection(app_data)
        
        with dpg.file_dialog(
            directory_selector=False, 
            show=True,
            callback=file_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension("All Files (*.*){.*}")
            dpg.add_file_extension("Encrypted Files (*.encrypted){.encrypted}")
            dpg.add_file_extension("Decrypted Files (*.decrypted){.decrypted}")
            dpg.add_file_extension("")
    
    def _handle_file_selection(self, app_data):
        """Handle file selection from dialog with automatic format detection"""
        try:
            print(f"DEBUG: File dialog data: {app_data}")
            
            if not app_data:
                self.main_window.log_message("File selection cancelled", "file")
                return
            
            file_path = None
            
            if 'file_path_name' in app_data:
                file_path = app_data['file_path_name']
            elif 'selections' in app_data and app_data['selections']:
                file_path = list(app_data['selections'].values())[0]
            elif 'current_path' in app_data:
                file_path = app_data['current_path']
            
            if file_path and self._validate_file_path(file_path):
                self._process_file_selection(file_path)
            else:
                self.main_window.log_message("Invalid file selected or no file selected", "file")
                
        except Exception as e:
            logging.error(f"File selection error: {e}")
            self.main_window.log_message(f"File selection error: {str(e)}", "file")
    
    def _handle_save_selection(self, app_data):
        """Handle save file selection"""
        try:
            print(f"DEBUG: Save dialog data: {app_data}")
            
            if not app_data:
                self.main_window.log_message("Save cancelled", "file")
                return
            
            file_path = None
            
            if 'file_path_name' in app_data:
                file_path = app_data['file_path_name']
            elif 'current_path' in app_data:
                file_path = app_data['current_path']
            
            if file_path:
                self._process_save_selection(file_path)
            else:
                self.main_window.log_message("No file path specified", "file")
            
        except Exception as e:
            logging.error(f"Save selection error: {e}")
            self.main_window.log_message(f"Save error: {str(e)}", "file")
    
    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path"""
        try:
            if not file_path or not isinstance(file_path, str):
                return False
            
            if os.path.isdir(file_path):
                return False
            
            if '..' in file_path:
                return False
            
            if not os.path.exists(file_path):
                return False
            
            if not os.access(file_path, os.R_OK):
                return False
            
            return True
            
        except Exception:
            return False
    
    def _process_file_selection(self, file_path: str):
        """Process selected file with automatic output naming and operation detection"""
        try:
            target = self.current_target
            file_name = os.path.basename(file_path)
            
            if target == "file_input":
                dpg.set_value("file_input_path", file_path)
                
                output_path = self._generate_output_filename(file_path)
                dpg.set_value("file_output_path", output_path)
                
                self.main_window._update_operation_buttons(file_path)
                
                self.main_window.log_message(f"Selected input file: {file_name}", "file")
                self.main_window.log_message(f"Auto-generated output: {os.path.basename(output_path)}", "file")
            
            elif target == "analyzer_input":
                dpg.set_value("analyzer_file_path", file_path)
                self.main_window.log_message(f"Selected file for analysis: {file_name}", "analyzer")
                
        except Exception as e:
            logging.error(f"File processing error: {e}")
            self.main_window.log_message(f"Error processing file: {str(e)}", "file")
    
    def _generate_output_filename(self, input_path: str) -> str:
        """Generate output filename based on input file extension"""
        input_path_obj = Path(input_path)
        
        current_extension = input_path_obj.suffix.lower()

        if current_extension == '.encrypted':
            output_extension = '.decrypted'
        else:
            output_extension = self.main_window.settings.get(
                "files.default_output_extension", ".encrypted"
            )
        
        output_path = input_path_obj.with_suffix(output_extension)
        
        counter = 1
        original_output_path = output_path
        
        while output_path.exists():
            new_name = f"{input_path_obj.stem}_{counter}{output_extension}"
            output_path = input_path_obj.with_name(new_name)
            counter += 1
            
            if counter > 100:
                break
        
        return str(output_path)
    
    def _process_save_selection(self, file_path: str):
        """Process save file selection"""
        try:
            if self.current_target == "file_output":
                dpg.set_value("file_output_path", file_path)
                file_name = os.path.basename(file_path)
                self.main_window.log_message(f"Set output file: {file_name}", "file")
                
        except Exception as e:
            logging.error(f"Save processing error: {e}")
            self.main_window.log_message(f"Error setting output file: {str(e)}", "file")


class MainWindow:
    """Main application window for Dear PyGui 2.1"""
    
    def __init__(self):
        self.settings = AppSettings()
        self.crypto_engine = CryptoEngine(self.settings)
        self.security_utils = SecurityUtils()
        self.code_analyzer = CodeAnalyzer()
        self.policy_manager = PolicyManager(self.crypto_engine, self.settings)
        self.steganography_engine = SteganographyEngine(self.crypto_engine)
        
        # Enhanced operation management
        self.operation_manager = OperationManager()
        self.file_dialog_handler = FileDialogHandler(self)
        
        # UI state
        self._ui_initialized = False
        
        self.setup_gui()
    
    def setup_gui(self):
        """Setup Dear PyGui interface"""
        try:
            dpg.create_context()
            self._setup_theming()
            self._create_main_window()
            self._setup_viewport()
            
            self._ui_initialized = True
            logging.info("Application initialized successfully")
            
        except Exception as e:
            logging.error(f"GUI setup failed: {e}")
            raise
    
    def _setup_theming(self):
        """Setup application theming"""
        with dpg.theme() as main_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (40, 40, 40, 255))
                dpg.add_theme_color(dpg.mvThemeCol_Button, (60, 60, 80, 255))
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (80, 80, 100, 255))
        
        dpg.bind_theme(main_theme)
    
    def _create_main_window(self):
        """Create main application window"""
        with dpg.window(tag="Primary Window", label="CryptoZ - Secure Encryption Tool"):
            self._create_tab_bar()


    def _create_tab_bar(self):
        """Create main tab bar"""
        with dpg.tab_bar() as tab_bar:
            self._create_file_encryption_tab()
            self._create_batch_operations_tab()
            self._create_policy_management_tab()
            self._create_steganography_tab()
            self._create_message_encryption_tab()
            self._create_code_encryption_tab()
            self._create_analyzer_tab()
            self._create_settings_tab()
            self._create_about_tab()
    
    def _create_file_encryption_tab(self):
        """Enhanced file encryption tab with auto-naming"""
        with dpg.tab(label="File Encryption"):
            # File selection section
            with dpg.group(horizontal=True):
                dpg.add_text("Input File:")
                dpg.add_input_text(
                    tag="file_input_path", 
                    width=400, 
                    readonly=True,
                    hint="Select input file...",
                    callback=self._on_input_file_change
                )
                dpg.add_button(
                    label="Browse", 
                    callback=lambda: self.file_dialog_handler.show_open_dialog("file_input")
                )
            
            with dpg.group(horizontal=True):
                dpg.add_text("Output File:")
                dpg.add_input_text(
                    tag="file_output_path", 
                    width=400,
                    hint="Specify output file path..."
                )
                dpg.add_button(
                    label="Browse", 
                    callback=lambda: self.file_dialog_handler.show_save_dialog("file_output")
                )
            
            # Algorithm selection
            with dpg.group(horizontal=True):
                dpg.add_text("Algorithm:")
                dpg.add_combo(
                    items=list(self.crypto_engine.get_available_algorithms().keys()),
                    default_value=self.settings.get("security.default_algorithm", "fernet"),
                    tag="file_algorithm",
                    width=150,
                    callback=self._on_algorithm_change
                )
                dpg.add_text("", tag="file_algorithm_desc", wrap=400)
            
            self._on_algorithm_change()  # Initial description
            
            # Password section
            self._create_password_section("file")
            
            # Operation buttons
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Encrypt File", 
                    callback=self._encrypt_file,
                    tag="encrypt_file_btn"
                )
                dpg.add_button(
                    label="Decrypt File", 
                    callback=self._decrypt_file,
                    tag="decrypt_file_btn"
                )
                dpg.add_button(
                    label="Clear All", 
                    callback=self._clear_file_fields
                )
            
            # Progress indicator
            with dpg.group(horizontal=True):
                dpg.add_text("Status:")
                dpg.add_text("Ready", tag="file_status", color=[0, 200, 0])
                dpg.add_progress_bar(
                    tag="file_progress", 
                    show=False,
                    width=200
                )
            
            # Log
            with dpg.group(horizontal=True):
                dpg.add_text("Operation Log:")
                dpg.add_button(
                    label="Copy", 
                    callback=lambda: self._copy_to_clipboard("file_log"),
                    width=80
                )
                dpg.add_button(
                    label="Clear", 
                    callback=lambda: dpg.set_value("file_log", ""),
                    width=80
                )
            
            dpg.add_input_text(
                tag="file_log",
                multiline=True,
                height=150,
                readonly=True,
                width=-1
            )

    def _auto_detect_operation(self, file_path: str) -> str:
        """Auto-detect if we should encrypt or decrypt based on file extension"""
        file_ext = Path(file_path).suffix.lower()
        
        if file_ext == '.encrypted':
            return 'decrypt'
        elif file_ext == '.decrypted':
            return 'encrypt'
        else:
            return 'encrypt'

    def _update_operation_buttons(self, file_path: str):
        """Update button states based on file type"""
        operation = self._auto_detect_operation(file_path)
        
        if operation == 'decrypt':
            dpg.configure_item("decrypt_file_btn", enabled=True)
            self.log_message("Detected encrypted file - ready for decryption", "file")
        else:
            dpg.configure_item("encrypt_file_btn", enabled=True)
            self.log_message("Detected regular file - ready for encryption", "file")
    
    def _create_password_section(self, prefix: str):
        """Create password input section"""
        with dpg.group(horizontal=True):
            dpg.add_text("Password:")
            dpg.add_input_text(
                tag=f"{prefix}_password",
                password=True,
                width=200,
                hint="Enter secure password...",
                callback=lambda: self._on_password_change(prefix)
            )
            dpg.add_button(
                label="Generate", 
                callback=getattr(self, f"_generate_{prefix}_password")
            )
            dpg.add_button(
                label="Copy", 
                callback=getattr(self, f"_copy_{prefix}_password")
            )
            dpg.add_checkbox(
                label="Show", 
                tag=f"{prefix}_show_password",
                callback=getattr(self, f"_toggle_{prefix}_password_visibility")
            )
        
        # Password confirmation for file operations
        if prefix == "file":
            with dpg.group(horizontal=True):
                dpg.add_text("Confirm:")
                dpg.add_input_text(
                    tag="file_confirm_password",
                    password=True,
                    width=200,
                    hint="Confirm password..."
                )
        
        # Password strength indicator
        dpg.add_text(
            "Password Strength: Not rated", 
            tag=f"{prefix}_password_strength"
        )
    
    def _create_message_encryption_tab(self):
        """Create message encryption tab"""
        with dpg.tab(label="Message Encryption"):
            # Algorithm selection
            with dpg.group(horizontal=True):
                dpg.add_text("Algorithm:")
                dpg.add_combo(
                    items=list(self.crypto_engine.get_available_algorithms().keys()),
                    default_value=self.settings.get("security.default_algorithm", "fernet"),
                    tag="message_algorithm",
                    width=150
                )
            
            # Input message
            dpg.add_text("Input Message:")
            dpg.add_input_text(
                tag="message_input",
                multiline=True,
                height=100,
                width=-1,
                hint="Enter message to encrypt/decrypt..."
            )
            
            # Password section
            self._create_password_section("message")
            
            # Operation buttons
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Encrypt Message", 
                    callback=self._encrypt_message
                )
                dpg.add_button(
                    label="Decrypt Message", 
                    callback=self._decrypt_message
                )
                dpg.add_button(
                    label="Clear", 
                    callback=self._clear_message_fields
                )
            
            # Output message
            dpg.add_text("Output Message:")
            dpg.add_input_text(
                tag="message_output",
                multiline=True,
                height=100,
                readonly=True,
                width=-1
            )
    
    def _create_code_encryption_tab(self):
        """Create code encryption tab"""
        with dpg.tab(label="Code Encryption"):
            # Method selection
            with dpg.group(horizontal=True):
                dpg.add_text("Encryption Method:")
                dpg.add_combo(
                    items=["obfuscate", "base64", "xor"],
                    default_value="obfuscate",
                    tag="code_method",
                    width=100
                )
            
            # Password section
            self._create_password_section("code")
            
            # Position selection
            with dpg.group(horizontal=True):
                dpg.add_text("Start Position:")
                dpg.add_input_text(tag="code_start", width=80, default_value="0")
                dpg.add_text("End Position:")
                dpg.add_input_text(tag="code_end", width=80)
                dpg.add_button(
                    label="Auto Select", 
                    callback=self._auto_select_code
                )
            
            # Input code
            dpg.add_text("Source Code:")
            dpg.add_input_text(
                tag="code_input",
                multiline=True,
                height=150,
                width=-1,
                hint="Enter source code to encrypt..."
            )
            
            # Operation buttons
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Encrypt Selected", 
                    callback=self._encrypt_selected_code
                )
                dpg.add_button(
                    label="Decrypt All", 
                    callback=self._decrypt_all_code
                )
                dpg.add_button(
                    label="Clear", 
                    callback=self._clear_code_fields
                )
            
            # Output code
            dpg.add_text("Result:")
            dpg.add_input_text(
                tag="code_output",
                multiline=True,
                height=150,
                readonly=True,
                width=-1
            )
    
    def _create_analyzer_tab(self):
        """Create file analyzer tab"""
        with dpg.tab(label="File Analyzer"):
            # File selection
            with dpg.group(horizontal=True):
                dpg.add_text("File to Analyze:")
                dpg.add_input_text(
                    tag="analyzer_file_path", 
                    width=400, 
                    readonly=True,
                    hint="Select file to analyze..."
                )
                dpg.add_button(
                    label="Browse", 
                    callback=lambda: self.file_dialog_handler.show_open_dialog("analyzer_input")
                )
            
            dpg.add_button(
                label="Analyze File", 
                callback=self._analyze_file
            )
            
            # Results
            dpg.add_text("Analysis Results:")
            dpg.add_input_text(
                tag="analyzer_results",
                multiline=True,
                height=200,
                readonly=True,
                width=-1
            )
    
    def _create_settings_tab(self):
        """Create settings tab"""
        with dpg.tab(label="Settings"):
            dpg.add_text("Application Settings", color=[0, 200, 255])
            dpg.add_separator()
            
            # Security settings
            with dpg.collapsing_header(label="Security Settings"):
                dpg.add_input_int(
                    label="Key Derivation Iterations",
                    default_value=self.settings.get("security.key_derivation_iterations", 310000),
                    min_value=1000,
                    max_value=1000000,
                    tag="setting_iterations",
                    callback=lambda s, d: self.settings.set("security.key_derivation_iterations", d)
                )
                dpg.add_input_int(
                    label="Default Password Length",
                    default_value=self.settings.get("security.password_length", 16),
                    min_value=8,
                    max_value=128,
                    tag="setting_password_length",
                    callback=lambda s, d: self.settings.set("security.password_length", d)
                )
            
            # Settings actions
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Save Settings",
                    callback=self._save_settings
                )
                dpg.add_button(
                    label="Reset to Defaults",
                    callback=self._reset_settings
                )
    
    def _create_about_tab(self):
        """Create about tab"""
        with dpg.tab(label="About"):
            dpg.add_text("CryptoZ - Advanced Encryption Tool", color=[0, 200, 255])
            dpg.add_separator()
            
            dpg.add_text("Description:", color=[200, 200, 0])
            dpg.add_text(
                "CryptoZ is a powerful encryption utility that provides multiple encryption\n"
                "algorithms for files, messages, and source code protection.\n\n"
                
                "Features:\n"
                "- File encryption/decryption with multiple algorithms\n"
                "- Text message encryption\n"
                "- Source code obfuscation and encryption\n"
                "- File encryption detection\n"
                "- Secure password generation\n"
                "- Policy System\n"
                "- Batch Operations (Folder Encryption)\n"
                "- Steganography cryptor and analyzer\n\n"
                
                "Supported Algorithms:\n"
                "- Fernet (AES-128)\n"
                "- AES-CBC (256-bit)\n"
                "- AES-GCM (256-bit)\n"
                "- AES-CTR (256-bit)\n"
                "- ChaCha20\n"
                "- Triple DES\n"
                "- XOR (Basic)\n\n",
                wrap=600
            )
            dpg.add_text(
                "This tool is designed for educational and professional use.\n"
                "Always keep your passwords secure and make backups of important data.", color=[255, 0, 0]),
            
            dpg.add_separator()
            dpg.add_text("Version: 2.1.6S")
            dpg.add_text("Author: FAKEDOWNBOY$ Team", color=[120, 255, 0])
            dpg.add_text("https://github.com/iBenji/CryptoZ.git")
            dpg.add_text("License: MIT Open Source")
    

    def _on_input_file_change(self):
        """Update output filename when input file changes"""
        try:
            input_path = dpg.get_value("file_input_path")
            if input_path and os.path.isfile(input_path):
                # Autogenerate output name
                output_path = self.file_dialog_handler._generate_output_filename(input_path)
                dpg.set_value("file_output_path", output_path)
        except Exception as e:
            logging.error(f"Error updating output filename: {e}")

    # ========== CALLBACK METHODS ========== #
    
    def _on_algorithm_change(self):
        """Update algorithm description""" 
        algorithm = dpg.get_value("file_algorithm")
        if algorithm:
            algo_info = self.crypto_engine.supported_algorithms.get(algorithm, {})
            description = algo_info.get('description', 'Unknown algorithm')
            dpg.set_value("file_algorithm_desc", description)
    
    def _on_password_change(self, prefix: str):
        """Handle password change"""
        password = dpg.get_value(f"{prefix}_password")
        if password:
            strength_info = self.security_utils.password_strength(password)
            strength_text = f"Password Strength: {strength_info['level']} ({strength_info['score']}/6)"
            dpg.set_value(f"{prefix}_password_strength", strength_text)
        else:
            dpg.set_value(f"{prefix}_password_strength", "Password Strength: Not rated")
    
    # ============ File encryption callbacks ============ #
    def _generate_file_password(self):
        """Generate password for file encryption"""
        length = self.settings.get("security.password_length", 16)
        password = self.security_utils.generate_password(length)
        dpg.set_value("file_password", password)
        dpg.set_value("file_confirm_password", password)
        self._on_password_change("file")
        self.log_message("Generated new password", "file")
    
    def _copy_file_password(self):
        """Copy file password to clipboard"""
        password = dpg.get_value("file_password")
        if password:
            dpg.set_clipboard_text(password)
            self.log_message("Password copied to clipboard", "file")
        else:
            self.log_message("No password to copy", "file")
    
    def _toggle_file_password_visibility(self):
        """Toggle password visibility for file tab"""
        show = dpg.get_value("file_show_password")
        dpg.configure_item("file_password", password=not show)
        dpg.configure_item("file_confirm_password", password=not show)
    
    def _encrypt_file(self):
        """File encryption"""
        if not self._validate_file_inputs():
            return
        
        input_path = dpg.get_value("file_input_path")
        output_path = dpg.get_value("file_output_path")
        password = dpg.get_value("file_password")
        algorithm = dpg.get_value("file_algorithm")
        
        try:
            self._set_operation_ui_state(True)
            self.log_message(f"Starting encryption: {os.path.basename(input_path)}", "file")
            
            success = self.crypto_engine.encrypt_file(input_path, output_path, password, algorithm)
            
            if success:
                self.log_message("Encryption completed successfully", "file")
                dpg.set_value("file_status", "Completed")
            else:
                self.log_message("Encryption failed", "file")
                dpg.set_value("file_status", "Failed")
                
        except Exception as e:
            self.log_message(f"Encryption error: {str(e)}", "file")
            dpg.set_value("file_status", "Error")
        finally:
            self._set_operation_ui_state(False)
    
    def _decrypt_file(self):
        """File decryption"""
        if not self._validate_file_inputs():
            return
        
        input_path = dpg.get_value("file_input_path")
        output_path = dpg.get_value("file_output_path")
        password = dpg.get_value("file_password")
        algorithm = dpg.get_value("file_algorithm")
        
        try:
            self._set_operation_ui_state(True)
            self.log_message(f"Starting decryption: {os.path.basename(input_path)}", "file")
            
            success = self.crypto_engine.decrypt_file(input_path, output_path, password, algorithm)
            
            if success:
                self.log_message("Decryption completed successfully", "file")
                dpg.set_value("file_status", "Completed")
            else:
                self.log_message("Decryption failed", "file")
                dpg.set_value("file_status", "Failed")
                
        except Exception as e:
            self.log_message(f"Decryption error: {str(e)}", "file")
            dpg.set_value("file_status", "Error")
        finally:
            self._set_operation_ui_state(False)
    
    def _validate_file_inputs(self) -> bool:
        """Validate file inputs"""
        validators = [
            (dpg.get_value("file_input_path"), "Please select input file"),
            (dpg.get_value("file_output_path"), "Please specify output file path"),
            (dpg.get_value("file_password"), "Please enter password"),
        ]
        
        for value, message in validators:
            if not value:
                self.log_message(message, "file")
                return False
        
        # Password confirmation
        if dpg.get_value("file_password") != dpg.get_value("file_confirm_password"):
            self.log_message("Passwords do not match", "file")
            return False
        
        # File existence
        input_path = dpg.get_value("file_input_path")
        if not os.path.exists(input_path):
            self.log_message("Input file does not exist", "file")
            return False
        
        return True
    
    def _set_operation_ui_state(self, running: bool):
        """Update UI state during operations"""
        if running:
            dpg.configure_item("file_progress", show=True)
            dpg.configure_item("encrypt_file_btn", enabled=False)
            dpg.configure_item("decrypt_file_btn", enabled=False)
            dpg.set_value("file_status", "Processing...")
        else:
            dpg.configure_item("file_progress", show=False)
            dpg.configure_item("encrypt_file_btn", enabled=True)
            dpg.configure_item("decrypt_file_btn", enabled=True)
    
    def _clear_file_fields(self):
        """Clear file encryption fields"""
        # Securely clear passwords first
        password = dpg.get_value("file_password")
        confirm_password = dpg.get_value("file_confirm_password")
        if password:
            self.security_utils.secure_clear(password)
        if confirm_password:
            self.security_utils.secure_clear(confirm_password)
        
        dpg.set_value("file_input_path", "")
        dpg.set_value("file_output_path", "")
        dpg.set_value("file_password", "")
        dpg.set_value("file_confirm_password", "")
        dpg.set_value("file_log", "")
        dpg.set_value("file_password_strength", "Password Strength: Not rated")
        dpg.set_value("file_show_password", False)
        dpg.configure_item("file_password", password=True)
        dpg.configure_item("file_confirm_password", password=True)
        dpg.set_value("file_status", "Ready")
    
    # ============ Message encryption callbacks ============ #
    def _generate_message_password(self):
        """Generate password for message encryption"""
        length = self.settings.get("security.password_length", 16)
        password = self.security_utils.generate_password(length)
        dpg.set_value("message_password", password)
        self._on_password_change("message")
        self.log_message("Generated new password", "message")
    
    def _copy_message_password(self):
        """Copy message password to clipboard"""
        password = dpg.get_value("message_password")
        if password:
            dpg.set_clipboard_text(password)
            self.log_message("Password copied to clipboard", "message")
        else:
            self.log_message("No password to copy", "message")
    
    def _toggle_message_password_visibility(self):
        """Toggle message password visibility"""
        show = dpg.get_value("message_show_password")
        dpg.configure_item("message_password", password=not show)
    
    def _encrypt_message(self):
        """Encrypt message"""
        try:
            message = dpg.get_value("message_input")
            password = dpg.get_value("message_password")
            algorithm = dpg.get_value("message_algorithm")
            
            if not message or not message.strip():
                self.log_message("Enter message to encrypt", "message")
                return
            
            if not password:
                self.log_message("Enter password", "message")
                return
            
            encrypted = self.crypto_engine.encrypt_text(message, password, algorithm)
            dpg.set_value("message_output", encrypted)
            self.log_message("Message encrypted successfully", "message")
            
        except Exception as e:
            self.log_message(f"Encryption error: {str(e)}", "message")
    
    def _decrypt_message(self):
        """Decrypt message"""
        try:
            message = dpg.get_value("message_output")
            password = dpg.get_value("message_password")
            algorithm = dpg.get_value("message_algorithm")
            
            if not message or not message.strip():
                self.log_message("Enter encrypted message", "message")
                return
            
            if not password:
                self.log_message("Enter password", "message")
                return
            
            decrypted = self.crypto_engine.decrypt_text(message, password, algorithm)
            dpg.set_value("message_input", decrypted)
            self.log_message("Message decrypted successfully", "message")
            
        except Exception as e:
            self.log_message(f"Decryption error: {str(e)}", "message")
    
    def _clear_message_fields(self):
        """Clear message encryption fields"""
        dpg.set_value("message_input", "")
        dpg.set_value("message_output", "")
        dpg.set_value("message_password", "")
        dpg.set_value("message_show_password", False)
        dpg.configure_item("message_password", password=True)
        dpg.set_value("message_password_strength", "Password Strength: Not rated")
    
    # ============ Code encryption callbacks ============ #
    def _generate_code_password(self):
        """Generate password for code encryption"""
        length = self.settings.get("security.password_length", 16)
        password = self.security_utils.generate_password(length)
        dpg.set_value("code_password", password)
        self._on_password_change("code")
        self.log_message("Generated new password", "code")
    
    def _copy_code_password(self):
        """Copy code password to clipboard"""
        password = dpg.get_value("code_password")
        if password:
            dpg.set_clipboard_text(password)
            self.log_message("Password copied to clipboard", "code")
        else:
            self.log_message("No password to copy", "code")
    
    def _toggle_code_password_visibility(self):
        """Toggle code password visibility"""
        show = dpg.get_value("code_show_password")
        dpg.configure_item("code_password", password=not show)
    
    def _auto_select_code(self):
        """Auto-select all code"""
        code = dpg.get_value("code_input")
        if code:
            dpg.set_value("code_start", "0")
            dpg.set_value("code_end", str(len(code)))
            self.log_message("All code selected", "code")
    
    def _encrypt_selected_code(self):
        """Encrypt selected code region"""
        try:
            code = dpg.get_value("code_input")
            password = dpg.get_value("code_password")
            method = dpg.get_value("code_method")
            
            start_pos_str = dpg.get_value("code_start")
            end_pos_str = dpg.get_value("code_end")
            
            if not code or not code.strip():
                self.log_message("Enter code to encrypt", "code")
                return
            
            if not password:
                self.log_message("Enter password", "code")
                return
            
            if not start_pos_str or not end_pos_str:
                self.log_message("Enter start and end positions", "code")
                return
            
            start_pos = int(start_pos_str)
            end_pos = int(end_pos_str)
            
            if start_pos >= end_pos:
                self.log_message("Invalid position range", "code")
                return
            
            if end_pos > len(code):
                self.log_message("End position exceeds code length", "code")
                return
            
            encrypted = self.code_analyzer.encrypt_code_region(code, password, start_pos, end_pos, method)
            dpg.set_value("code_output", encrypted)
            self.log_message("Code region encrypted successfully", "code")
            
        except ValueError:
            self.log_message("Invalid position values", "code")
        except Exception as e:
            self.log_message(f"Code encryption error: {str(e)}", "code")
    
    def _decrypt_all_code(self):
        """Decrypt all code"""
        try:
            code = dpg.get_value("code_output")
            password = dpg.get_value("code_password")
            method = dpg.get_value("code_method")
            
            if not code or not code.strip():
                self.log_message("Enter encrypted code", "code")
                return
            
            if not password:
                self.log_message("Enter password", "code")
                return
            
            decrypted = self.code_analyzer.decrypt_code_region(code, password, method)
            dpg.set_value("code_input", decrypted)
            self.log_message("Code decrypted successfully", "code")
            
        except Exception as e:
            self.log_message(f"Code decryption error: {str(e)}", "code")
    
    def _clear_code_fields(self):
        """Clear code encryption fields"""
        dpg.set_value("code_input", "")
        dpg.set_value("code_output", "")
        dpg.set_value("code_password", "")
        dpg.set_value("code_start", "0")
        dpg.set_value("code_end", "")
        dpg.set_value("code_show_password", False)
        dpg.configure_item("code_password", password=True)
        dpg.set_value("code_password_strength", "Password Strength: Not rated")
    
    # Analyzer callbacks
    def _analyze_file(self):
        """Analyze file encryption"""
        file_path = dpg.get_value("analyzer_file_path")
        if not file_path:
            self.log_message("Select file to analyze", "analyzer")
            return
        
        try:
            if not os.path.exists(file_path):
                self.log_message("File does not exist", "analyzer")
                return
            
            result = self.crypto_engine.detect_algorithm(file_path)
            
            output = f"Algorithm: {result['algorithm']}\n"
            output += f"Confidence: {result['confidence']}%\n"
            output += f"File Size: {result['details'].get('file_size', 0)} bytes\n"
            output += f"Entropy: {result['details'].get('entropy', 0):.2f}\n"
            
            if 'signature' in result['details']:
                output += f"Signature: {result['details']['signature']}\n"
            
            if 'error' in result['details']:
                output += f"Error: {result['details']['error']}\n"
            
            dpg.set_value("analyzer_results", output)
            self.log_message("File analysis completed", "analyzer")
            
        except Exception as e:
            self.log_message(f"Analysis error: {str(e)}", "analyzer")
    
    # ============ Settings callbacks ============ #
    def _save_settings(self):
        """Save application settings"""
        try:
            if self.settings.save_settings():
                self.log_message("Settings saved successfully", "file")
            else:
                self.log_message("Failed to save settings", "file")
        except Exception as e:
            self.log_message(f"Error saving settings: {str(e)}", "file")
    
    def _reset_settings(self):
        """Reset settings to defaults"""
        try:
            if self.settings.reset_to_defaults():
                self.log_message("Settings reset to defaults", "file")
            else:
                self.log_message("Failed to reset settings", "file")
        except Exception as e:
            self.log_message(f"Error resetting settings: {str(e)}", "file")
    
    def _export_settings(self):
        """Export settings to file"""
        try:
            export_path = "cryptoz_settings_export.json"
            if self.settings.export_settings(export_path):
                self.log_message(f"Settings exported to {export_path}", "file")
            else:
                self.log_message("Failed to export settings", "file")
        except Exception as e:
            self.log_message(f"Error exporting settings: {str(e)}", "file")
    
    # ============ Utility methods ============ #
    def log_message(self, message: str, tab: str = "file"):
        """Enhanced logging with timestamps and levels"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            log_text = dpg.get_value(f"{tab}_log") or ""
            log_text += f"[{timestamp}] {message}\n"
            dpg.set_value(f"{tab}_log", log_text)
            
            # Auto-scroll to bottom
            dpg.focus_item(f"{tab}_log")
        except Exception as e:
            logging.info(f"[{tab}] {message}")
    
    def _copy_to_clipboard(self, item_tag: str):
        """Copy text to clipboard"""
        text = dpg.get_value(item_tag)
        if text:
            dpg.set_clipboard_text(text)
            self.log_message("Content copied to clipboard", "file")
    
    def _open_file_location(self, path_tag: str):
        """Open file location in system file manager"""
        path = dpg.get_value(path_tag)
        if path and os.path.exists(path):
            try:
                import subprocess
                if os.name == 'nt':  # Windows
                    subprocess.run(['explorer', '/select,', os.path.abspath(path)])
            except Exception as e:
                self.log_message(f"Could not open file location: {e}", "file")
    
    # ============ Batch operations UI ============ #
    def _create_batch_operations_tab(self):
        """Create batch operations tab for folder encryption"""
        with dpg.tab(label="Batch Operations"):
            dpg.add_text("Folder Encryption/Decryption", color=[0, 200, 255])
            dpg.add_separator()
            
            # Input folder selection
            with dpg.group(horizontal=True):
                dpg.add_text("Input Folder:")
                dpg.add_input_text(
                    tag="batch_input_folder",
                    width=400,
                    readonly=True,
                    hint="Select folder to process..."
                )
                dpg.add_button(
                    label="Browse",
                    callback=lambda: self._show_folder_dialog("batch_input")
                )
            
            # Output folder selection
            with dpg.group(horizontal=True):
                dpg.add_text("Output Folder:")
                dpg.add_input_text(
                    tag="batch_output_folder", 
                    width=400,
                    hint="Select output folder..."
                )
                dpg.add_button(
                    label="Browse",
                    callback=lambda: self._show_folder_dialog("batch_output")
                )
            
            # Algorithm selection
            with dpg.group(horizontal=True):
                dpg.add_text("Algorithm:")
                dpg.add_combo(
                    items=list(self.crypto_engine.get_available_algorithms().keys()),
                    default_value=self.settings.get("security.default_algorithm", "fernet"),
                    tag="batch_algorithm",
                    width=150
                )
            
            # File patterns
            with dpg.group(horizontal=True):
                dpg.add_text("File Patterns:")
                dpg.add_input_text(
                    tag="batch_patterns",
                    default_value="*",
                    width=300,
                    hint="Comma-separated patterns (e.g., *.txt,*.docx)"
                )
            
            # Password section
            self._create_password_section("batch")
            
            # Operation buttons
            with dpg.group(horizontal=True):
                dpg.add_button(
                    label="Encrypt Folder",
                    callback=self._encrypt_folder
                )
                dpg.add_button(
                    label="Decrypt Folder", 
                    callback=self._decrypt_folder
                )
                dpg.add_button(
                    label="Clear",
                    callback=self._clear_batch_fields
                )
            
            # Progress and status
            with dpg.group(horizontal=True):
                dpg.add_text("Status:")
                dpg.add_text("Ready", tag="batch_status", color=[0, 200, 0])
                dpg.add_progress_bar(
                    tag="batch_progress",
                    show=False,
                    width=200
                )
            
            # Statistics
            with dpg.group(horizontal=True):
                dpg.add_text("Processed:")
                dpg.add_text("0", tag="batch_processed")
                dpg.add_text("/")
                dpg.add_text("0", tag="batch_total")
                dpg.add_text("files")
            
            # Results log
            dpg.add_text("Operation Log:")
            dpg.add_input_text(
                tag="batch_log",
                multiline=True,
                height=150,
                readonly=True,
                width=-1
            )
    
    def _show_folder_dialog(self, target: str):
        """Show folder selection dialog"""
        def folder_callback(sender, app_data):
            self._handle_folder_selection(app_data, target)
        
        with dpg.file_dialog(
            directory_selector=True,
            show=True,
            callback=folder_callback,
            width=700,
            height=400
        ):
            pass
    
    def _handle_folder_selection(self, app_data: dict, target: str):
        """Handle folder selection"""
        try:
            if not app_data or 'file_path_name' not in app_data:
                return
            
            folder_path = app_data['file_path_name']
            
            if target == "batch_input":
                dpg.set_value("batch_input_folder", folder_path)
                # Auto-generate output folder
                input_path = Path(folder_path)
                output_path = input_path.parent / f"{input_path.name}_processed"
                dpg.set_value("batch_output_folder", str(output_path))
                
            elif target == "batch_output":
                dpg.set_value("batch_output_folder", folder_path)
                
        except Exception as e:
            logging.error(f"Folder selection error: {e}")
            self.log_message(f"Folder selection error: {str(e)}", "batch")

    # ============ Batch operation callbacks ============ #
    def _encrypt_folder(self):
        """Encrypt folder batch operation"""
        if not self._validate_batch_inputs():
            return
        
        input_folder = dpg.get_value("batch_input_folder")
        output_folder = dpg.get_value("batch_output_folder")
        password = dpg.get_value("batch_password")
        algorithm = dpg.get_value("batch_algorithm")
        patterns_text = dpg.get_value("batch_patterns")
        
        # Parse file patterns
        file_patterns = [p.strip() for p in patterns_text.split(',') if p.strip()]
        
        def encrypt_operation():
            return self.crypto_engine.encrypt_folder(
                input_folder, output_folder, password, algorithm, file_patterns
            )
        
        self._start_batch_operation(encrypt_operation, "Encrypting folder...")
    
    def _decrypt_folder(self):
        """Decrypt folder batch operation"""
        if not self._validate_batch_inputs():
            return
        
        input_folder = dpg.get_value("batch_input_folder")
        output_folder = dpg.get_value("batch_output_folder")
        password = dpg.get_value("batch_password")
        algorithm = dpg.get_value("batch_algorithm")
        
        def decrypt_operation():
            return self.crypto_engine.decrypt_folder(
                input_folder, output_folder, password, algorithm
            )
        
        self._start_batch_operation(decrypt_operation, "Decrypting folder...")
    
    def _start_batch_operation(self, operation, status_message: str):
        """Start batch operation in background"""
        operation_id = f"batch_op_{int(time.time())}"
        
        def operation_wrapper():
            result = operation()
            dpg.set_value("batch_status", "Completed")
            self._update_batch_results(result)
        
        # Update UI
        dpg.set_value("batch_status", status_message)
        dpg.configure_item("batch_progress", show=True)
        
        # Start operation
        self.operation_manager.start_operation(operation_id, operation_wrapper)
    
    def _update_batch_results(self, result: Dict[str, Any]):
        """Update UI with batch operation results"""
        try:
            dpg.set_value("batch_processed", str(result.get('processed', 0)))
            dpg.set_value("batch_total", str(result.get('total', 0)))
            
            if result.get('success', False):
                self.log_message(result.get('message', 'Operation completed'), "batch")
            else:
                self.log_message(f"Operation failed: {result.get('message', 'Unknown error')}", "batch")
            
            # Log individual errors
            for error in result.get('errors', []):
                self.log_message(f"Error: {error}", "batch")
                
        except Exception as e:
            logging.error(f"Error updating batch results: {e}")
    
    def _validate_batch_inputs(self) -> bool:
        """Validate batch operation inputs"""
        validators = [
            (dpg.get_value("batch_input_folder"), "Select input folder"),
            (dpg.get_value("batch_output_folder"), "Select output folder"),
            (dpg.get_value("batch_password"), "Enter password"),
        ]
        
        for value, message in validators:
            if not value:
                self.log_message(message, "batch")
                return False
        
        # Check if input folder exists
        input_folder = dpg.get_value("batch_input_folder")
        if not os.path.exists(input_folder):
            self.log_message("Input folder does not exist", "batch")
            return False
        
        return True
    
    def _clear_batch_fields(self):
        """Clear batch operation fields"""
        dpg.set_value("batch_input_folder", "")
        dpg.set_value("batch_output_folder", "")
        dpg.set_value("batch_password", "")
        dpg.set_value("batch_patterns", "*")
        dpg.set_value("batch_log", "")
        dpg.set_value("batch_status", "Ready")
        dpg.set_value("batch_processed", "0")
        dpg.set_value("batch_total", "0")
        dpg.configure_item("batch_progress", show=False)

    # ============ Batch password methods ============ #
    def _generate_batch_password(self):
        """Generate password for batch operations"""
        length = self.settings.get("security.password_length", 16)
        password = self.security_utils.generate_password(length)
        dpg.set_value("batch_password", password)
        self._on_password_change("batch")
        self.log_message("Generated new password", "batch")
    
    def _copy_batch_password(self):
        """Copy batch password to clipboard"""
        password = dpg.get_value("batch_password")
        if password:
            dpg.set_clipboard_text(password)
            self.log_message("Password copied to clipboard", "batch")
        else:
            self.log_message("No password to copy", "batch")
    
    def _toggle_batch_password_visibility(self):
        """Toggle batch password visibility"""
        show = dpg.get_value("batch_show_password")
        dpg.configure_item("batch_password", password=not show)

    # ============ Policy Managment ============ #
    def _create_policy_management_tab(self):
        """Create policy management tab"""
        with dpg.tab(label="Policy Management"):
            dpg.add_text("Encryption Policies", color=[0, 200, 255])
            dpg.add_separator()
            
            # Создание новой политики
            with dpg.collapsing_header(label="Create New Policy"):
                with dpg.group(horizontal=True):
                    dpg.add_text("Policy Name:")
                    dpg.add_input_text(tag="policy_name", width=200)
                
                with dpg.group(horizontal=True):
                    dpg.add_text("Target Path:")
                    dpg.add_input_text(tag="policy_target", width=300)
                    dpg.add_button(
                        label="Browse",
                        callback=lambda: self._show_policy_target_dialog()
                    )
                
                with dpg.group(horizontal=True):
                    dpg.add_text("Algorithm:")
                    dpg.add_combo(
                        items=list(self.crypto_engine.get_available_algorithms().keys()),
                        default_value="fernet",
                        tag="policy_algorithm",
                        width=150
                    )
                
                # Пароль для политики
                with dpg.group(horizontal=True):
                    dpg.add_text("Password:")
                    dpg.add_input_text(
                        tag="policy_password",
                        password=True,
                        width=200
                    )
                    dpg.add_button(
                        label="Generate",
                        callback=self._generate_policy_password
                    )
                
                # Паттерны файлов
                with dpg.group(horizontal=True):
                    dpg.add_text("File Patterns:")
                    dpg.add_input_text(
                        tag="policy_patterns",
                        default_value="*",
                        width=300,
                        hint="*.txt,*.docx,*.pdf"
                    )
                
                dpg.add_button(
                    label="Create Policy",
                    callback=self._create_policy
                )
            
            # Список существующих политик
            with dpg.collapsing_header(label="Manage Policies"):
                dpg.add_text("Existing Policies:")
                # Создаем контейнер для списка политик
                with dpg.group(tag="policies_list_container"):
                    pass  # Политики будут добавляться динамически
            
            # Применение политик
            with dpg.collapsing_header(label="Apply Policies"):
                with dpg.group(horizontal=True):
                    dpg.add_combo(
                        items=[],
                        tag="policy_apply_list",
                        width=200
                    )
                    dpg.add_button(
                        label="Apply Selected Policy",
                        callback=self._apply_policy
                    )
                    dpg.add_button(
                        label="Refresh List",
                        callback=self._refresh_policies_list
                    )
                
                dpg.add_text("Application Results:")
                dpg.add_input_text(
                    tag="policy_results",
                    multiline=True,
                    height=150,
                    readonly=True,
                    width=-1
                )
            
            # Инициализируем список политик после создания всех элементов
            self._policy_items = []
            self._refresh_policies_list()
    
    def _show_policy_target_dialog(self):
        """Show target selection dialog for policy"""
        def target_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                dpg.set_value("policy_target", app_data['file_path_name'])
        
        with dpg.file_dialog(
            directory_selector=True,
            show=True,
            callback=target_callback,
            width=700,
            height=400
        ):
            pass
    
    def _generate_policy_password(self):
        """Generate password for policy"""
        length = self.settings.get("security.password_length", 16)
        password = self.security_utils.generate_password(length)
        dpg.set_value("policy_password", password)
    
    def _create_policy(self):
        """Create new policy"""
        try:
            name = dpg.get_value("policy_name")
            target = dpg.get_value("policy_target")
            algorithm = dpg.get_value("policy_algorithm")
            password = dpg.get_value("policy_password")
            patterns_text = dpg.get_value("policy_patterns")
            
            if not all([name, target, algorithm, password]):
                self._safe_log_policy_message("Please fill all required fields")
                return
            
            # Parse patterns
            patterns = [p.strip() for p in patterns_text.split(',') if p.strip()]
            
            rules = {
                "target": target,
                "algorithm": algorithm,
                "password": password,
                "patterns": patterns
            }
            
            success = self.policy_manager.create_policy(name, rules)
            
            if success:
                self._safe_log_policy_message(f"Policy '{name}' created successfully")
                self._refresh_policies_list()
                self._clear_policy_fields()
            else:
                self._safe_log_policy_message(f"Failed to create policy '{name}'")
                
        except Exception as e:
            self._safe_log_policy_message(f"Error creating policy: {str(e)}")
    
    def _refresh_policies_list(self):
        """Refresh policies list in UI"""
        try:
            policies = self.policy_manager.get_policies()
            policy_names = list(policies.keys())
            
            # Обновляем комбо-бокс только если он существует
            if dpg.does_item_exist("policy_apply_list"):
                dpg.configure_item("policy_apply_list", items=policy_names)
            
            # Очищаем контейнер списка политик
            if dpg.does_item_exist("policies_list_container"):
                # Удаляем только дочерние элементы контейнера, не сам контейнер
                children = dpg.get_item_children("policies_list_container")[1]
                for child in children:
                    dpg.delete_item(child)
            
            # Сбрасываем список элементов
            self._policy_items = []
            
            # Добавляем политики в контейнер
            for policy_name, policy_data in policies.items():
                if dpg.does_item_exist("policies_list_container"):
                    with dpg.group(horizontal=True, parent="policies_list_container"):
                        status = "Enabled" if policy_data.get('enabled', True) else "Disabled"
                        dpg.add_text(f"{policy_name} ({status})")
                        dpg.add_button(
                            label="Apply",
                            callback=lambda s, d, p=policy_name: self._apply_policy(p)
                        )
                        dpg.add_button(
                            label="Delete",
                            callback=lambda s, d, p=policy_name: self._delete_policy(p)
                        )
                        dpg.add_button(
                            label="Toggle",
                            callback=lambda s, d, p=policy_name: self._toggle_policy(p)
                        )
                        
        except Exception as e:
            # Используем безопасное логирование
            self._safe_log_policy_message(f"Error refreshing policies: {str(e)}")
    
    def _apply_policy(self, policy_name: str = None):
        """Apply policy"""
        try:
            if policy_name is None:
                policy_name = dpg.get_value("policy_apply_list")
            
            if not policy_name:
                self._safe_log_policy_message("Select a policy to apply")
                return
            
            result = self.policy_manager.apply_policy(policy_name)
            
            if result.get("success"):
                self._safe_log_policy_message(f"Policy '{policy_name}' applied successfully")
                
                # Show detailed results
                if "results" in result:
                    for target, target_result in result["results"].items():
                        status = "success" if target_result.get("success") else "failed"
                        self._safe_log_policy_message(f"  {target}: {status}")
            else:
                self._safe_log_policy_message(f"Policy application failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            self._safe_log_policy_message(f"Error applying policy: {str(e)}")

    def _delete_policy(self, policy_name: str):
        """Delete policy"""
        try:
            success = self.policy_manager.delete_policy(policy_name)
            
            if success:
                self._safe_log_policy_message(f"Policy '{policy_name}' deleted")
                self._refresh_policies_list()
            else:
                self._safe_log_policy_message(f"Failed to delete policy '{policy_name}'")
                
        except Exception as e:
            self._safe_log_policy_message(f"Error deleting policy: {str(e)}")
    
    def _toggle_policy(self, policy_name: str):
        """Toggle policy enabled/disabled"""
        try:
            policies = self.policy_manager.get_policies()
            current_state = policies[policy_name].get("enabled", True)
            success = self.policy_manager.toggle_policy(policy_name, not current_state)
            
            if success:
                new_state = "enabled" if not current_state else "disabled"
                self._safe_log_policy_message(f"Policy '{policy_name}' {new_state}")
                self._refresh_policies_list()
            else:
                self._safe_log_policy_message(f"Failed to toggle policy '{policy_name}'")
                
        except Exception as e:
            self._safe_log_policy_message(f"Error toggling policy: {str(e)}")
    
    def _log_policy_message(self, message: str):
        """Log message to policy results"""
        self._safe_log_policy_message(message)
    
    def _clear_policy_fields(self):
        """Clear policy creation fields"""
        try:
            if dpg.does_item_exist("policy_name"):
                dpg.set_value("policy_name", "")
            if dpg.does_item_exist("policy_target"):
                dpg.set_value("policy_target", "")
            if dpg.does_item_exist("policy_password"):
                dpg.set_value("policy_password", "")
            if dpg.does_item_exist("policy_patterns"):
                dpg.set_value("policy_patterns", "*")
        except Exception as e:
            logging.error(f"Error clearing policy fields: {e}")

    def _safe_log_policy_message(self, message: str):
        """Safely log message to policy results (handles initialization errors)"""
        try:
            if dpg.does_item_exist("policy_results"):
                current_text = dpg.get_value("policy_results") or ""
                timestamp = datetime.now().strftime("%H:%M:%S")
                new_text = f"[{timestamp}] {message}\n{current_text}"
                dpg.set_value("policy_results", new_text)
            else:
                # Если элемент еще не создан, просто логируем в консоль
                logging.info(f"Policy: {message}")
        except Exception as e:
            logging.error(f"Error logging policy message: {e}")

    # ============ Steganography ============ #
    def _create_steganography_tab(self):
        """Create steganography tab with test functionality"""
        with dpg.tab(label="Steganography"):
            dpg.add_text("Data Hiding in Files", color=[0, 200, 255])
            dpg.add_separator()
            
            # Вкладки для разных операций
            with dpg.tab_bar() as stego_tab_bar:
                self._create_stego_hide_tab()
                self._create_stego_extract_tab()
                self._create_stego_analyze_tab()
    
    def _create_stego_hide_tab(self):
        """Create tab for hiding data with auto output"""
        with dpg.tab(label="Hide Data"):
            dpg.add_text("Step 1: Select carrier file (image/audio)", color=[200, 200, 0])
            
            # Выбор файла-носителя
            with dpg.group(horizontal=True):
                dpg.add_text("Carrier File:")
                dpg.add_input_text(
                    tag="stego_carrier_file",
                    width=400,
                    readonly=True,
                    hint="Select PNG, JPG, BMP, TIFF or WAV file..."
                )
                dpg.add_button(
                    label="Browse",
                    callback=lambda: self._show_stego_carrier_dialog()
                )
            
            dpg.add_text("Step 2: Select data to hide", color=[200, 200, 0])
            
            # Выбор данных для скрытия
            with dpg.group(horizontal=True):
                dpg.add_text("Data to Hide:")
                dpg.add_input_text(
                    tag="stego_data_file",
                    width=400,
                    readonly=True,
                    hint="Select any file to hide (txt, pdf, zip, etc)..."
                )
                dpg.add_button(
                    label="Browse", 
                    callback=lambda: self._show_stego_data_dialog()
                )
            
            dpg.add_text("Step 3: Output file (auto-generated)", color=[200, 200, 0])
            
            # Выходной файл (только для информации и ручного изменения)
            with dpg.group(horizontal=True):
                dpg.add_text("Output File:")
                dpg.add_input_text(
                    tag="stego_output_file",
                    width=400,
                    hint="Auto-generated output path...",
                    readonly=False  # Разрешаем ручное изменение
                )
                dpg.add_button(
                    label="Auto Generate",
                    callback=lambda: self._regenerate_stego_output()
                )
            
            dpg.add_text("Step 4: Configure settings", color=[200, 200, 0])
            
            # Метод стеганографии
            with dpg.group(horizontal=True):
                dpg.add_text("Method:")
                dpg.add_combo(
                    items=["lsb", "lsb_enhanced"],
                    default_value="lsb",
                    tag="stego_method",
                    width=150,
                    callback=self._on_stego_method_change
                )
                dpg.add_text("", tag="stego_method_desc", wrap=300)
            
            # Информация о емкости
            dpg.add_text("Available Capacity: Unknown", tag="stego_capacity_info")
            
            # Пароль для шифрования
            with dpg.group(horizontal=True):
                dpg.add_text("Encryption Password (optional):")
                dpg.add_input_text(
                    tag="stego_password",
                    password=True,
                    width=200,
                    hint="Encrypt data before hiding..."
                )
                dpg.add_button(
                    label="Generate",
                    callback=self._generate_stego_password
                )
            
            # Примечания
            with dpg.group():
                dpg.add_text("Automatic Features:", color=[0, 200, 255])
                dpg.add_text("Output path generated automatically", color=[150, 255, 150])
                dpg.add_text("JPG files converted to PNG automatically", color=[150, 255, 150])
                dpg.add_text("Duplicate names handled automatically", color=[150, 255, 150])
            
            dpg.add_text("Step 5: Execute", color=[200, 200, 0])
            
            # Кнопка выполнения
            dpg.add_button(
                label="Hide Data",
                callback=self._hide_data_stego
            )
            
            # Статус и прогресс
            with dpg.group(horizontal=True):
                dpg.add_text("Status:")
                dpg.add_text("Ready", tag="stego_hide_status", color=[0, 200, 0])
                dpg.add_progress_bar(
                    tag="stego_hide_progress",
                    show=False,
                    width=200
                )
            
            # Лог операций
            dpg.add_text("Operation Log:")
            dpg.add_input_text(
                tag="stego_hide_log",
                multiline=True,
                height=150,
                readonly=True,
                width=-1
            )
            
            # Инициализируем описание метода
            self._on_stego_method_change()
    
    def _regenerate_stego_output(self):
        """Regenerate output path manually"""
        carrier_path = dpg.get_value("stego_carrier_file")
        data_path = dpg.get_value("stego_data_file")
        
        if carrier_path:
            self._auto_generate_stego_output(carrier_path, data_path)
            self._log_stego_message("Output path regenerated", "hide")
        else:
            self._log_stego_message("Select carrier file first", "hide")

    def _on_stego_method_change(self):
        """Update method description when method changes"""
        method = dpg.get_value("stego_method")
        if method == "lsb":
            dpg.set_value("stego_method_desc", "Basic LSB - higher capacity, less stealth")
        else:
            dpg.set_value("stego_method_desc", "Enhanced LSB - better stealth, lower capacity")
        
        # Обновляем емкость при смене метода
        carrier_path = dpg.get_value("stego_carrier_file")
        if carrier_path:
            self._update_stego_capacity(carrier_path)

    def _create_stego_extract_tab(self):
        """Create tab for extracting hidden data - IMPROVED"""
        with dpg.tab(label="Extract Data"):
            dpg.add_text("Extract Hidden Data from Files", color=[0, 200, 255])
            dpg.add_separator()
            
            # Выбор стего-файла
            with dpg.group(horizontal=True):
                dpg.add_text("Stego File:")
                dpg.add_input_text(
                    tag="stego_extract_file",
                    width=400,
                    readonly=True,
                    hint="Select file with hidden data..."
                )
                dpg.add_button(
                    label="Browse",
                    callback=lambda: self._show_stego_extract_dialog()
                )
            
            # Информация о файле (улучшенная)
            dpg.add_text("File Info: Select a file to analyze", tag="stego_file_info", color=[200, 200, 0])
            
            # Выходной файл для извлеченных данных
            with dpg.group(horizontal=True):
                dpg.add_text("Output File:")
                dpg.add_input_text(
                    tag="stego_extract_output", 
                    width=400,
                    hint="Where to save extracted data..."
                )
                dpg.add_button(
                    label="Browse",
                    callback=lambda: self._show_stego_extract_output_dialog()
                )
            
            # Пароль для расшифровки
            with dpg.group(horizontal=True):
                dpg.add_text("Decryption Password:")
                dpg.add_input_text(
                    tag="stego_extract_password",
                    password=True,
                    width=200,
                    hint="Only if data was encrypted..."
                )
            
            # Подсказки по цветам
            with dpg.group():
                dpg.add_text("Color Guide:", color=[255, 200, 0])
                dpg.add_text("Green: No password needed", color=[100, 255, 100])
                dpg.add_text("Red: Password required", color=[255, 100, 100])
                dpg.add_text("Yellow: Unknown - try extraction", color=[255, 200, 0])
                dpg.add_text("Gray: No steganography detected", color=[200, 200, 200])
            
            # Кнопка извлечения
            dpg.add_button(
                label="Extract Data",
                callback=self._extract_data_stego
            )
            
            # Статус
            with dpg.group(horizontal=True):
                dpg.add_text("Status:")
                dpg.add_text("Ready", tag="stego_extract_status", color=[0, 200, 0])
            
            # Лог операций
            dpg.add_text("Extraction Log:")
            dpg.add_input_text(
                tag="stego_extract_log",
                multiline=True,
                height=150,
                readonly=True,
                width=-1
            )
    
    def _create_stego_analyze_tab(self):
        """Create tab for steganography analysis"""
        with dpg.tab(label="Analyze File"):
            # Выбор файла для анализа
            with dpg.group(horizontal=True):
                dpg.add_text("File to Analyze:")
                dpg.add_input_text(
                    tag="stego_analyze_file",
                    width=400,
                    readonly=True,
                    hint="Select file to check for steganography..."
                )
                dpg.add_button(
                    label="Browse",
                    callback=lambda: self._show_stego_analyze_dialog()
                )
            
            # Кнопка анализа
            dpg.add_button(
                label="Analyze for Steganography",
                callback=self._analyze_stego_file
            )
            
            # Результаты анализа
            dpg.add_text("Analysis Results:")
            dpg.add_input_text(
                tag="stego_analyze_results",
                multiline=True,
                height=200,
                readonly=True,
                width=-1
            )
    
    def _show_stego_carrier_dialog(self):
        """Show carrier file selection dialog with auto output generation"""
        def carrier_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                carrier_path = app_data['file_path_name']
                dpg.set_value("stego_carrier_file", carrier_path)
                
                # Автоматически генерируем выходной файл
                self._auto_generate_stego_output(carrier_path)
                self._update_stego_capacity(carrier_path)
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=carrier_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension("Images (*.png *.jpg *.jpeg *.bmp *.tiff *.tif){.png,.jpg,.jpeg,.bmp,.tiff,.tif}", color=(255, 255, 0, 255))
            dpg.add_file_extension("Audio (*.wav){.wav}", color=(0, 255, 255, 255))
            dpg.add_file_extension(".*", color=(150, 255, 150, 255))
    
    def _auto_generate_stego_output(self, carrier_path: str, data_path: str = None):
        """Automatically generate output file path"""
        try:
            if not carrier_path:
                return
            
            import os
            from pathlib import Path
            
            carrier = Path(carrier_path)
            carrier_dir = carrier.parent
            carrier_name = carrier.stem
            
            # Определяем расширение на основе типа carrier файла
            carrier_ext = carrier.suffix.lower()
            
            if carrier_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif']:
                output_ext = '.png'  # Всегда используем PNG для изображений
            elif carrier_ext == '.wav':
                output_ext = '.wav'  # Сохраняем как WAV для аудио
            else:
                output_ext = '.png'  # По умолчанию PNG
            
            # Создаем базовое имя файла
            if data_path:
                data_file = Path(data_path)
                data_name = data_file.stem
                base_name = f"{carrier_name}_{data_name}_hidden"
            else:
                base_name = f"{carrier_name}_hidden"
            
            # Генерируем полный путь
            output_name = base_name + output_ext
            output_path = carrier_dir / output_name
            
            # Если файл уже существует, добавляем номер
            counter = 1
            while output_path.exists():
                output_name = f"{base_name}_{counter}{output_ext}"
                output_path = carrier_dir / output_name
                counter += 1
                if counter > 100:  # Защита от бесконечного цикла
                    break
            
            dpg.set_value("stego_output_file", str(output_path))
            
        except Exception as e:
            logging.error(f"Auto output generation error: {e}")

    def _show_stego_data_dialog(self):
        """Show data file selection dialog"""
        def data_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                data_path = app_data['file_path_name']
                dpg.set_value("stego_data_file", data_path)
                
                # Обновляем выходной файл с учетом данных
                carrier_path = dpg.get_value("stego_carrier_file")
                if carrier_path:
                    self._auto_generate_stego_output(carrier_path, data_path)
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=data_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension(".*", color=(150, 255, 150, 255))
            dpg.add_file_extension("Text Files (*.txt *.log *.ini *.cfg){.txt,.log,.ini,.cfg}", color=(255, 255, 0, 255))
            dpg.add_file_extension("Documents (*.pdf *.doc *.docx *.xls *.xlsx){.pdf,.doc,.docx,.xls,.xlsx}", color=(0, 255, 255, 255))
            dpg.add_file_extension("Archives (*.zip *.rar *.7z *.tar *.gz){.zip,.rar,.7z,.tar,.gz}", color=(255, 0, 255, 255))
            dpg.add_file_extension("Code (*.py *.js *.html *.css *.json *.xml){.py,.js,.html,.css,.json,.xml}", color=(0, 255, 0, 255))
            dpg.add_file_extension("Keys & Certificates (*.key *.pem *.crt *.cer){.key,.pem,.crt,.cer}", color=(255, 165, 0, 255))

    def _show_stego_extract_output_dialog(self):
        """Show output selection for extracted data"""
        def output_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                dpg.set_value("stego_extract_output", app_data['file_path_name'])
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=output_callback,
            width=700,
            height=400
        ):
            # Фильтры для выходных файлов
            dpg.add_file_extension(".*", color=(150, 255, 150, 255))
            dpg.add_file_extension("Text Files (*.txt){.txt}", color=(255, 255, 0, 255))
            dpg.add_file_extension("PDF Documents (*.pdf){.pdf}", color=(0, 255, 255, 255))
            dpg.add_file_extension("Archives (*.zip){.zip}", color=(255, 0, 255, 255))
            dpg.add_file_extension("All Files (*.*){.*}")
    
    def _show_stego_extract_dialog(self):
        """Show stego file selection for extraction with improved analysis"""
        def extract_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                stego_path = app_data['file_path_name']
                dpg.set_value("stego_extract_file", stego_path)
                
                # Автоматически генерируем выходной файл
                self._auto_generate_extract_output(stego_path)
                
                # Анализируем файл
                self._analyze_stego_file_for_extraction(stego_path)
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=extract_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension(".*", color=(150, 255, 150, 255))
            dpg.add_file_extension("Images (*.png *.jpg *.jpeg *.bmp *.tiff *.tif){.png,.jpg,.jpeg,.bmp,.tiff,.tif}", color=(255, 255, 0, 255))
            dpg.add_file_extension("Audio (*.wav){.wav}", color=(0, 255, 255, 255))

    def _auto_generate_extract_output(self, stego_path: str):
        """Automatically generate output path for extraction"""
        try:
            import os
            from pathlib import Path
            
            stego = Path(stego_path)
            stego_dir = stego.parent
            stego_name = stego.stem
            
            # Убираем суффиксы типа "_hidden" если они есть
            if stego_name.endswith('_hidden'):
                base_name = stego_name[:-7] + '_extracted'
            else:
                base_name = stego_name + '_extracted'
            
            # По умолчанию используем .txt, но пользователь может изменить
            output_path = stego_dir / f"{base_name}.txt"
            
            # Если файл уже существует, добавляем номер
            counter = 1
            while output_path.exists():
                output_name = f"{base_name}_{counter}.txt"
                output_path = stego_dir / output_name
                counter += 1
                if counter > 100:
                    break
            
            dpg.set_value("stego_extract_output", str(output_path))
            
        except Exception as e:
            logging.error(f"Auto output generation error: {e}")
    
    def _analyze_stego_file_for_extraction(self, stego_path: str):
        """Analyze stego file to provide user guidance - FIXED VERSION"""
        try:
            if not stego_path:
                dpg.set_value("stego_file_info", "File Info: No file selected")
                dpg.configure_item("stego_file_info", color=[200, 200, 200])
                return
            
            # Выполняем анализ через основной метод
            result = self.steganography_engine.analyze_stego_file(stego_path)
            
            if not result.get('analysis_complete', True):
                info_text = "File Info: Analysis failed"
                color = [255, 100, 100]  # Красный
            elif result.get('potential_stego', False):
                # Обнаружена стеганография
                methods = result.get('methods', [])
                if 'CryptoZ LSB Steganography' in methods:
                    # Это наш формат
                    if result.get('is_encrypted', False):
                        info_text = "File Info: Encrypted CryptoZ data - password REQUIRED"
                        color = [255, 100, 100]  # Красный - требуется пароль
                    else:
                        info_text = "File Info: Unencrypted CryptoZ data - password NOT needed"
                        color = [100, 255, 100]  # Зеленый - пароль не нужен
                    
                    # Добавляем информацию о размере данных
                    data_size = result.get('detected_data_size', 0)
                    if data_size > 0:
                        info_text += f" ({data_size} bytes)"
                        
                else:
                    # Другие методы стеганографии
                    info_text = "File Info: Potential steganography detected - try extraction"
                    color = [255, 200, 0]  # Желтый - неизвестно
            else:
                # Стеганография не обнаружена
                info_text = "File Info: No steganography detected"
                color = [200, 200, 200]  # Серый - не обнаружено
            
            dpg.set_value("stego_file_info", info_text)
            dpg.configure_item("stego_file_info", color=color)
                
        except Exception as e:
            dpg.set_value("stego_file_info", "File Info: Analysis error")
            dpg.configure_item("stego_file_info", color=[255, 100, 100])

    def _show_stego_extract_output_dialog(self):
        """Show output selection for extracted data"""
        def output_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                dpg.set_value("stego_extract_output", app_data['file_path_name'])
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=output_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension("All Files{.*}")
            dpg.add_file_extension("")
    
    def _show_stego_analyze_dialog(self):
        """Show file selection for stego analysis"""
        def analyze_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                dpg.set_value("stego_analyze_file", app_data['file_path_name'])
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=analyze_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension("Images (*.png *.jpg *.jpeg *.bmp *.tiff *.tif){.png,.jpg,.jpeg,.bmp,.tiff,.tif}", color=(255, 255, 0, 255))
            dpg.add_file_extension("Audio (*.wav){.wav}", color=(0, 255, 255, 255))
            dpg.add_file_extension(".*", color=(150, 255, 150, 255))
    
    def _update_stego_capacity(self, carrier_path: str):
        """Update capacity information for carrier file"""
        try:
            if not carrier_path:
                return
            
            method = dpg.get_value("stego_method")
            file_ext = carrier_path.lower().split('.')[-1]
            
            # Поддерживаемые форматы изображений
            image_extensions = ['png', 'jpg', 'jpeg', 'bmp', 'tiff', 'tif']
            
            if file_ext in image_extensions:
                capacity = self.steganography_engine._calculate_max_image_capacity(carrier_path, method)
                dpg.set_value("stego_capacity_info", f"Capacity: ~{capacity} bytes")
                
                # Update method description
                if method == "lsb":
                    dpg.set_value("stego_method_desc", "Basic LSB - modifies all color channels")
                else:
                    dpg.set_value("stego_method_desc", "Enhanced LSB - better stealth, lower capacity")
            
            elif file_ext == 'wav':
                # Estimate audio capacity
                import wave
                with wave.open(carrier_path, 'rb') as audio:
                    params = audio.getparams()
                    capacity = params.nframes // 8  # Rough estimate
                dpg.set_value("stego_capacity_info", f"Capacity: ~{capacity} bytes")
                dpg.set_value("stego_method_desc", "Audio LSB - modifies audio samples")
            
            else:
                dpg.set_value("stego_capacity_info", f"Capacity: Unsupported file type (.{file_ext})")
                dpg.set_value("stego_method_desc", "")
                
        except Exception as e:
            dpg.set_value("stego_capacity_info", f"Capacity: Error - {str(e)}")
    
    def _generate_stego_password(self):
        """Generate password for steganography"""
        length = self.settings.get("security.password_length", 16)
        password = self.security_utils.generate_password(length)
        dpg.set_value("stego_password", password)
    
    def _hide_data_stego(self):
        """Hide data in carrier file with better logging"""
        try:
            carrier_path = dpg.get_value("stego_carrier_file")
            data_path = dpg.get_value("stego_data_file")
            output_path = dpg.get_value("stego_output_file")
            method = dpg.get_value("stego_method")
            password = dpg.get_value("stego_password")
            
            # Validation
            if not all([carrier_path, data_path, output_path]):
                self._log_stego_message("Please select all required files", "hide")
                return
            
            if not os.path.exists(carrier_path):
                self._log_stego_message("Carrier file not found", "hide")
                return
            
            if not os.path.exists(data_path):
                self._log_stego_message("Data file not found", "hide")
                return
            
            # Read data to hide
            with open(data_path, 'rb') as f:
                data = f.read()
            
            self._log_stego_message(f"Carrier file: {carrier_path}", "hide")
            self._log_stego_message(f"Data file: {data_path} ({len(data)} bytes)", "hide")
            self._log_stego_message(f"Output file: {output_path}", "hide")
            self._log_stego_message(f"Method: {method}", "hide")
            self._log_stego_message(f"Password: {'Yes' if password else 'No'}", "hide")
            
            # Update UI
            dpg.set_value("stego_hide_status", "Hiding data...")
            dpg.configure_item("stego_hide_progress", show=True)
            
            # Determine file type and call appropriate method
            file_ext = carrier_path.lower().split('.')[-1]
            image_extensions = ['png', 'jpg', 'jpeg', 'bmp', 'tiff', 'tif']
            
            if file_ext in image_extensions:
                # Для JPG файлов всегда сохраняем как PNG чтобы избежать потерь
                if file_ext in ['jpg', 'jpeg'] and not output_path.lower().endswith('.png'):
                    output_path = os.path.splitext(output_path)[0] + '.png'
                    self._log_stego_message(f"Note: JPG carrier will be saved as PNG: {output_path}", "hide")
                
                result = self.steganography_engine.hide_in_image(
                    data, carrier_path, output_path, password, method
                )
            elif file_ext == 'wav':
                result = self.steganography_engine.hide_in_audio(
                    data, carrier_path, output_path, password
                )
            else:
                self._log_stego_message(f"Unsupported carrier file type: {file_ext}", "hide")
                return
            
            # Handle result with detailed logging
            if result["success"]:
                dpg.set_value("stego_hide_status", "Completed")
                self._log_stego_message("Data hidden successfully!", "hide")
                self._log_stego_message(f"Output: {result['output_path']}", "hide")
                self._log_stego_message(f"Data size: {result['data_size']} bytes", "hide")
                self._log_stego_message(f"Method: {result.get('method', 'N/A')}", "hide")
                self._log_stego_message(f"Original size: {result.get('original_size', 0)} bytes", "hide")
                self._log_stego_message(f"Output size: {result.get('output_size', 0)} bytes", "hide")
                
                if result.get('encrypted'):
                    self._log_stego_message("Data was encrypted", "hide")
                
                # Test extraction immediately
                self._log_stego_message("Testing extraction...", "hide")
                test_output = output_path + ".test"
                test_result = self.steganography_engine.extract_from_image(output_path, test_output, password)
                
                if test_result["success"]:
                    self._log_stego_message("Extraction test PASSED", "hide")
                    # Clean up test file
                    try:
                        os.remove(test_output)
                    except:
                        pass
                else:
                    self._log_stego_message("Extraction test FAILED", "hide")
                    self._log_stego_message(f"Test error: {test_result['error']}", "hide")
                    
            else:
                dpg.set_value("stego_hide_status", "Failed")
                self._log_stego_message(f"Error: {result['error']}", "hide")
            
        except Exception as e:
            dpg.set_value("stego_hide_status", "Error")
            self._log_stego_message(f"✗ Operation failed: {str(e)}", "hide")
            logging.error(f"Steganography error: {e}")
        finally:
            dpg.configure_item("stego_hide_progress", show=False)
    
    def _extract_data_stego(self):
        """Extract hidden data from stego file with simple diagnostics"""
        try:
            stego_path = dpg.get_value("stego_extract_file")
            output_path = dpg.get_value("stego_extract_output")
            password = dpg.get_value("stego_extract_password")
            
            if not all([stego_path, output_path]):
                self._log_stego_message("Please select stego file and output path", "extract")
                return
            
            if not os.path.exists(stego_path):
                self._log_stego_message("Stego file not found", "extract")
                return
            
            # Если пароль пустой, преобразуем в None
            if password == "":
                password = None
            
            dpg.set_value("stego_extract_status", "Extracting...")
            
            # Определяем файл тип
            file_ext = stego_path.lower().split('.')[-1]
            
            if file_ext in ['png', 'jpg', 'jpeg', 'bmp', 'tiff', 'tif']:
                result = self.steganography_engine.extract_from_image(
                    stego_path, output_path, password
                )
            elif file_ext == 'wav':
                result = self.steganography_engine.extract_from_audio(
                    stego_path, output_path, password
                )
            else:
                self._log_stego_message(f"Unsupported stego file type: {file_ext}", "extract")
                return
            
            # Обрабатываем результат
            if result["success"]:
                dpg.set_value("stego_extract_status", "Completed")
                self._log_stego_message(f"Data extracted to: {output_path}", "extract")
                self._log_stego_message(f"File size: {result['data_size']} bytes", "extract")
                
                if result.get('encrypted'):
                    self._log_stego_message("Data was decrypted", "extract")
                
                # Простая проверка: пытаемся прочитать как текст если это .txt файл
                if output_path.lower().endswith('.txt'):
                    try:
                        with open(output_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        self._log_stego_message(f"Text content preview: {content[:100]}...", "extract")
                    except:
                        self._log_stego_message("Note: Extracted data is not valid UTF-8 text", "extract")
                        
            else:
                dpg.set_value("stego_extract_status", "Failed")
                error_msg = result['error']
                
                if "Password required" in error_msg:
                    self._log_stego_message("ERROR: This file contains encrypted data", "extract")
                    self._log_stego_message("Please enter the correct password", "extract")
                elif "Decryption failed" in error_msg:
                    self._log_stego_message("ERROR: Wrong password or corrupted data", "extract")
                else:
                    self._log_stego_message(f"ERROR: {error_msg}", "extract")
            
        except Exception as e:
            dpg.set_value("stego_extract_status", "Error")
            self._log_stego_message(f"Extraction failed: {str(e)}", "extract")
    
    def _analyze_stego_file(self):
        """Analyze file for steganography - FIXED RESULT HANDLING"""
        try:
            file_path = dpg.get_value("stego_analyze_file")
            
            if not file_path:
                dpg.set_value("stego_analyze_results", "Please select a file to analyze")
                return
            
            if not os.path.exists(file_path):
                dpg.set_value("stego_analyze_results", "File not found")
                return
            
            # Выполняем анализ
            result = self.steganography_engine.analyze_stego_file(file_path)
            
            # Форматируем результаты для отображения
            output = self._format_analysis_results(result)
            dpg.set_value("stego_analyze_results", output)
                
        except Exception as e:
            dpg.set_value("stego_analyze_results", f"Analysis error: {str(e)}")

    def _format_analysis_results(self, analysis: Dict[str, Any]) -> str:
        """Format analysis results for display"""
        try:
            output = "File Analysis Results:\n"
            output += "=" * 50 + "\n"
            
            # Основная информация
            output += f"File Type: {analysis.get('file_type', 'unknown')}\n"
            output += f"File Size: {analysis.get('file_size', 0)} bytes\n"
            
            # Информация об изображении (если есть)
            if 'image_dimensions' in analysis:
                output += f"Image Dimensions: {analysis['image_dimensions']}\n"
            if 'color_mode' in analysis:
                output += f"Color Mode: {analysis['color_mode']}\n"
            
            # Результаты анализа стеганографии
            output += f"Potential Steganography: {'YES' if analysis.get('potential_stego') else 'NO'}\n"
            output += f"Confidence: {analysis.get('confidence', 0)}%\n"
            
            # Обнаруженные методы
            methods = analysis.get('methods', [])
            if methods:
                output += f"Detected Methods: {', '.join(methods)}\n"
            
            # Дополнительная информация
            if 'detected_data_size' in analysis:
                output += f"Hidden Data Size: {analysis['detected_data_size']} bytes\n"
            if 'detected_method' in analysis:
                output += f"Stego Method: {analysis['detected_method']}\n"
            if 'is_encrypted' in analysis:
                output += f"Encrypted: {'YES' if analysis['is_encrypted'] else 'NO'}\n"
            
            # Заметки
            notes = analysis.get('notes', [])
            if notes:
                output += f"\nNotes:\n"
                for note in notes:
                    output += f"  • {note}\n"
            
            # Статус анализа
            if not analysis.get('analysis_complete', True):
                output += f"\nAnalysis incomplete - some checks may have failed\n"
            
            return output
            
        except Exception as e:
            return f"Error formatting results: {str(e)}"
    
    def _log_stego_message(self, message: str, log_type: str = "hide"):
        """Log message to steganography log"""
        try:
            log_tag = f"stego_{log_type}_log"
            if dpg.does_item_exist(log_tag):
                current_text = dpg.get_value(log_tag) or ""
                timestamp = datetime.now().strftime("%H:%M:%S")
                new_text = f"[{timestamp}] {message}\n{current_text}"
                dpg.set_value(log_tag, new_text)
        except Exception as e:
            logging.error(f"Error logging stego message: {e}")

    def _test_steganography(self):
        """Test steganography functionality with sample data"""
        try:
            import tempfile
            import hashlib
            
            # Create test data
            test_data = b"This is a test message for steganography verification!"
            test_data_hash = hashlib.sha256(test_data).hexdigest()[:16]
            
            # Create temporary files
            with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as carrier_file:
                carrier_path = carrier_file.name
            
            with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as data_file:
                data_file.write(test_data)
                data_path = data_file.name
            
            output_path = carrier_path.replace('.png', '_hidden.png')
            extract_path = output_path.replace('.png', '_extracted.txt')
            
            self._log_stego_message("=== STEGANOGRAPHY TEST ===", "hide")
            self._log_stego_message(f"Test data: {test_data_hash}", "hide")
            
            # Test hiding
            result = self.steganography_engine.hide_in_image(
                test_data, carrier_path, output_path, None, 'lsb'
            )
            
            if result["success"]:
                self._log_stego_message("Hiding successful", "hide")
                
                # Test extraction
                extract_result = self.steganography_engine.extract_from_image(
                    output_path, extract_path, None
                )
                
                if extract_result["success"]:
                    # Verify extracted data
                    with open(extract_path, 'rb') as f:
                        extracted_data = f.read()
                    
                    if extracted_data == test_data:
                        self._log_stego_message("Extraction successful", "hide")
                        self._log_stego_message("Data integrity verified", "hide")
                    else:
                        self._log_stego_message("Data corruption detected", "hide")
                else:
                    self._log_stego_message(f"Extraction failed: {extract_result['error']}", "hide")
            else:
                self._log_stego_message(f"Hiding failed: {result['error']}", "hide")
            
            # Cleanup
            for path in [carrier_path, data_path, output_path, extract_path]:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except:
                    pass
                    
        except Exception as e:
            self._log_stego_message(f"Test error: {str(e)}", "hide")

    def _setup_viewport(self):
        """Setup application viewport"""
        dpg.create_viewport(
            title='CryptoZ - Advanced Encryption Tool',
            width=1200,
            height=800,
            min_width=1000,
            min_height=600
        )
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.set_primary_window("Primary Window", True)
    
    def run(self):
        """Run the application"""
        try:
            dpg.start_dearpygui()
        except Exception as e:
            logging.error(f"Application error: {e}")
        finally:
            self.cleanup()
    
    def cleanup(self):
        """Cleanup resources"""
        try:
            if hasattr(self, 'crypto_engine'):
                self.crypto_engine.cleanup()
            dpg.destroy_context()
        except Exception as e:
            logging.error(f"Cleanup error: {e}")
    
    def log_message(self, message: str, tab: str = "file"):
        """Log message to UI"""
        try:
            timestamp = time.strftime("%H:%M:%S")
            log_text = dpg.get_value(f"{tab}_log") or ""
            log_text += f"[{timestamp}] {message}\n"
            dpg.set_value(f"{tab}_log", log_text)
        except Exception as e:
            logging.info(f"[{tab}] {message}")