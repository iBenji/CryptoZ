import dearpygui.dearpygui as dpg
import os
import threading
import time
import json
import logging
import sys
from typing import Optional, Dict, Any, Callable
from pathlib import Path

from core.crypto_engine import CryptoEngine
from core.security_utils import SecurityUtils
from core.code_analyzer import CodeAnalyzer
from config.settings import AppSettings


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
                "- Secure password generation\n\n"
                
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
            dpg.add_text("Version: 2.1.5")
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

    # ========== CALLBACK METHODS ==========
    
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
    
    # File encryption callbacks
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
    
    # Message encryption callbacks
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
    
    # Code encryption callbacks
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
    
    # Settings callbacks
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
    
    # Utility methods
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