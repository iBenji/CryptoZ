from datetime import datetime
#from tkinter import Image
import dearpygui.dearpygui as dpg
import os
import threading
import time
#import json
import logging
#import subprocess
#import sys
from typing import Optional, Dict, Any, Callable, List
from pathlib import Path

from core.crypto_engine import CryptoEngine
from core.security_utils import SecurityUtils
from core.code_analyzer import CodeAnalyzer
from config.settings import AppSettings
from core.policy_manager import PolicyManager
from core.steganography_engine import SteganographyEngine
from core.secure_folder import SecureFolderManager


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
        self.stego_engine = SteganographyEngine(crypto_engine=self.crypto_engine)
        self.security_utils = SecurityUtils()
        self.code_analyzer = CodeAnalyzer()
        self.policy_manager = PolicyManager(self.crypto_engine, self.settings)
        self.steganography_engine = SteganographyEngine(self.crypto_engine)
        
        # Enhanced operation management
        self.operation_manager = OperationManager()
        self.file_dialog_handler = FileDialogHandler(self)
        
        # UI state
        self._ui_initialized = False
        self.settings.set_ui_callback(self.update_stats_display)
        
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
        """Create categorized tab bar with icons"""
        with dpg.tab_bar() as main_tab_bar:
            
            # 🔐 FILES
            with dpg.tab(label="Files"):
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("File encryption and batch operations")
                with dpg.tab_bar():
                    with dpg.tab(label="Encrypt"):
                        self._create_file_encryption_content()
                    with dpg.tab(label="Batch"):
                        self._create_batch_operations_content()

            # 🛡️ SECURITY
            with dpg.tab(label="Security"):
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Security analysis and steganography")
                with dpg.tab_bar():
                    with dpg.tab(label="Scan"):
                        self._create_vulnerability_scan_content()
                    with dpg.tab(label="Analyze"):
                        self._create_analyzer_content()
                    with dpg.tab(label="Stego"):
                        self._create_steganography_content()

            # 💬 TOOLS
            with dpg.tab(label="Tools"):
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Message and code encryption")
                with dpg.tab_bar():
                    with dpg.tab(label="Message"):
                        self._create_message_encryption_content()
                    with dpg.tab(label="Code"):
                        self._create_code_encryption_content()

            # ⚙️ SYSTEM
            with dpg.tab(label="System"):
                with dpg.tooltip(dpg.last_item()):
                    dpg.add_text("Policies, settings, and info")
                with dpg.tab_bar():
                    with dpg.tab(label="Policies"):
                        self._create_policy_management_content()
                    with dpg.tab(label="Settings"):
                        self._create_settings_content()
                    with dpg.tab(label="About"):
                        self._create_about_content()

            # 🛡️ Secure Folder
            with dpg.tab(label="Secure Folder"):
                dpg.add_text("Secure Folder - Auto-encrypt all files", color=(0, 255, 127))
                dpg.add_separator()

                with dpg.group(horizontal=True):
                    dpg.add_text("Folder:")
                    dpg.add_input_text(tag="secure_folder_path", width=400, hint="C:\\MySecureData")
                    dpg.add_button(label="Browse", callback=self._show_secure_folder_dialog)

                with dpg.group(horizontal=True):
                    dpg.add_text("Password:")
                    dpg.add_input_text(tag="secure_folder_password", password=True, width=200, hint="Master password")
                    dpg.add_button(label="Generate", callback=self._generate_secure_folder_password)

                with dpg.group(horizontal=True):
                    dpg.add_text("Choose algorithm:")
                    dpg.add_combo(
                        items=["aes_gcm", "aes_cbc", "chacha20", "aes_ctr"],
                        default_value="aes_gcm",
                        tag="secure_folder_algorithm",
                        width=200
                    )

                dpg.add_button(
                    label="Start Monitoring",
                    tag="secure_folder_start_btn",
                    callback=self._start_secure_folder,
                    width=200
                )
                dpg.add_button(
                    label="Stop Monitoring",
                    tag="secure_folder_stop_btn",
                    callback=self._stop_secure_folder,
                    show=False,
                    width=200
                )
                dpg.add_button(label="Decrypt & Open", callback=self._decrypt_and_open_file, width=200)
                dpg.add_button(label="Clean Temp Files", callback=self._clean_secure_temp, width=200)
                dpg.add_text("Status: Not running", tag="secure_folder_status", color=(200, 200, 0))
                dpg.add_text("Instructions:", color=(100, 200, 255))
                dpg.add_text("- All files you put here will be encrypted")
                dpg.add_text("- To view: decrypt via 'Decrypt File' button (next update)")
                dpg.add_text("- Never lose your password - no recovery!")

                dpg.add_text("Log:")
                dpg.add_input_text(
                    tag="secure_folder_log",
                    multiline=True,
                    height=180,
                    readonly=True,
                    width=-1
                )
    
    def _create_file_encryption_content(self):
        """File encryption UI - no dpg.tab wrapper"""
        dpg.add_text("File Encryption", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.group(horizontal=True):
            dpg.add_text("Input File:")
            dpg.add_input_text(tag="file_input_path", width=400, readonly=True, hint="Select input file...")
            dpg.add_button(label="Browse", callback=lambda: self.file_dialog_handler.show_open_dialog("file_input"))

        with dpg.group(horizontal=True):
            dpg.add_text("Output File:")
            dpg.add_input_text(tag="file_output_path", width=400, hint="Specify output file path...")
            dpg.add_button(label="Browse", callback=lambda: self.file_dialog_handler.show_save_dialog("file_output"))

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

        self._on_algorithm_change()

        self._create_password_section("file")

        with dpg.group(horizontal=True):
            dpg.add_button(label="Encrypt File", callback=self._encrypt_file, tag="encrypt_file_btn")
            dpg.add_button(label="Decrypt File", callback=self._decrypt_file, tag="decrypt_file_btn")
            dpg.add_button(label="Clear All", callback=self._clear_file_fields)

        with dpg.group(horizontal=True):
            dpg.add_text("Status:")
            dpg.add_text("Ready", tag="file_status", color=[0, 200, 0])
            dpg.add_progress_bar(tag="file_progress", show=False, width=200)

        dpg.add_text("Operation Log:")
        dpg.add_button(label="Copy", callback=lambda: self._copy_to_clipboard("file_log"), width=80)
        dpg.add_button(label="Clear", callback=lambda: dpg.set_value("file_log", ""), width=80)

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
    
    def _create_message_encryption_content(self):
        dpg.add_text("Message Encryption", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.group(horizontal=True):
            dpg.add_text("Algorithm:")
            dpg.add_combo(
                items=list(self.crypto_engine.get_available_algorithms().keys()),
                default_value=self.settings.get("security.default_algorithm", "fernet"),
                tag="message_algorithm",
                width=150
            )

        dpg.add_text("Input Message:")
        dpg.add_input_text(tag="message_input", multiline=True, height=100, width=-1, hint="Enter message...")

        self._create_password_section("message")

        with dpg.group(horizontal=True):
            dpg.add_button(label="Encrypt Message", callback=self._encrypt_message)
            dpg.add_button(label="Decrypt Message", callback=self._decrypt_message)
            dpg.add_button(label="Clear", callback=self._clear_message_fields)

        dpg.add_text("Output Message:")
        dpg.add_input_text(tag="message_output", multiline=True, height=100, readonly=True, width=-1)

    
    def _create_code_encryption_content(self):
        dpg.add_text("Code Encryption", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.group(horizontal=True):
            dpg.add_text("Encryption Method:")
            dpg.add_combo(items=["obfuscate", "base64", "xor"], default_value="obfuscate", tag="code_method", width=100)

        self._create_password_section("code")

        with dpg.group(horizontal=True):
            dpg.add_text("Start Position:")
            dpg.add_input_text(tag="code_start", width=80, default_value="0")
            dpg.add_text("End Position:")
            dpg.add_input_text(tag="code_end", width=80)
            dpg.add_button(label="Auto Select", callback=self._auto_select_code)

        dpg.add_text("Source Code:")
        dpg.add_input_text(tag="code_input", multiline=True, height=150, width=-1, hint="Enter source code...")

        with dpg.group(horizontal=True):
            dpg.add_button(label="Encrypt Selected", callback=self._encrypt_selected_code)
            dpg.add_button(label="Decrypt All", callback=self._decrypt_all_code)
            dpg.add_button(label="Clear", callback=self._clear_code_fields)

        dpg.add_text("Result:")
        dpg.add_input_text(tag="code_output", multiline=True, height=150, readonly=True, width=-1)

    
    def _create_analyzer_content(self):
        dpg.add_text("File Analyzer", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.group(horizontal=True):
            dpg.add_text("File to Analyze:")
            dpg.add_input_text(tag="analyzer_file_path", width=400, readonly=True, hint="Select file...")
            dpg.add_button(label="Browse", callback=lambda: self.file_dialog_handler.show_open_dialog("analyzer_input"))

        dpg.add_button(label="Analyze File", callback=self._analyze_file)

        dpg.add_text("Analysis Results:")
        dpg.add_input_text(tag="analyzer_results", multiline=True, height=200, readonly=True, width=-1)

    
    def _create_settings_content(self):
        dpg.add_text("Settings", color=[0, 200, 255])
        dpg.add_separator()

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

        with dpg.group(horizontal=True):
            dpg.add_button(label="Save Settings", callback=self._save_settings)
            dpg.add_button(label="Reset to Defaults", callback=self._reset_settings)

    
    def _create_about_content(self):
        """Create enhanced About tab with organized sub-tabs"""
        dpg.add_text("About CryptoZ", color=[0, 200, 255])
        dpg.add_text("Advanced Encryption & Security Suite", color=[100, 200, 255])
        dpg.add_text("CryptoZ v2.2.0 Secure Folder & Live Encryption", color=[0, 255, 255])
        dpg.add_separator()

        with dpg.tab_bar():

            # --- Core Features ---
            with dpg.tab(label="Core Features"):
                dpg.add_text("Core Features", color=[200, 200, 0], bullet=True)
                dpg.add_text(
                    "File Encryption - AES-256, Fernet, ChaCha20, Triple DES, XOR\n"
                    "Batch Processing - Encrypt/decrypt entire folders recursively\n"
                    "Message Encryption - Secure text messages with password protection\n"
                    "Code Encryption - Obfuscate, encrypt, and protect source code\n"
                    "File Analyzer - Detect encryption type and entropy of files\n"
                    "Policy Engine - Create and apply automated encryption rules\n"
                    "Configurable Security - Adjustable KDF iterations, password strength, and defaults",
                    wrap=580
                )

                dpg.add_spacer()
                dpg.add_text("Secure Folder", color=[0, 255, 200], bullet=True)
                dpg.add_text(
                    "Real-time monitoring of secure folders\n"
                    "Auto-encrypt on file drop\n"
                    "Decrypt & Edit & Save Back\n"
                    "Multi-algorithm support (AES-GCM, ChaCha20, etc.)\n"
                    "Auto-clean temporary files on exit\n"
                    "Auto-lock when app closes",
                    wrap=580
                )

            # --- Steganography ---
            with dpg.tab(label="Steganography"):
                dpg.add_text("Steganography Features", color=[150, 255, 150], bullet=True)
                dpg.add_text(
                    "LSB & Enhanced LSB embedding\n"
                    "Auto-conversion of JPG to PNG for lossless hiding\n"
                    "Password-protected hidden data\n"
                    "Detection of hidden content in files\n"
                    "Capacity estimation and real-time preview",
                    wrap=580
                )

            # --- Security Scanner ---
            with dpg.tab(label="Scanner"):
                dpg.add_text("Security Scanner Features", color=[255, 200, 100], bullet=True)
                dpg.add_text(
                    "Full directory scans with subfolder support\n"
                    "Detection of passwords, keys, and credentials in files\n"
                    "Risk scoring and severity classification\n"
                    "Exportable JSON reports\n"
                    "Real-time file analysis and summary dashboard",
                    wrap=580
                )

            # --- UX & Dev ---
            with dpg.tab(label="UX & Info"):
                dpg.add_text("User Experience", color=[200, 200, 255], bullet=True)
                dpg.add_text(
                    "Modern categorized UI with icons (Files, Security, Tools, System)\n"
                    "Auto-generation of input/output paths\n"
                    "Real-time password strength feedback\n"
                    "Background operations with progress tracking\n"
                    "Full logging with copy/clear controls\n"
                    "Usage Statistics",
                    wrap=580
                )

                dpg.add_spacer()
                dpg.add_text("Developer & License", color=[120, 255, 255], bullet=True)
                dpg.add_text("Developer: FAKEDOWNBOY$ Team", indent=20)
                dpg.add_text("GitHub: https://github.com/iBenji/CryptoZ.git", color=[100, 200, 255], indent=20)
                dpg.add_text("License: MIT Open Source", color=[150, 150, 150], indent=20)

                dpg.add_spacer()
                dpg.add_text("Use Responsibly - Never use on data without proper authorization.", color=[255, 0, 0])

            # --- Stats ---
            with dpg.tab(label="Stats"):
                dpg.add_text("Usage Statistics", color=[0, 255, 200], bullet=True)

                # Secure Folder Stats
                enc_count = self.settings.get("statistics.secure_folder.files_encrypted", 0)
                dec_count = self.settings.get("statistics.secure_folder.files_decrypted", 0)
                sessions = self.settings.get("statistics.secure_folder.sessions_count", 0)
                last = self.settings.get("statistics.secure_folder.last_session", "Never")

                dpg.add_text(f"Secure Folder", bullet=True)
                dpg.add_text(f"Files Encrypted: {enc_count}", indent=20, tag="stats_encrypted")
                dpg.add_text(f"Files Decrypted: {dec_count}", indent=20, tag="stats_decrypted")
                dpg.add_text(f"Active Sessions: {sessions}", indent=20, tag="stats_sessions")
                dpg.add_text(f"Last Session: {last}", indent=20, tag="stats_last_session")

                dpg.add_spacer()

                # General Stats
                total_enc = self.settings.get("statistics.general.total_files_encrypted", 0)
                total_msg = self.settings.get("statistics.general.total_messages_encrypted", 0)

                dpg.add_text(f"General", bullet=True)
                dpg.add_text(f"Total Files Encrypted: {total_enc}", indent=20, tag="stats_total_enc")
                dpg.add_text(f"Messages Encrypted: {total_msg}", indent=20, tag="stats_total_msg")


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
    def _create_batch_operations_content(self):
        """Batch operations UI - no dpg.tab wrapper"""
        dpg.add_text("Batch Operations", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.group(horizontal=True):
            dpg.add_text("Input Folder:")
            dpg.add_input_text(tag="batch_input_folder", width=400, readonly=True, hint="Select folder to process...")
            dpg.add_button(label="Browse", callback=lambda: self._show_folder_dialog("batch_input"))

        with dpg.group(horizontal=True):
            dpg.add_text("Output Folder:")
            dpg.add_input_text(tag="batch_output_folder", width=400, hint="Select output folder...")
            dpg.add_button(label="Browse", callback=lambda: self._show_folder_dialog("batch_output"))

        with dpg.group(horizontal=True):
            dpg.add_text("Algorithm:")
            dpg.add_combo(
                items=list(self.crypto_engine.get_available_algorithms().keys()),
                default_value=self.settings.get("security.default_algorithm", "fernet"),
                tag="batch_algorithm",
                width=150
            )

        with dpg.group(horizontal=True):
            dpg.add_text("File Patterns:")
            dpg.add_input_text(
                tag="batch_patterns",
                default_value="*",
                width=300,
                hint="Comma-separated patterns (e.g., *.txt,*.docx)"
            )

        self._create_password_section("batch")

        with dpg.group(horizontal=True):
            dpg.add_button(label="Encrypt Folder", callback=self._encrypt_folder)
            dpg.add_button(label="Decrypt Folder", callback=self._decrypt_folder)
            dpg.add_button(label="Clear", callback=self._clear_batch_fields)

        with dpg.group(horizontal=True):
            dpg.add_text("Status:")
            dpg.add_text("Ready", tag="batch_status", color=[0, 200, 0])
            dpg.add_progress_bar(tag="batch_progress", show=False, width=200)

        with dpg.group(horizontal=True):
            dpg.add_text("Processed:")
            dpg.add_text("0", tag="batch_processed")
            dpg.add_text("/")
            dpg.add_text("0", tag="batch_total")
            dpg.add_text("files")

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
    def _create_policy_management_content(self):
        """Policy management UI - no dpg.tab wrapper"""
        dpg.add_text("Policy Management", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.collapsing_header(label="Create New Policy"):
            with dpg.group(horizontal=True):
                dpg.add_text("Policy Name:")
                dpg.add_input_text(tag="policy_name", width=200)

            with dpg.group(horizontal=True):
                dpg.add_text("Target Path:")
                dpg.add_input_text(tag="policy_target", width=300)
                dpg.add_button(label="Browse", callback=self._show_policy_target_dialog)

            with dpg.group(horizontal=True):
                dpg.add_text("Algorithm:")
                dpg.add_combo(
                    items=list(self.crypto_engine.get_available_algorithms().keys()),
                    default_value="fernet",
                    tag="policy_algorithm",
                    width=150
                )

            with dpg.group(horizontal=True):
                dpg.add_text("Password:")
                dpg.add_input_text(tag="policy_password", password=True, width=200)
                dpg.add_button(label="Generate", callback=self._generate_policy_password)

            with dpg.group(horizontal=True):
                dpg.add_text("File Patterns:")
                dpg.add_input_text(tag="policy_patterns", default_value="*", width=300, hint="*.txt,*.docx")

            dpg.add_button(label="Create Policy", callback=self._create_policy)

        with dpg.collapsing_header(label="Manage Policies"):
            dpg.add_text("Existing Policies:")
            with dpg.group(tag="policies_list_container"):
                pass

        with dpg.collapsing_header(label="Apply Policies"):
            with dpg.group(horizontal=True):
                dpg.add_combo(tag="policy_apply_list", width=200)
                dpg.add_button(label="Apply Selected Policy", callback=self._apply_policy)
                dpg.add_button(label="Refresh List", callback=self._refresh_policies_list)

            dpg.add_text("Application Results:")
            dpg.add_input_text(
                tag="policy_results",
                multiline=True,
                height=150,
                readonly=True,
                width=-1
            )

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
            
            # Update combo box if it exists
            if dpg.does_item_exist("policy_apply_list"):
                dpg.configure_item("policy_apply_list", items=policy_names)
            
            # Cleanup container if it exists
            if dpg.does_item_exist("policies_list_container"):
                children = dpg.get_item_children("policies_list_container")[1]
                for child in children:
                    dpg.delete_item(child)
            
            self._policy_items = []
            
            # Adding policies to UI
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
                logging.info(f"Policy: {message}")
        except Exception as e:
            logging.error(f"Error logging policy message: {e}")

    # ============ Steganography ============ #
    def _create_steganography_content(self):
        """Steganography UI - no dpg.tab wrapper, uses internal tab_bar"""
        with dpg.tab_bar():
            self._create_stego_hide_content()
            self._create_stego_extract_content()
            self._create_stego_analyze_content()
    
    def _create_stego_hide_content(self):
        """Hide tab with progress group"""
        with dpg.tab(label="Hide Data"):
            dpg.add_text("Step 1: Select carrier file (image/audio)", color=[200, 200, 0])
            with dpg.group(horizontal=True):
                dpg.add_text("Carrier File:")
                dpg.add_input_text(tag="stego_carrier_file", width=400, readonly=True, hint="PNG, JPG, WAV...")
                dpg.add_button(label="Browse", callback=self._show_stego_carrier_dialog)

            dpg.add_text("Step 2: Select data to hide", color=[200, 200, 0])
            with dpg.group(horizontal=True):
                dpg.add_text("Data to Hide:")
                dpg.add_input_text(tag="stego_data_file", width=400, readonly=True, hint="Any file...")
                dpg.add_button(label="Browse", callback=self._show_stego_data_dialog)

            dpg.add_text("Step 3: Output file (auto-generated)", color=[200, 200, 0])
            with dpg.group(horizontal=True):
                dpg.add_text("Output File:")
                dpg.add_input_text(tag="stego_output_file", width=400, hint="Auto-generated...")
                dpg.add_button(label="Auto Generate", callback=self._regenerate_stego_output)

            dpg.add_text("Step 4: Configure settings", color=[200, 200, 0])
            with dpg.group(horizontal=True):
                dpg.add_text("Method:")
                dpg.add_combo(items=["lsb", "lsb_enhanced"], default_value="lsb", tag="stego_method", callback=self._on_stego_method_change)
                dpg.add_text("", tag="stego_method_desc", wrap=300)

            dpg.add_text("Available Capacity: Unknown", tag="stego_capacity_info")

            with dpg.group(horizontal=True):
                dpg.add_text("Encryption Password (optional):")
                dpg.add_input_text(tag="stego_password", password=True, width=200, hint="Encrypt before hiding...")
                dpg.add_button(label="Generate", callback=self._generate_stego_password)

            with dpg.group(horizontal=True):
                dpg.add_text("Compression:")
                dpg.add_checkbox(label="Compress data before hiding", tag="stego_compress", default_value=True)

            dpg.add_text("Automatic Features:", color=[0, 200, 255])
            dpg.add_text("Output path generated automatically", color=[150, 255, 150])
            dpg.add_text("JPG files converted to PNG automatically", color=[150, 255, 150])
            dpg.add_text("Duplicate names handled automatically", color=[150, 255, 150])

            dpg.add_text("Step 5: Execute", color=[200, 200, 0])
            dpg.add_button(label="Hide Data", callback=self._hide_data_stego)

            # === PROGRESS BAR: Remove and create ===
            if dpg.does_item_exist("stego_hide_progress_group"):
                dpg.delete_item("stego_hide_progress_group")

            with dpg.group(tag="stego_hide_progress_group"):
                dpg.add_text("Progress:")
                dpg.add_progress_bar(tag="stego_hide_progress", width=300, show=False)
                dpg.add_text("Ready", tag="stego_hide_status", color=[0, 200, 0])

            dpg.add_text("Operation Log:")
            dpg.add_input_text(tag="stego_hide_log", multiline=True, height=150, readonly=True, width=-1)

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
        
        # Update capacity info
        carrier_path = dpg.get_value("stego_carrier_file")
        if carrier_path:
            self._update_stego_capacity(carrier_path)

    def _create_stego_extract_content(self):
        """Extract tab with progress group"""
        with dpg.tab(label="Extract Data"):
            dpg.add_text("Extract Hidden Data from Files", color=[0, 200, 255])
            dpg.add_separator()

            with dpg.group(horizontal=True):
                dpg.add_text("Stego File:")
                dpg.add_input_text(tag="stego_extract_file", width=400, readonly=True, hint="Select file with hidden data...")
                dpg.add_button(label="Browse", callback=self._show_stego_extract_dialog)

            dpg.add_text("File Info: Select a file to analyze", tag="stego_file_info", color=[200, 200, 0])

            with dpg.group(horizontal=True):
                dpg.add_text("Output File:")
                dpg.add_input_text(tag="stego_extract_output", width=400, hint="Where to save...")
                dpg.add_button(label="Browse", callback=self._show_stego_extract_output_dialog)

            with dpg.group(horizontal=True):
                dpg.add_text("Decryption Password:")
                dpg.add_input_text(tag="stego_extract_password", password=True, width=200, hint="If encrypted...")

            dpg.add_text("Color Guide:", color=[255, 200, 0])
            dpg.add_text("Green: No password needed", color=[100, 255, 100])
            dpg.add_text("Red: Password required", color=[255, 100, 100])
            dpg.add_text("Yellow: Unknown - try extraction", color=[255, 200, 0])
            dpg.add_text("Gray: No steganography detected", color=[200, 200, 200])

            dpg.add_button(label="Extract Data", callback=self._extract_data_stego)

            # === PROGRESS BAR: Remove and create ===
            if dpg.does_item_exist("stego_extract_progress_group"):
                dpg.delete_item("stego_extract_progress_group")

            with dpg.group(tag="stego_extract_progress_group"):
                dpg.add_text("Progress:")
                dpg.add_progress_bar(tag="stego_extract_progress", width=300, show=False)
                dpg.add_text("Ready", tag="stego_extract_status", color=[0, 200, 0])

            dpg.add_text("Extraction Log:")
            dpg.add_input_text(tag="stego_extract_log", multiline=True, height=150, readonly=True, width=-1)


    
    def _create_stego_analyze_content(self):
        with dpg.tab(label="Analyze File"):
            with dpg.group(horizontal=True):
                dpg.add_text("File to Analyze:")
                dpg.add_input_text(tag="stego_analyze_file", width=400, readonly=True, hint="Check for steganography...")
                dpg.add_button(label="Browse", callback=self._show_stego_analyze_dialog)

            dpg.add_button(label="Analyze for Steganography", callback=self._analyze_stego_file)

            dpg.add_text("Analysis Results:")
            dpg.add_input_text(tag="stego_analyze_results", multiline=True, height=200, readonly=True, width=-1)

    
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
            
            from pathlib import Path
            
            carrier = Path(carrier_path)
            carrier_dir = carrier.parent
            carrier_name = carrier.stem
            
            # Detect file type
            carrier_ext = carrier.suffix.lower()
            
            if carrier_ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff', '.tif']:
                output_ext = '.png'
            elif carrier_ext == '.wav':
                output_ext = '.wav'
            else:
                output_ext = '.png'
            
            if data_path:
                data_file = Path(data_path)
                data_name = data_file.stem
                base_name = f"{carrier_name}_{data_name}_hidden"
            else:
                base_name = f"{carrier_name}_hidden"
            
            output_name = base_name + output_ext
            output_path = carrier_dir / output_name
            
            counter = 1
            while output_path.exists():
                output_name = f"{base_name}_{counter}{output_ext}"
                output_path = carrier_dir / output_name
                counter += 1
                if counter > 100:  # Safeguard against infinite loops
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
            # Output extensions
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
                
                self._auto_generate_extract_output(stego_path)
                
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
            from pathlib import Path
            
            stego = Path(stego_path)
            stego_dir = stego.parent
            stego_name = stego.stem
            
            if stego_name.endswith('_hidden'):
                base_name = stego_name[:-7] + '_extracted'
            else:
                base_name = stego_name + '_extracted'
            
            output_path = stego_dir / f"{base_name}.txt"
            
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
        """Analyze stego file to provide user guidance"""
        try:
            if not stego_path:
                dpg.set_value("stego_file_info", "File Info: No file selected")
                dpg.configure_item("stego_file_info", color=[200, 200, 200])
                return
            
            result = self.steganography_engine.analyze_stego_file(stego_path)
            
            if not result.get('analysis_complete', True):
                info_text = "File Info: Analysis failed"
                color = [255, 100, 100]
            elif result.get('potential_stego', False):
                methods = result.get('methods', [])
                if 'CryptoZ LSB Steganography' in methods:
                    if result.get('is_encrypted', False):
                        info_text = "File Info: Encrypted CryptoZ data - password REQUIRED"
                        color = [255, 100, 100]
                    else:
                        info_text = "File Info: Unencrypted CryptoZ data - password NOT needed"
                        color = [100, 255, 100]
                    
                    data_size = result.get('detected_data_size', 0)
                    if data_size > 0:
                        info_text += f" ({data_size} bytes)"
                        
                else:
                    # Другие методы стеганографии
                    info_text = "File Info: Potential steganography detected - try extraction"
                    color = [255, 200, 0]
            else:
                # Стеганография не обнаружена
                info_text = "File Info: No steganography detected"
                color = [200, 200, 200]
            
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
            
            # Supported extensions
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
        carrier_path = dpg.get_value("stego_carrier_file")
        data_path = dpg.get_value("stego_data_file")
        output_path = dpg.get_value("stego_output_file")
        method = dpg.get_value("stego_method")
        password = dpg.get_value("stego_password").strip() or None
        compress = dpg.get_value("stego_compress")

        self._reset_stego_progress()
        self._update_stego_hide_progress(0.0, "Starting...")

        # Checks
        if not carrier_path or not os.path.exists(carrier_path):
            self._update_stego_hide_progress(0.0, "Error: Carrier not found")
            return

        if not data_path or not os.path.exists(data_path):
            self._update_stego_hide_progress(0.0, "Error: Data file not found")
            return

        with open(data_path, 'rb') as f:
            data = f.read()

        # Call with progress callback
        result = self.stego_engine.hide_in_image(
            data=data,
            carrier_path=carrier_path,
            output_path=output_path,
            password=password,
            method=method,
            progress_callback=self._update_stego_hide_progress,
            compress=compress,
            log_callback=self._log_stego
        )

        if result["success"]:
            self._update_stego_hide_progress(1.0, "Success!")
            self._log_stego(f"Data hidden: {output_path}")
        else:
            self._update_stego_hide_progress(0.0, "Failed")
            self._log_stego(f"Error: {result['error']}")

    
    def _extract_data_stego(self):
        stego_path = dpg.get_value("stego_extract_file")
        output_path = dpg.get_value("stego_extract_output")
        password = dpg.get_value("stego_extract_password").strip() or None

        self._reset_stego_progress()
        self._update_stego_extract_progress(0.0, "Starting...")

        if not stego_path or not os.path.exists(stego_path):
            self._update_stego_extract_progress(0.0, "Error: File not found")
            return

        if not output_path:
            self._update_stego_extract_progress(0.0, "Error: No output path")
            return

        result = self.stego_engine.extract_from_image(
            stego_path=stego_path,
            output_path=output_path,
            password=password,
            progress_callback=self._update_stego_extract_progress,
            log_callback=self._log_stego_extract
        )

        if result["success"]:
            self._update_stego_extract_progress(1.0, "Extracted!")
            self._log_stego(f"Data saved: {output_path}")
        else:
            self._update_stego_extract_progress(0.0, "Failed")
            self._log_stego(f"Error: {result['error']}")

    
    def _update_stego_hide_progress(self, value: float, label: str = ""):
        """Update hide progress bar"""
        if dpg.does_item_exist("stego_hide_progress"):
            dpg.set_value("stego_hide_progress", value)
        if dpg.does_item_exist("stego_hide_status"):
            dpg.set_value("stego_hide_status", label)
        if dpg.does_item_exist("stego_hide_progress"):
            dpg.configure_item("stego_hide_progress", show=True)

    def _update_stego_extract_progress(self, value: float, label: str = ""):
        """Update extract progress bar"""
        if dpg.does_item_exist("stego_extract_progress"):
            dpg.set_value("stego_extract_progress", value)
        if dpg.does_item_exist("stego_extract_status"):
            dpg.set_value("stego_extract_status", label)
        if dpg.does_item_exist("stego_extract_progress"):
            dpg.configure_item("stego_extract_progress", show=True)

    def _reset_stego_progress(self):
        """Hide both progress bars"""
        if dpg.does_item_exist("stego_hide_progress"):
            dpg.configure_item("stego_hide_progress", show=False)
            dpg.set_value("stego_hide_progress", 0.0)
        if dpg.does_item_exist("stego_extract_progress"):
            dpg.configure_item("stego_extract_progress", show=False)
            dpg.set_value("stego_extract_progress", 0.0)



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

    def _log_stego(self, message: str):
        """Log message to stego hide log with timestamp"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        current_log = dpg.get_value("stego_hide_log") if dpg.does_item_exist("stego_hide_log") else ""
        
        updated_log = current_log + log_entry
        
        # Restrict to last 1000 lines
        log_lines = updated_log.splitlines()
        if len(log_lines) > 1000:
            updated_log = '\n'.join(log_lines[-1000:])
        
        # Update log
        if dpg.does_item_exist("stego_hide_log"):
            dpg.set_value("stego_hide_log", updated_log)
            dpg.set_value("stego_hide_log", updated_log)  # Just beacuse.

    def _log_stego_extract(self, message: str):
        """Log message to stego extract log"""
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        current_log = dpg.get_value("stego_extract_log") if dpg.does_item_exist("stego_extract_log") else ""
        updated_log = current_log + log_entry
        
        log_lines = updated_log.splitlines()
        if len(log_lines) > 1000:
            updated_log = '\n'.join(log_lines[-1000:])
        
        if dpg.does_item_exist("stego_extract_log"):
            dpg.set_value("stego_extract_log", updated_log)
            dpg.set_value("stego_extract_log", updated_log)


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

# ============ Steganography END ============ #

# ============ Vulnerability ============ #
    def _create_vulnerability_scan_content(self):
        dpg.add_text("Vulnerability Scanner", color=[0, 200, 255])
        dpg.add_separator()

        with dpg.group(horizontal=True):
            dpg.add_text("Directory to Scan:")
            dpg.add_input_text(tag="scan_directory", width=400, readonly=True, hint="Select directory...")
            dpg.add_button(label="Browse", callback=self._show_scan_directory_dialog)

        dpg.add_checkbox(label="Scan Subdirectories", tag="scan_recursive", default_value=True)
        dpg.add_checkbox(label="Show All Files", tag="scan_show_all", default_value=False)

        with dpg.group(horizontal=True):
            dpg.add_button(label="Start Scan", callback=self._start_vulnerability_scan)
            dpg.add_button(label="Export Results", callback=self._export_scan_results)
            dpg.add_button(label="Clear", callback=self._clear_scan_results)

        with dpg.group(horizontal=True):
            dpg.add_text("Status:")
            dpg.add_text("Ready", tag="scan_status", color=[0, 200, 0])
            dpg.add_progress_bar(tag="scan_progress", show=False, width=200)

        dpg.add_text("Scan Summary:", color=[200, 200, 0])
        with dpg.table(tag="scan_summary_table", header_row=True, borders_innerH=True, borders_innerV=True, width=-1):
            dpg.add_table_column(label="Metric")
            dpg.add_table_column(label="Value")

        dpg.add_text("Scan Results:", color=[200, 200, 0])
        with dpg.tab_bar():
            with dpg.tab(label="Issues"):
                with dpg.table(tag="scan_issues_table", header_row=True, resizable=True, scrollY=True, height=200):
                    dpg.add_table_column(label="File"); dpg.add_table_column(label="Issue")
                    dpg.add_table_column(label="Severity"); dpg.add_table_column(label="Description")
            with dpg.tab(label="Files"):
                with dpg.table(tag="scan_files_table", header_row=True, resizable=True, scrollY=True, height=200):
                    dpg.add_table_column(label="File"); dpg.add_table_column(label="Size")
                    dpg.add_table_column(label="Issues"); dpg.add_table_column(label="Risk")

        dpg.add_text("Details:", color=[200, 200, 0])
        dpg.add_input_text(tag="scan_details", multiline=True, readonly=True, height=150, width=-1)


    def _show_scan_directory_dialog(self):
        """Show directory selection dialog for vulnerability scan"""
        def dir_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                dpg.set_value("scan_directory", app_data['file_path_name'])
        
        with dpg.file_dialog(
            directory_selector=True,
            show=True,
            callback=dir_callback,
            width=700,
            height=400
        ):
            pass

    def _start_vulnerability_scan(self):
        """Start vulnerability scan"""
        directory = dpg.get_value("scan_directory")
        if not directory:
            self.log_message("Select directory to scan", "scan")
            return
        
        if not os.path.exists(directory):
            self.log_message("Directory not found", "scan")
            return
        
        # Initialize scanner
        if not hasattr(self, 'vulnerability_scanner'):
            from core.vulnerability_scanner import VulnerabilityScanner
            self.vulnerability_scanner = VulnerabilityScanner(self.settings)
        
        # Update UI
        dpg.set_value("scan_status", "Scanning...")
        dpg.configure_item("scan_progress", show=True)
        dpg.set_value("scan_details", "")
        
        # Clear previous results
        self._clear_scan_results(clear_directory=False)
        
        # Start scan in background
        operation_id = "vulnerability_scan"
        
        def scan_operation():
            try:
                recursive = dpg.get_value("scan_recursive")
                results = self.vulnerability_scanner.scan_directory(directory, recursive)
                
                # Store results
                self._current_scan_results = results
                
                # Update UI
                self._update_scan_ui(results)
                self.log_message("Vulnerability scan completed", "scan")
                dpg.set_value("scan_status", "Completed")
                
            except Exception as e:
                self.log_message(f"Scan failed: {str(e)}", "scan")
                dpg.set_value("scan_status", "Error")
            finally:
                dpg.configure_item("scan_progress", show=False)
        
        # Start operation
        self.operation_manager.start_operation(operation_id, scan_operation)

    def _update_scan_ui(self, results: Dict[str, Any]):
        """Update UI with scan results"""
        try:
            # Update summary table
            summary_table = "scan_summary_table"
            if dpg.does_item_exist(summary_table):
                # Clear existing rows
                children = dpg.get_item_children(summary_table)[1]
                for child in children:
                    dpg.delete_item(child)
                
                # Add summary rows
                summary = results['summary']
                scan_info = results['scan_info']
                
                with dpg.table_row(parent=summary_table):
                    dpg.add_text("Files Scanned:")
                    dpg.add_text(f"{summary['scanned_files']}/{summary['total_files']}")
                
                with dpg.table_row(parent=summary_table):
                    dpg.add_text("Issues Found:")
                    dpg.add_text(str(summary['issues_found']), color=[255, 100, 100] if summary['issues_found'] > 0 else [100, 255, 100])
                
                with dpg.table_row(parent=summary_table):
                    dpg.add_text("Risk Level:")
                    risk_level = self.vulnerability_scanner.get_risk_level(summary['risk_score'])
                    dpg.add_text(risk_level, color=self._get_risk_color(summary['risk_score']))
                
                with dpg.table_row(parent=summary_table):
                    dpg.add_text("Scan Time:")
                    dpg.add_text(scan_info['timestamp'])
            
            # Update issues table
            issues_table = "scan_issues_table"
            if dpg.does_item_exist(issues_table):
                # Clear existing rows
                children = dpg.get_item_children(issues_table)[1]
                for child in children:
                    dpg.delete_item(child)
                
                # Add issues
                for file_result in results['files']:
                    for issue in file_result['issues']:
                        with dpg.table_row(parent=issues_table):
                            dpg.add_text(os.path.basename(file_result['path']))
                            dpg.add_text(issue['type'])
                            dpg.add_text(issue['severity'].upper(), color=self._get_severity_color(issue['severity']))
                            dpg.add_text(issue['description'])
            
            # Update files table
            files_table = "scan_files_table"
            if dpg.does_item_exist(files_table):
                # Clear existing rows
                children = dpg.get_item_children(files_table)[1]
                for child in children:
                    dpg.delete_item(child)
                
                # Add files
                show_all = dpg.get_value("scan_show_all")
                for file_result in results['files']:
                    if show_all or file_result['issues']:
                        with dpg.table_row(parent=files_table):
                            dpg.add_text(os.path.basename(file_result['path']))
                            dpg.add_text(f"{file_result['size']} bytes")
                            dpg.add_text(str(len(file_result['issues'])))
                            dpg.add_text("High", color=[255, 100, 100])
            
        except Exception as e:
            self.logger.error(f"Error updating scan UI: {e}")

    def _get_severity_color(self, severity: str) -> list:
        """Get color for severity level"""
        colors = {
            'critical': [255, 0, 0],
            'high': [255, 100, 0],
            'medium': [255, 200, 0],
            'low': [100, 255, 100]
        }
        return colors.get(severity.lower(), [200, 200, 200])

    def _get_risk_color(self, risk_score: int) -> list:
        """Get color for risk level"""
        if risk_score >= 80:
            return [255, 0, 0]
        elif risk_score >= 60:
            return [255, 100, 0]
        elif risk_score >= 40:
            return [255, 200, 0]
        elif risk_score >= 20:
            return [100, 200, 255]
        else:
            return [100, 255, 100]

    def _export_scan_results(self):
        """Export scan results to file"""
        if not hasattr(self, '_current_scan_results'):
            self.log_message("No scan results to export", "scan")
            return
        
        def save_callback(sender, app_data):
            if app_data and 'file_path_name' in app_data:
                try:
                    output_path = app_data['file_path_name']
                    if not output_path.endswith('.json'):
                        output_path += '.json'
                    
                    self.vulnerability_scanner.export_results(self._current_scan_results, output_path)
                    self.log_message(f"Scan results exported to {output_path}", "scan")
                except Exception as e:
                    self.log_message(f"Export failed: {str(e)}", "scan")
        
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=save_callback,
            width=700,
            height=400
        ):
            dpg.add_file_extension("JSON Files (*.json){.json}")
            dpg.add_file_extension("All Files (*.*){.*}")

    def _clear_scan_results(self, clear_directory: bool = True):
        """Clear scan results"""
        # Clear tables
        for table_tag in ["scan_summary_table", "scan_issues_table", "scan_files_table"]:
            if dpg.does_item_exist(table_tag):
                children = dpg.get_item_children(table_tag)[1]
                for child in children:
                    dpg.delete_item(child)
        
        # Clear details
        dpg.set_value("scan_details", "")
        
        # Clear directory if requested
        if clear_directory:
            dpg.set_value("scan_directory", "")

# ============ Vulnerability END ============ #

# ============ Secure Folder ============ #
    def _show_secure_folder_dialog(self):
        with dpg.file_dialog(
            directory_selector=True,
            show=True,
            callback=self._select_secure_folder,
            width=700,
            height=400
        ):
            # You can add file extensions here
            dpg.add_file_extension("All Files (*.*){.*}")


    def _select_secure_folder(self, sender, app_data):
        folder = app_data['file_path_name']
        dpg.set_value("secure_folder_path", folder)

    def _generate_secure_folder_password(self):
        password = self.crypto_engine.generate_secure_key().hex()[:32]
        dpg.set_value("secure_folder_password", password)

    def _start_secure_folder(self):
        folder = dpg.get_value("secure_folder_path").strip()
        password = dpg.get_value("secure_folder_password").strip()
        algorithm = dpg.get_value("secure_folder_algorithm").strip()

        if not folder or not os.path.exists(folder):
            self._log_secure_folder("Folder not valid")
            return
        if not password:
            self._log_secure_folder("Password required")
            return
        if not algorithm:
            self._log_secure_folder("Algorithm not selected")
            return

        try:
            self.secure_folder_manager = SecureFolderManager(
                folder_path=folder,
                password=password,
                crypto_engine=self.crypto_engine,
                algorithm=algorithm,
                log_callback=lambda msg: self._log_secure_folder(f"SecureFolder: {msg}"),
                settings=self.settings
            )
            self.settings.increment_session()
            self.secure_folder_manager.start_monitoring()

            dpg.configure_item("secure_folder_start_btn", show=False)
            dpg.configure_item("secure_folder_stop_btn", show=True)

            dpg.set_value("secure_folder_status", "Status: Monitoring...")
            self._log_secure_folder(f"Started with {algorithm}")

        except Exception as e:
            self._log_secure_folder(f"Failed: {e}")



    def _stop_secure_folder(self):
        if hasattr(self, "secure_folder_manager"):
            self.secure_folder_manager.stop_monitoring()
            self.secure_folder_manager.cleanup_temp_files()
            del self.secure_folder_manager

        dpg.configure_item("secure_folder_start_btn", show=True)
        dpg.configure_item("secure_folder_stop_btn", show=False)
        dpg.set_value("secure_folder_status", "Status: Stopped")
        self._log_secure_folder("Monitoring stopped")


        # Save algorythm
        current_algo = dpg.get_value("secure_folder_algorithm")
        self.settings.set("secure_folder.algorithm", current_algo)


    def _log_secure_folder(self, message: str):
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        current = dpg.get_value("secure_folder_log") or ""
        dpg.set_value("secure_folder_log", current + log_entry)

    
    def _decrypt_and_open_file(self):
        """Открыть диалог выбора .enc файла с фильтрами"""
        with dpg.file_dialog(
            directory_selector=False,
            show=True,
            callback=self._on_enc_file_selected,
            width=700,
            height=400,
            modal=False
        ):
            dpg.add_file_extension("Encrypted Files (*.enc){.enc}")
            dpg.add_file_extension("All Files (*.*){.*}")
            
    def _on_enc_file_selected(self, sender, app_data):
        file_path = app_data.get("file_path_name", "").strip()
        
        if not file_path:
            self._log_secure_folder("No file selected")
            return
        
        if not file_path.lower().endswith(".enc"):
            self._log_secure_folder("Please select a .enc file")
            return

        password = dpg.get_value("secure_folder_password").strip()
        if not password:
            self._log_secure_folder("Password required")
            return

        if not hasattr(self, "secure_folder_manager"):
            self._log_secure_folder("Secure folder not running")
            return

        try:
            decrypted_path = self.secure_folder_manager.decrypt_file(Path(file_path))
            if not decrypted_path:
                self._log_secure_folder("Decryption failed")
                return

            self._log_secure_folder(f"Decrypted: {decrypted_path.name}")

            # Открыть в системе
            try:
                if os.name == 'nt':
                    os.startfile(decrypted_path)
                self._log_secure_folder(f"Opened: {decrypted_path.name}")
            except Exception as e:
                self._log_secure_folder(f"Failed to open: {e}")

        except Exception as e:
            self._log_secure_folder(f"Error: {str(e)}")

    def _clean_secure_temp(self):
        temp_dir = Path(dpg.get_value("secure_folder_path")) / ".temp_decrypted"
        if temp_dir.exists():
            deleted = 0
            for f in temp_dir.iterdir():
                if f.is_file():
                    f.unlink()
                    deleted += 1
            self._log_secure_folder(f"Cleaned {deleted} temporary files")
        else:
            self._log_secure_folder("No temp files to clean")

# ============ Secure Folder END ============ #

# ============ "About" stats ============ #
    def update_stats_display(self):
        """Обновить отображение статистики в About"""
        try:
            # Получаем текущие значения
            enc_count = self.settings.get("statistics.secure_folder.files_encrypted", 0)
            dec_count = self.settings.get("statistics.secure_folder.files_decrypted", 0)
            sessions = self.settings.get("statistics.secure_folder.sessions_count", 0)
            last = self.settings.get("statistics.secure_folder.last_session", "Never")

            total_enc = self.settings.get("statistics.general.total_files_encrypted", 0)
            total_msg = self.settings.get("statistics.general.total_messages_encrypted", 0)

            # Обновляем текст
            dpg.set_value("stats_encrypted", f"Files Encrypted: {enc_count}")
            dpg.set_value("stats_decrypted", f"Files Decrypted: {dec_count}")
            dpg.set_value("stats_sessions", f"Active Sessions: {sessions}")
            dpg.set_value("stats_last_session", f"Last Session: {last}")
            dpg.set_value("stats_total_enc", f"Total Files Encrypted: {total_enc}")
            dpg.set_value("stats_total_msg", f"Messages Encrypted: {total_msg}")

        except Exception as e:
            print(f"Failed to update stats display: {e}")


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
            #dpg.set_viewport_close_callback(self._on_app_close) # Not Working? Invalid callback.
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

    def _on_app_close(self):
        """Вызывается при попытке закрыть окно"""
        self._log("Auto-lock: shutting down Secure Folder...")
        
        # Останавливаем Secure Folder, если запущен
        if hasattr(self, "secure_folder_manager"):
            try:
                self.secure_folder_manager.stop_monitoring()
                self.secure_folder_manager.cleanup_temp_files()
                self._log("Secure Folder stopped and temp files cleaned")
            except Exception as e:
                self._log(f"Error during auto-lock: {e}")
        
        # Даём системе время на завершение
        import time
        time.sleep(0.3)
        
        # Закрываем приложение
        dpg.stop_dearpygui()
