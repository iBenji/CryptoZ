import dearpygui.dearpygui as dpg
import logging
import sys
import os
from pathlib import Path
from logging.handlers import RotatingFileHandler
from gui.main_window import MainWindow


def setup_logging():
    """Logging configuration"""
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_dir / 'cryptoz.log', encoding='utf-8'),
            logging.StreamHandler(sys.stdout),
        ]
    )


def setup_icon():
    """Setup application icon"""
    try:
        if os.path.exists("assets/icon.ico"):
            dpg.set_viewport_small_icon("assets/icon.ico")
            dpg.set_viewport_large_icon("assets/icon.ico")
            logging.info("Application icon set")
            return True
        return False
    except Exception as e:
        logging.error(f"Error setting icon: {e}")
        return False


def check_dependencies():
    """Check required dependencies"""
    try:
        import cryptography
        import Crypto
        import dearpygui
        return True
    except ImportError as e:
        print(f"Missing dependency: {e}")
        return False


def main():
    """Main application entry point"""
    try:
        setup_logging()
        logger = logging.getLogger(__name__)
        
        logger.info("Starting CryptoZ application")
        
        if not check_dependencies():
            logger.error("Required dependencies not available")
            sys.exit(1)
        
        # Create and run main window
        app = MainWindow()
        logger.info("Application initialized successfully")
        
        # Setup application icon
        setup_icon()
        
        app.run()
        
        logger.info("Application shutdown completed")
        
    except Exception as e:
        logging.critical(f"Application startup error: {e}", exc_info=True)
        print(f"Application error: {e}")
        sys.exit(1)
    finally:
        try:
            dpg.destroy_context()
        except:
            pass


if __name__ == "__main__":
    main()