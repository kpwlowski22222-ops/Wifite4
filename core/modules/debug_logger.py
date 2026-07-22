import logging
import json
import traceback
import sys
from datetime import datetime
from typing import Any, Dict, Optional
from functools import wraps
import asyncio

class DebugLogger:
    """Enhanced debugging logger for the WiFi Offensive AI Toolkit"""
    
    def __init__(self, name: str, debug_mode: bool = False):
        self.logger = logging.getLogger(name)
        self.debug_mode = debug_mode
        self.setup_debug_logging()
        
    def setup_debug_logging(self):
        """Setup detailed debug logging format"""
        if not self.logger.handlers:  # Avoid duplicate handlers
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter(
                '%(asctime)s | %(name)-20s | %(levelname)-8s | %(message)s',
                datefmt='%H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
            
    def debug(self, msg: str, *args, **kwargs):
        """Log debug message"""
        if self.debug_mode:
            self.logger.debug(msg, *args, **kwargs)
            
    def info(self, msg: str, *args, **kwargs):
        """Log info message"""
        self.logger.info(msg, *args, **kwargs)
        
    def warning(self, msg: str, *args, **kwargs):
        """Log warning message"""
        self.logger.warning(msg, *args, **kwargs)
        
    def error(self, msg: str, *args, **kwargs):
        """Log error message"""
        self.logger.error(msg, *args, **kwargs)
        
    def critical(self, msg: str, *args, **kwargs):
        """Log critical message"""
        self.logger.critical(msg, *args, **kwargs)
        
    def debug_dict(self, label: str, data: Dict[str, Any]):
        """Debug log a dictionary in formatted JSON"""
        if self.debug_mode:
            formatted = json.dumps(data, indent=2, default=str)
            self.logger.debug(f"{label}:\n{formatted}")
            
    def debug_exception(self, label: str = "Exception"):
        """Debug log the last exception with full traceback"""
        if self.debug_mode:
            self.logger.debug(f"{label}: {traceback.format_exc()}")
            
    def time_it(self, func):
        """Decorator to time function execution"""
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start = datetime.now()
            try:
                result = await func(*args, **kwargs)
                elapsed = (datetime.now() - start).total_seconds()
                self.debug(f"{func.__name__} completed in {elapsed:.3f}s")
                return result
            except Exception as e:
                elapsed = (datetime.now() - start).total_seconds()
                self.error(f"{func.__name__} failed after {elapsed:.3f}s: {e}")
                self.debug_exception(f"{func.__name__} exception")
                raise
                
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            start = datetime.now()
            try:
                result = func(*args, **kwargs)
                elapsed = (datetime.now() - start).total_seconds()
                self.debug(f"{func.__name__} completed in {elapsed:.3f}s")
                return result
            except Exception as e:
                elapsed = (datetime.now() - start).total_seconds()
                self.error(f"{func.__name__} failed after {elapsed:.3f}s: {e}")
                self.debug_exception(f"{func.__name__} exception")
                raise
                
        return async_wrapper if asyncio.iscoroutinefunction(func) else sync_wrapper

# Global debug logger instance
debug_logger = DebugLogger("wifi_offensive_toolkit")

def enable_debug_mode():
    """Enable debug mode globally"""
    debug_logger.debug_mode = True
    debug_logger.logger.setLevel(logging.DEBUG)
    # Update all existing loggers
    for logger_name in logging.Logger.manager.loggerDict:
        logging.getLogger(logger_name).setLevel(logging.DEBUG)

def disable_debug_mode():
    """Disable debug mode globally"""
    debug_logger.debug_mode = False
    debug_logger.logger.setLevel(logging.INFO)
    # Update all existing loggers to WARNING or higher to reduce noise
    for logger_name in logging.Logger.manager.loggerDict:
        if not logger_name.startswith('core'):
            logging.getLogger(logger_name).setLevel(logging.WARNING)

# Convenience functions
def debug(msg: str, *args, **kwargs):
    debug_logger.debug(msg, *args, **kwargs)

def info(msg: str, *args, **kwargs):
    debug_logger.info(msg, *args, **kwargs)

def warning(msg: str, *args, **kwargs):
    debug_logger.warning(msg, *args, **kwargs)

def error(msg: str, *args, **kwargs):
    debug_logger.error(msg, *args, **kwargs)

def critical(msg: str, *args, **kwargs):
    debug_logger.critical(msg, *args, **kwargs)

def debug_dict(label: str, data: Dict[str, Any]):
    debug_logger.debug_dict(label, data)

def debug_exception(label: str = "Exception"):
    debug_logger.debug_exception(label)

def time_it(func):
    return debug_logger.time_it(func)