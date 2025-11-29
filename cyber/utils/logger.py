"""
Centralized logging configuration for the Attack Path Intelligence Engine
"""
import sys
from pathlib import Path
from loguru import logger
from datetime import datetime

class EngineLogger:
    """Singleton logger for the entire system"""
    
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
            
        self._initialized = True
        
        # Remove default handler
        logger.remove()
        
        # Create logs directory
        Path("logs").mkdir(exist_ok=True)
        
        # Console handler with color
        logger.add(
            sys.stderr,
            format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <level>{level: <8}</level> | <cyan>{name}</cyan>:<cyan>{function}</cyan> - <level>{message}</level>",
            level="INFO",
            colorize=True
        )
        
        # File handler with rotation
        logger.add(
            "logs/engine_{time:YYYY-MM-DD}.log",
            rotation="500 MB",
            retention="30 days",
            level="DEBUG",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
        )
        
        # Error file handler
        logger.add(
            "logs/errors_{time:YYYY-MM-DD}.log",
            rotation="100 MB",
            retention="90 days",
            level="ERROR",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} - {message}"
        )
        
        self.logger = logger
    
    def get_logger(self):
        return self.logger

# Global logger instance
engine_logger = EngineLogger().get_logger()
