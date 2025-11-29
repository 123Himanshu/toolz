"""
Base parser class for all scanner ingestors
"""
from abc import ABC, abstractmethod
from typing import List, Dict, Any
from pathlib import Path
from models.schemas import NormalizedVulnerability
from utils.logger import engine_logger

class BaseParser(ABC):
    """Abstract base class for all scanner parsers"""
    
    def __init__(self, scanner_name: str):
        self.scanner_name = scanner_name
        self.logger = engine_logger
    
    @abstractmethod
    def parse(self, file_path: str) -> List[NormalizedVulnerability]:
        """Parse scanner output and return normalized vulnerabilities"""
        pass
    
    def validate_file(self, file_path: str) -> bool:
        """Validate that file exists and is readable"""
        path = Path(file_path)
        if not path.exists():
            self.logger.error(f"File not found: {file_path}")
            return False
        if not path.is_file():
            self.logger.error(f"Not a file: {file_path}")
            return False
        return True
    
    def handle_parse_error(self, error: Exception, context: str = ""):
        """Centralized error handling for parsing"""
        self.logger.error(f"[{self.scanner_name}] Parse error {context}: {str(error)}")
        return []
    
    def generate_asset_id(self, ip: str = None, hostname: str = None) -> str:
        """Generate consistent asset ID"""
        if ip:
            return f"asset_{ip.replace('.', '_')}"
        elif hostname:
            return f"asset_{hostname.replace('.', '_')}"
        return f"asset_unknown_{id(self)}"
