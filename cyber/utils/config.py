"""
Configuration management for the Attack Path Intelligence Engine
"""
import yaml
from pathlib import Path
from typing import Dict, Any
from utils.logger import engine_logger

class Config:
    """Singleton configuration manager"""
    
    _instance = None
    _config = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._config is None:
            self.load_config()
    
    def load_config(self, config_path: str = "config.yaml"):
        """Load configuration from YAML file"""
        try:
            config_file = Path(config_path)
            if not config_file.exists():
                engine_logger.warning(f"Config file {config_path} not found, using defaults")
                self._config = self._get_default_config()
                return
            
            with open(config_file, 'r') as f:
                self._config = yaml.safe_load(f)
            
            engine_logger.info(f"Configuration loaded from {config_path}")
        except Exception as e:
            engine_logger.error(f"Error loading config: {e}")
            self._config = self._get_default_config()
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Return default configuration"""
        return {
            'database': {
                'neo4j': {
                    'uri': 'bolt://localhost:7687',
                    'user': 'neo4j',
                    'password': 'password'
                }
            },
            'risk_weights': {
                'cvss': 0.25,
                'epss': 0.20,
                'exploitability': 0.20,
                'chain_potential': 0.15,
                'zdes': 0.10,
                'path_impact': 0.10
            },
            'zero_day': {
                'zdes_threshold': 70,
                'anomaly_sensitivity': 0.8
            },
            'attack_graph': {
                'max_path_length': 5,
                'min_cvss_threshold': 4.0
            }
        }
    
    def get(self, key: str, default=None):
        """Get configuration value by dot-notation key"""
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict):
                value = value.get(k)
                if value is None:
                    return default
            else:
                return default
        
        return value
    
    def get_all(self) -> Dict[str, Any]:
        """Get entire configuration"""
        return self._config

# Global config instance
config = Config()
