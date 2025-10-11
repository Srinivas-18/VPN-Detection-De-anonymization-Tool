import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Configuration management for the VPN Detection & De-anonymization project"""
    
    # API Keys - loaded from environment variables
    GEMINI_API_KEY: Optional[str] = os.getenv('GEMINI_API_KEY')
    IPGEO_API_KEY: Optional[str] = os.getenv('IPGEO_API_KEY')
    VPN_API_KEY: Optional[str] = os.getenv('VPN_API_KEY')
    
    # Analysis Settings
    MAX_PACKETS_FOR_ANALYSIS: int = int(os.getenv('MAX_PACKETS', '10000'))
    PAYLOAD_MAX_LENGTH: int = 200
    CACHE_ENABLED: bool = os.getenv('CACHE_ENABLED', 'true').lower() == 'true'
    CACHE_FILE: str = "analysis_cache.json"
    
    # Performance Settings
    PARALLEL_PROCESSING: bool = os.getenv('PARALLEL_PROCESSING', 'true').lower() == 'true'
    MAX_WORKERS: int = 4
    
    # Export Settings
    DEFAULT_EXPORT_FORMAT: str = "csv"
    INCLUDE_AI_ANALYSIS: bool = True
    
    @classmethod
    def load_from_env(cls):
        """Load configuration from environment variables (legacy method - now handled at class level)"""
        # This method is kept for backward compatibility
        # All environment variables are now loaded automatically when the class is defined
        pass
    
    @classmethod
    def is_ai_enabled(cls) -> bool:
        """Check if AI features are enabled"""
        return cls.GEMINI_API_KEY is not None
    
    @classmethod
    def get_api_key(cls, api_name: str) -> Optional[str]:
        """Get API key by name"""
        api_keys = {
            'gemini': cls.GEMINI_API_KEY,
            'ipgeo': cls.IPGEO_API_KEY,
            'vpn': cls.VPN_API_KEY
        }
        return api_keys.get(api_name.lower())
    
    @classmethod
    def validate_config(cls) -> list:
        """Validate configuration and return list of issues"""
        issues = []
        
        if not cls.GEMINI_API_KEY:
            issues.append("GEMINI_API_KEY not set - AI analysis features will be disabled")
        
        if not cls.IPGEO_API_KEY:
            issues.append("IPGEO_API_KEY not set - Geolocation may be limited")
        
        return issues

# Load configuration on import
Config.load_from_env()
