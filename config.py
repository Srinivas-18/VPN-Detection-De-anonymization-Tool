import os
from typing import Optional

class Config:
    """Configuration management for the VPN Detection & De-anonymization project"""
    
    # API Keys
    GEMINI_API_KEY: Optional[str] = 'AIzaSyAjnTpdS8TIk87I9N7RxYhVsoI40AnURes'
    IPGEO_API_KEY: Optional[str] = '8bfb49775bc546b2aff5219404fa64c3'
    
    # Analysis Settings
    MAX_PACKETS_FOR_ANALYSIS: int = 10000
    PAYLOAD_MAX_LENGTH: int = 200
    CACHE_ENABLED: bool = True
    CACHE_FILE: str = "analysis_cache.json"
    
    # Performance Settings
    PARALLEL_PROCESSING: bool = True
    MAX_WORKERS: int = 4
    
    # Export Settings
    DEFAULT_EXPORT_FORMAT: str = "csv"
    INCLUDE_AI_ANALYSIS: bool = True
    
    @classmethod
    def load_from_env(cls):
        """Load configuration from environment variables"""
        # Only override if environment variable is set
        env_gemini_key = os.getenv('GEMINI_API_KEY')
        if env_gemini_key:
            cls.GEMINI_API_KEY = env_gemini_key
            
        env_ipgeo_key = os.getenv('IPGEO_API_KEY')
        if env_ipgeo_key:
            cls.IPGEO_API_KEY = env_ipgeo_key
        
        # Load other settings
        cls.MAX_PACKETS_FOR_ANALYSIS = int(os.getenv('MAX_PACKETS', cls.MAX_PACKETS_FOR_ANALYSIS))
        cls.CACHE_ENABLED = os.getenv('CACHE_ENABLED', 'true').lower() == 'true'
        cls.PARALLEL_PROCESSING = os.getenv('PARALLEL_PROCESSING', 'true').lower() == 'true'
    
    @classmethod
    def is_ai_enabled(cls) -> bool:
        """Check if AI features are enabled"""
        return cls.GEMINI_API_KEY is not None
    
    @classmethod
    def get_api_key(cls, api_name: str) -> Optional[str]:
        """Get API key by name"""
        api_keys = {
            'gemini': cls.GEMINI_API_KEY,
            'ipgeo': cls.IPGEO_API_KEY
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
