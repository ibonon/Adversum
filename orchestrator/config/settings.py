from pydantic import Field
import os
from typing import Set, List

class Settings:
    """
    Centralized configuration for the Orchestrator.
    Using simple class for now, easily upgradeable to Pydantic BaseSettings.
    """
    PROJECT_NAME: str = "Adversum Orchestrator"
    VERSION: str = "0.2.0"
    
    # Scanner Settings
    IGNORED_DIRECTORIES: Set[str] = {
        ".git", ".svn", ".hg", ".idea", ".vscode",
        "node_modules", "venv", ".venv", "env", "__pycache__",
        "dist", "build", "target", "bin", "obj"
    }
    
    SUPPORTED_EXTENSIONS: Set[str] = {
        ".py", ".rs", ".js", ".ts", ".jsx", ".tsx",
        ".c", ".cpp", ".h", ".hpp",
        ".java", ".go"
    }
    
    # Core Bridge Settings
    CORE_BINARY_PATH: str = "adversum_core" # expected on PATH or overridden
    # MOCK_CORE forces the Python fallback engine regardless of whether the
    # compiled Rust extension (adversum_core.pyd) is available. Production and
    # the default pipeline must run against the real Rust core, so this is off
    # by default. Set ADVERSUM_MOCK_CORE=true only in isolated tests where the
    # native engine cannot be built.
    # NOTE: Settings is a plain class (not pydantic BaseSettings), so we must
    # resolve the env value eagerly; Field(default_factory=...) would stay an
    # unresolved FieldInfo object at runtime.
    MOCK_CORE: bool = False

    # API Settings
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    ALLOWED_ORIGINS: List[str] = ["http://localhost:3000"] # Strict default
    
    # Rate Limiting
    RATE_LIMIT_STRATEGY: str = "fixed-window"
    RATE_LIMIT_ANALYZE: str = "10/minute" # Strict limit for heavy jobs
    MAX_BODY_SIZE: int = 1024 * 1024 # 1MB Limit for request bodies
    
    # Database Settings
    DATABASE_URL: str = "sqlite:///./adversum.db"
    
    # Security Settings
    API_KEY_HEADER_NAME: str = "X-API-KEY"
    
    # Secrets MUST be loaded from environment variables
    # We provide a default for dev ONLY if strictly necessary, otherwise fail
    API_KEY_SECRET: str = os.getenv("API_KEY_SECRET", "adv-dev-key-123")
    
    # AES-256 Key
    # In production, this must be set via DATA_ENCRYPTION_KEY env var
    DATA_ENCRYPTION_KEY: str = os.getenv("DATA_ENCRYPTION_KEY", "J1qK8_8f9L4n5P6q2R3s4T5u6V7w8X9y0Z1a2B3c4D5=")

    def __init__(self, **values):
        super().__init__(**values)
        # Resolve MOCK_CORE eagerly from the environment. Settings is a plain
        # class (not pydantic BaseSettings), so the class-level Field(...) value
        # would never be evaluated; we read the env var here instead.
        self.MOCK_CORE = os.getenv("ADVERSUM_MOCK_CORE", "false").lower() == "true"
        # In production, enforce strong secrets
        if os.getenv("ADVERSUM_ENV") == "production":
            if self.API_KEY_SECRET == "adv-dev-key-123":
                 raise ValueError("CRITICAL: Default API_KEY_SECRET used in production!")
            if self.DATA_ENCRYPTION_KEY == "J1qK8_8f9L4n5P6q2R3s4T5u6V7w8X9y0Z1a2B3c4D5=":
                 raise ValueError("CRITICAL: Default DATA_ENCRYPTION_KEY used in production!")

settings = Settings()
