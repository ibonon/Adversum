#!/usr/bin/env python3
"""
Base Solidity Tool Adapter
Defines interface for external Solidity SAST tools (Slither, Aderyn, etc.)
"""
import os
import shutil
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

class BaseSolidityAdapter(ABC):
    def __init__(self, executable_path: Optional[str] = None):
        self.executable_path = executable_path or self._find_executable()

    @abstractmethod
    def tool_name(self) -> str:
        """Returns tool name (e.g. 'Slither', 'Aderyn')."""
        pass

    @abstractmethod
    def _default_executable_name(self) -> str:
        """Default binary name in PATH."""
        pass

    @abstractmethod
    def _env_var_name(self) -> str:
        """Environment variable that can override binary path."""
        pass

    def _find_executable(self) -> Optional[str]:
        # 1. Environment variable
        env_path = os.environ.get(self._env_var_name())
        if env_path and os.path.exists(env_path):
            return env_path
        # 2. System PATH
        return shutil.which(self._default_executable_name())

    def is_available(self) -> bool:
        """Returns True if the tool binary is found on system."""
        return bool(self.executable_path and (os.path.exists(self.executable_path) or shutil.which(self.executable_path)))

    @abstractmethod
    def run(self, target_path: str, timeout: int = 300) -> List[Any]:
        """Runs tool on target file or project directory and returns normalized SolFinding objects."""
        pass

    @abstractmethod
    def parse_json_output(self, raw_json: str, target_path: str) -> List[Any]:
        """Parses tool's raw JSON output and returns normalized SolFinding objects."""
        pass
