import os
from typing import List

class Scanner:
    def __init__(self, root_path: str):
        self.root_path = root_path
        self.ignore_dirs = {'.git', 'node_modules', 'target', '__pycache__', '.venv', 'dist', 'build'}
        self.extensions = {'.py', '.rs', '.js', '.ts', '.c', '.cpp', '.java', '.go'}

    def scan(self) -> List[str]:
        source_files = []
        if not os.path.exists(self.root_path):
            raise ValueError(f"Path does not exist: {self.root_path}")

        for root, dirs, files in os.walk(self.root_path):
            # Modify dirs in-place to skip ignored directories
            dirs[:] = [d for d in dirs if d not in self.ignore_dirs]
            
            for file in files:
                _, ext = os.path.splitext(file)
                if ext in self.extensions:
                    full_path = os.path.join(root, file)
                    source_files.append(full_path)
        
        return source_files
