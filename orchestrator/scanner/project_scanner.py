import os
import logging
from typing import List

logger = logging.getLogger(__name__)

class ProjectScanner:
    """
    Scans a given project path for relevant source code files.
    """
    
    # Extensions we care about for security analysis
    SUPPORTED_EXTENSIONS = {
        '.py', '.js', '.ts', '.java', '.c', '.cpp', '.rs', '.go', '.php'
    }

    def __init__(self, root_path: str):
        self.root_path = root_path

    def scan(self) -> List[str]:
        """
        Traverses the directory and returns a list of absolute file paths
        that match supported extensions.
        """
        if not os.path.exists(self.root_path):
            logger.error(f"Path does not exist: {self.root_path}")
            return []

        if os.path.isfile(self.root_path):
            _, ext = os.path.splitext(self.root_path)
            if ext.lower() in self.SUPPORTED_EXTENSIONS:
                return [os.path.abspath(self.root_path)]
            return []

        source_files = []
        logger.info(f"Scanning project at: {self.root_path}")

        for root, dirs, files in os.walk(self.root_path):
            # Skip common junk directories and library environments
            dirs[:] = [d for d in dirs if d not in {
                'node_modules', '.git', '__pycache__', 'venv', '.venv', 'env', '.env',
                'site-packages', 'dist-packages', 'dist', 'build', 'target',
                '.pytest_cache', '.next', '.docusaurus'
            }]

            for file in files:
                _, ext = os.path.splitext(file)
                if ext.lower() in self.SUPPORTED_EXTENSIONS:
                    full_path = os.path.join(root, file)
                    source_files.append(full_path)

        logger.info(f"Found {len(source_files)} valid source files.")
        return source_files
