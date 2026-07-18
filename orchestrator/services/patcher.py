import os
import shutil
import logging

logger = logging.getLogger(__name__)

class PatchService:
    """
    Safely applies code patches to files.
    """
    
    def apply_fix(self, file_path: str, line_number: int, old_snippet: str, new_code: str) -> bool:
        """
        Applies a single fix.
        """
        return self.apply_batch_fixes(file_path, [(line_number, old_snippet, new_code)])

    def apply_batch_fixes(self, file_path: str, fixes: list[tuple[int, str, str]]) -> bool:
        """
        Applies multiple fixes to a single file.
        Fixes should be list of (line_number, old_snippet, new_code).
        Sorts fixes by line number descending to avoid offset issues.
        """
        if not os.path.exists(file_path):
            logger.error(f"File not found: {file_path}")
            return False

        try:
            # 1. Create Backup
            shutil.copy2(file_path, f"{file_path}.bak")
            
            # 2. Read content
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            lines = content.splitlines(keepends=True)
            
            # 3. Sort fixes by line number DESCENDING
            # This is critical so that applying a fix at the bottom doesn't 
            # change the line numbers for fixes above.
            sorted_fixes = sorted(fixes, key=lambda x: x[0], reverse=True)
            
            for line_number, old_snippet, new_code in sorted_fixes:
                # Find target range relative to current lines
                target_idx = line_number - 1
                start_search = max(0, target_idx - 5)
                end_search = min(len(lines), target_idx + 5)
                
                found_idx = -1
                if old_snippet and old_snippet.strip():
                    clean_old = old_snippet.strip()
                    for i in range(start_search, end_search):
                        if clean_old in lines[i]:
                            found_idx = i
                            break
                
                if found_idx == -1:
                    if 0 <= target_idx < len(lines):
                        found_idx = target_idx
                    else:
                        logger.warning(f"Line number {line_number} out of range in current lines. Skipping this fix.")
                        continue

                # Handle Indentation
                original_line = lines[found_idx]
                leading_whitespace = original_line[:len(original_line) - len(original_line.lstrip())]
                
                new_lines_raw = new_code.splitlines()
                indented_new_lines = []
                
                for i, line in enumerate(new_lines_raw):
                    if i == 0:
                        indented_new_lines.append(f"{leading_whitespace}{line.lstrip()}\n")
                    else:
                        if not line.strip():
                            indented_new_lines.append("\n")
                        else:
                            indented_new_lines.append(f"{leading_whitespace}{line}\n")
                
                # Execute Replacement
                lines[found_idx : found_idx + 1] = indented_new_lines
            
            # 6. Write back
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
                
            logger.info(f"Successfully applied {len(fixes)} patches to {file_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to apply batch patches to {file_path}: {e}")
            self.rollback(file_path)
            return False

    def rollback(self, file_path: str):
        """Restores the .bak file if remediation failed."""
        bak_file = f"{file_path}.bak"
        if os.path.exists(bak_file):
            import shutil
            shutil.copy2(bak_file, file_path)
            logger.info(f"AVR: Rollback successful for {file_path}")
