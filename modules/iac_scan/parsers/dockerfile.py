import re
from dataclasses import dataclass

@dataclass
class DockerfileInstruction:
    line_number: int
    instruction: str
    args: str
    raw: str

class DockerfileParser:
    def parse(self, content: str) -> list[DockerfileInstruction]:
        instructions = []
        for i, line in enumerate(content.splitlines()):
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                continue
            parts = stripped.split(maxsplit=1)
            inst = parts[0].upper()
            args = parts[1] if len(parts) > 1 else ''
            instructions.append(DockerfileInstruction(i + 1, inst, args, line))
        return instructions

    def get_instructions(self, content: str, instruction_type: str) -> list[DockerfileInstruction]:
        instructions = self.parse(content)
        return [i for i in instructions if i.instruction == instruction_type.upper()]
