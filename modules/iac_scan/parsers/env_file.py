class EnvFileParser:
    def parse(self, content: str):
        return [line for line in content.splitlines() if line.strip() and not line.startswith('#')]
