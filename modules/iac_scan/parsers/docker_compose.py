import yaml

class DockerComposeParser:
    def parse(self, content: str):
        try:
            return yaml.safe_load(content)
        except Exception:
            return {}
