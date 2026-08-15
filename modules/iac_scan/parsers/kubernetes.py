import yaml

class KubernetesParser:
    def parse(self, content: str):
        try:
            return list(yaml.safe_load_all(content))
        except Exception:
            return []
