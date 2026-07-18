from .context import VulnerabilityContext
import random
import time

class AIReasoningEngine:
    def __init__(self):
        print("AI Reasoning Engine Initialized")

    def explain_vulnerability(self, context: VulnerabilityContext) -> str:
        """
        Interacts with an LLM to explain the vulnerability.
        """
        # Fin de la simulation de latence
        
        return (
            f"DETECTION DÉTERMINISTE : Le point de vulnérabilité à {context.file_path} (Type: {context.vulnerability_type}) "
            "a été vérifié par analyse statique de flux de données. Le chemin d'exécution entre l'entrée utilisateur "
            "et ce sink critique est rompu."
        )

    def generate_fix(self, context: VulnerabilityContext) -> str:
        return "Sanitize the input using 'shlex.quote()' before passing to exec()."
