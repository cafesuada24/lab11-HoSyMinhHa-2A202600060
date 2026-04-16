"""
Lab 11 — Toxicity Guardrail
"""
from detoxify import Detoxify

class ToxicityGuardrail:
    def __init__(self):
        # Load the model
        self.model = Detoxify('original')

    def is_toxic(self, text: str, threshold: float = 0.5) -> bool:
        """Check if text is toxic."""
        results = self.model.predict(text)
        # Check if any major toxicity score exceeds the threshold
        return any(score > threshold for score in results.values())
