"""
Classifier abstraction layer.
BaseClassifier ABC with Template Method pattern for zone mapping.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Tuple
from models.packet_data import Zone


class BaseClassifier(ABC):
    """
    Abstract Base Class for all ML classifiers.
    Subclasses must implement predict_confidence() and load().
    The classify() method is a Template Method that maps scores to zones.
    """

    # Zone thresholds (configurable via config)
    SUSPICIOUS_THRESHOLD = 0.50
    MALICIOUS_THRESHOLD = 0.60
    CRITICAL_THRESHOLD = 0.90

    @abstractmethod
    def predict_confidence(self, packet: Dict[str, Any]) -> float:
        """
        Run ML inference on packet features.
        Returns a float between 0.0 and 1.0.
        """
        ...

    @abstractmethod
    def load(self, model_path: str) -> None:
        """Load the model from the given path."""
        ...

    def classify(self, packet: Dict[str, Any]) -> Tuple[float, Zone]:
        """
        Template Method: predict confidence, then map to Zone.
        Returns (confidence, zone) tuple.

        Thresholds:
          < 0.50 -> BENIGN
          0.50 - 0.60 -> SUSPICIOUS
          0.60 - 0.90 -> MALICIOUS
          >= 0.90 -> CRITICAL
        """
        confidence = self.predict_confidence(packet)

        # Clamp to [0, 1]
        confidence = max(0.0, min(1.0, confidence))

        if confidence >= self.CRITICAL_THRESHOLD:
            zone = Zone.CRITICAL
        elif confidence >= self.MALICIOUS_THRESHOLD:
            zone = Zone.MALICIOUS
        elif confidence >= self.SUSPICIOUS_THRESHOLD:
            zone = Zone.SUSPICIOUS
        else:
            zone = Zone.BENIGN

        return confidence, zone

    def update_thresholds(
        self,
        suspicious: float = None,
        malicious: float = None,
        critical: float = None,
    ) -> None:
        """Update classification thresholds at runtime."""
        if suspicious is not None:
            self.SUSPICIOUS_THRESHOLD = suspicious
        if malicious is not None:
            self.MALICIOUS_THRESHOLD = malicious
        if critical is not None:
            self.CRITICAL_THRESHOLD = critical
