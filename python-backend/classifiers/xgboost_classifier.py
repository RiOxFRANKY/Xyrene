"""
XGBoost classifier implementation wrapping the trained model.
"""

import os
import json
import xgboost as xgb
import pandas as pd
from typing import Dict, Any
from classifiers.base_classifier import BaseClassifier


class XGBoostClassifier(BaseClassifier):
    """
    Concrete classifier using a trained XGBoost model.
    """

    def __init__(self, model_path: str, feature_names_path: str):
        self._model = None
        self._feature_names = []
        self._model_path = model_path
        self._feature_names_path = feature_names_path
        self.load(model_path)

    def load(self, model_path: str) -> None:
        """Load XGBoost model and feature names from disk."""
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"XGBoost model not found: {model_path}")

        self._model = xgb.Booster()
        self._model.load_model(model_path)

        if not os.path.exists(self._feature_names_path):
            raise FileNotFoundError(
                f"Feature names file not found: {self._feature_names_path}"
            )

        with open(self._feature_names_path, "r") as f:
            self._feature_names = json.load(f)

    def predict_confidence(self, packet: Dict[str, Any]) -> float:
        """
        Run XGBoost prediction on packet features.
        Missing features are zero-filled.
        """
        input_data = {}
        for fname in self._feature_names:
            val = packet.get(fname, 0)
            input_data[fname] = [float(val) if val is not None else 0.0]

        df = pd.DataFrame(input_data)
        dmatrix = xgb.DMatrix(df, feature_names=self._feature_names)

        probability = float(self._model.predict(dmatrix)[0])
        return probability

    def _extract_features(self, raw_packet: Dict[str, Any]) -> Dict[str, float]:
        """Extract and normalize features from raw packet data."""
        features = {}
        for fname in self._feature_names:
            val = raw_packet.get(fname, 0)
            features[fname] = float(val) if val is not None else 0.0
        return features

    @property
    def model_version(self) -> str:
        """Return model identifier string."""
        return f"xgboost:{os.path.basename(self._model_path)}"
