"""Model Registry & Status Service."""
from typing import Dict
from app.ml.inference import inference_engine


class ModelRegistry:
    """Manages ML model lifecycle and availability checks."""

    def __init__(self):
        # Automatically attempt loading on startup if artifacts exist
        inference_engine.load_models()

    def get_status(self) -> Dict[str, bool]:
        """Returns availability status for all expected model artifacts."""
        # Refresh if not loaded yet
        if not inference_engine.is_sms_loaded or not inference_engine.is_url_loaded:
            inference_engine.load_models()

        return {
            "url_classifier": inference_engine.is_url_loaded,
            "sms_classifier": inference_engine.is_sms_loaded,
        }

    @property
    def url_model_loaded(self) -> bool:
        return inference_engine.is_url_loaded

    @property
    def sms_model_loaded(self) -> bool:
        return inference_engine.is_sms_loaded


model_registry = ModelRegistry()
