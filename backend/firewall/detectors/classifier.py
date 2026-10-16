"""TF-IDF + Logistic Regression classifier for prompt injection risk scoring."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline

from firewall.detectors.training_data import training_labels, training_texts

logger = logging.getLogger(__name__)

DEFAULT_MODEL_PATH = Path(__file__).resolve().parent.parent / "ml" / "prompt_classifier.joblib"


class PromptClassifier:
    """Lightweight, fast classifier. Train once, load many times."""

    def __init__(self, model_path: Optional[str | Path] = None) -> None:
        self.model_path = Path(model_path) if model_path else DEFAULT_MODEL_PATH
        self._pipeline: Optional[Pipeline] = None

    def load_or_train(self) -> None:
        if self.model_path.exists():
            self._pipeline = joblib.load(self.model_path)
            logger.info("Loaded classifier from %s", self.model_path)
            return
        self.train_and_save()

    def train_and_save(self) -> None:
        texts = training_texts()
        labels = training_labels()
        self._pipeline = Pipeline(
            [
                (
                    "tfidf",
                    TfidfVectorizer(
                        ngram_range=(1, 3),
                        max_features=8000,
                        sublinear_tf=True,
                        lowercase=True,
                        strip_accents="unicode",
                    ),
                ),
                (
                    "clf",
                    LogisticRegression(
                        max_iter=1000,
                        class_weight="balanced",
                        C=1.0,
                        solver="liblinear",
                    ),
                ),
            ]
        )
        self._pipeline.fit(texts, labels)
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._pipeline, self.model_path)
        logger.info("Trained and saved classifier to %s", self.model_path)

    def attack_score(self, text: str) -> float:
        """Return probability of being an attack (0.0 – 1.0)."""
        if self._pipeline is None:
            raise RuntimeError("Classifier has not been initialized. Call load_or_train().")
        proba = self._pipeline.predict_proba([text])[0]
        classes = list(self._pipeline.classes_)
        if 1 in classes:
            return float(proba[classes.index(1)])
        return 0.0
