"""Train and persist the prompt-injection classifier."""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure package root is on path when run as script
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from firewall.detectors.classifier import PromptClassifier


def main() -> None:
    clf = PromptClassifier()
    clf.train_and_save()
    print(f"Classifier trained and saved to: {clf.model_path}")


if __name__ == "__main__":
    main()
