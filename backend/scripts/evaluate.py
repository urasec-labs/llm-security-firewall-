#!/usr/bin/env python3
"""Simple offline evaluation of rules + classifier on the training corpus."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from firewall.detectors.classifier import PromptClassifier
from firewall.detectors.rules import HeuristicDetector
from firewall.detectors.training_data import TRAINING_EXAMPLES


def evaluate() -> None:
    rules = HeuristicDetector()
    clf = PromptClassifier()
    clf.load_or_train()
    THRESHOLD = 0.72

    tp = fp = tn = fn = 0
    rule_only_tp = 0

    for text, label in TRAINING_EXAMPLES:
        rule_hit = rules.scan(text).blocked
        score = clf.attack_score(text)
        pred = 1 if (rule_hit or score >= THRESHOLD) else 0

        if label == 1 and pred == 1:
            tp += 1
            if rule_hit:
                rule_only_tp += 1
        elif label == 0 and pred == 1:
            fp += 1
        elif label == 0 and pred == 0:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0
    recall = tp / (tp + fn) if (tp + fn) else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0
    acc = (tp + tn) / total if total else 0

    print("=" * 55)
    print("Offline Evaluation (Training Corpus)")
    print("=" * 55)
    print(f"Total samples     : {total}")
    print(f"Attacks / Benign  : {tp+fn} / {tn+fp}")
    print()
    print(f"True Positives    : {tp}")
    print(f"False Positives   : {fp}")
    print(f"True Negatives    : {tn}")
    print(f"False Negatives   : {fn}")
    print()
    print(f"Accuracy          : {acc:.3f}")
    print(f"Precision         : {precision:.3f}")
    print(f"Recall            : {recall:.3f}")
    print(f"F1 Score          : {f1:.3f}")
    print(f"Rule contribution : {rule_only_tp}/{tp} of TPs caught by rules alone")
    print("=" * 55)


if __name__ == "__main__":
    evaluate()
