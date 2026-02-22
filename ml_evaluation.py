"""
Évaluation des modèles ML de MiniSec (basé sur ai_models.AIDetector).

Objectifs académiques :
- Construire un petit dataset annoté (bénin / malveillant)
- Extraire des features via AIDetector.extract_features
- Entraîner un classifieur supervisé (RandomForest)
- Calculer précision, rappel, F1-score, accuracy
- Générer une matrice de confusion
- Exporter les métriques dans un fichier JSON dans reports/ml_metrics.json
"""

import json
import os
from pathlib import Path
from typing import List, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    precision_recall_fscore_support,
)
from sklearn.model_selection import train_test_split

from ai_models import AIDetector


ROOT_DIR = Path(__file__).resolve().parent
DATA_PATH = ROOT_DIR / "ml_data" / "labeled_samples.jsonl"
REPORTS_DIR = ROOT_DIR / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)
METRICS_PATH = REPORTS_DIR / "ml_metrics.json"


def load_labeled_dataset(path: Path = DATA_PATH) -> Tuple[List[str], List[int]]:
    """
    Charger le petit dataset annoté (JSON Lines).

    Chaque ligne doit contenir :
        {"label": "benign" | "malicious", "content": "..."}
    """
    texts: List[str] = []
    labels: List[int] = []

    if not path.exists():
        raise FileNotFoundError(f"Dataset ML introuvable: {path}")

    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue

            content = str(obj.get("content", ""))
            label_str = str(obj.get("label", "")).lower()
            if not content or label_str not in {"benign", "malicious"}:
                continue

            label = 0 if label_str == "benign" else 1
            texts.append(content)
            labels.append(label)

    if not texts:
        raise ValueError("Dataset ML vide après filtrage.")

    return texts, labels


def build_feature_matrix(detector: AIDetector, texts: List[str]) -> np.ndarray:
    """Convertir une liste de contenus en matrice de features numériques."""
    features = [detector.extract_features(t) for t in texts]
    return np.vstack(features)


def evaluate_supervised_model() -> dict:
    """
    Entraîner et évaluer un modèle supervisé simple (RandomForest)
    sur le petit dataset annoté.
    """
    texts, labels = load_labeled_dataset()
    labels_arr = np.array(labels, dtype=int)

    detector = AIDetector()
    X = build_feature_matrix(detector, texts)

    # Split train / test pour évaluation
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels_arr, test_size=0.3, random_state=42, stratify=labels_arr
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)

    acc = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="binary"
    )

    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(
        y_test, y_pred, target_names=["benign", "malicious"], output_dict=True
    )

    metrics = {
        "model": "RandomForestClassifier",
        "dataset": {
            "total_samples": int(len(labels)),
            "train_size": int(len(y_train)),
            "test_size": int(len(y_test)),
        },
        "metrics": {
            "accuracy": float(acc),
            "precision": float(precision),
            "recall": float(recall),
            "f1_score": float(f1),
        },
        "confusion_matrix": {
            "labels": ["benign", "malicious"],
            "matrix": cm,
        },
        "classification_report": report,
    }

    return metrics


def save_metrics_to_json(metrics: dict, path: Path = METRICS_PATH) -> None:
    """Sauvegarder les métriques ML dans un fichier JSON."""
    with path.open("w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)


def main() -> None:
    """Point d'entrée CLI pour lancer l'évaluation ML."""
    metrics = evaluate_supervised_model()
    save_metrics_to_json(metrics)

    print("== Évaluation ML MiniSec ==")
    print(f"- Taille du dataset: {metrics['dataset']['total_samples']}")
    print(
        f"- Accuracy: {metrics['metrics']['accuracy']:.3f} | "
        f"Precision: {metrics['metrics']['precision']:.3f} | "
        f"Recall: {metrics['metrics']['recall']:.3f} | "
        f"F1-score: {metrics['metrics']['f1_score']:.3f}"
    )
    print("- Matrice de confusion [ [TN, FP], [FN, TP] ]:")
    print(metrics["confusion_matrix"]["matrix"])
    print(f"- Rapport complet exporté dans: {METRICS_PATH}")


if __name__ == "__main__":
    main()

