"""
A lightweight AI/ML detection module for PentestLab.
- Uses TF-IDF + LogisticRegression for initial payload classification (attack vs benign)
- Falls back to keyword heuristics when model missing or for explainability
- Saves/loads model to `models/ai_detector.joblib`
"""

import os
import json
from pathlib import Path
from typing import Tuple, Dict, Any

import joblib
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics.pairwise import cosine_similarity

try:
    from sentence_transformers import SentenceTransformer
    _HAS_STS = True
except Exception:
    SentenceTransformer = None
    _HAS_STS = False

MODEL_DIR = Path("models")
MODEL_PATH = MODEL_DIR / "ai_detector.joblib"
SAMPLE_DATA = Path("ai_training_samples.json")

class AIDetector:
    def __init__(self):
        self.pipeline: Pipeline | None = None
        if not MODEL_DIR.exists():
            MODEL_DIR.mkdir(parents=True, exist_ok=True)
        self._ensure_model()

    def _ensure_model(self):
        if MODEL_PATH.exists():
            try:
                self.pipeline = joblib.load(MODEL_PATH)
            except Exception:
                self.pipeline = None
        else:
            # Try to train from bundled samples if available
            if SAMPLE_DATA.exists():
                self.train_from_file(SAMPLE_DATA)
        # prepare embedding model if available
        if _HAS_STS:
            try:
                # small, efficient model; will download on first use
                self.embedder = SentenceTransformer('all-MiniLM-L6-v2')
            except Exception:
                self.embedder = None
        else:
            self.embedder = None

    def train_from_file(self, file_path: Path) -> Tuple[bool, Dict[str, Any]]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            texts = [it["text"] for it in data]
            labels = [1 if it.get("label") == "attack" else 0 for it in data]
            return self.train(texts, labels)
        except Exception as e:
            return False, {"error": str(e)}

    def train(self, texts, labels) -> Tuple[bool, Dict[str, Any]]:
        try:
            clf = LogisticRegression(max_iter=1000)
            vect = TfidfVectorizer(ngram_range=(1,2), max_features=20000)
            self.pipeline = Pipeline([("tfidf", vect), ("clf", clf)])
            self.pipeline.fit(texts, labels)
            joblib.dump(self.pipeline, MODEL_PATH)
            return True, {"message": "Model trained", "samples": len(texts)}
        except Exception as e:
            return False, {"error": str(e)}

    def predict_proba(self, text: str) -> Dict[str, Any]:
        # Fallback heuristic rules
        heuristics = self._heuristic_score(text)
        if self.pipeline is None:
            return {"attack_prob": heuristics, "heuristic_only": True}
        try:
            proba = float(self.pipeline.predict_proba([text])[0][1])
            # combine simple ensemble: avg of model proba and heuristic
            combined = (proba + heuristics) / 2.0
            result = {"attack_prob": combined, "model_proba": proba, "heuristic": heuristics}
            # if embedder available, compute similarity to known attack samples
            try:
                if getattr(self, 'embedder', None) is not None and SAMPLE_DATA.exists():
                    with open(SAMPLE_DATA, 'r', encoding='utf-8') as f:
                        samples = [it['text'] for it in json.load(f) if it.get('label') == 'attack']
                    if len(samples) > 0:
                        emb_inputs = self.embedder.encode([text] + samples)
                        v0 = emb_inputs[0].reshape(1, -1)
                        sims = cosine_similarity(v0, emb_inputs[1:])[0]
                        max_sim = float(max(sims))
                        # mix embedding similarity in (weighted)
                        result.update({'embedding_max_sim': max_sim})
                        # slightly adjust attack probability
                        result['attack_prob'] = min(1.0, 0.7 * result['attack_prob'] + 0.3 * max_sim)
            except Exception:
                pass
            return result
        except Exception as e:
            return {"attack_prob": heuristics, "error": str(e)}

    def predict_label(self, text: str, threshold: float = 0.5) -> Dict[str, Any]:
        res = self.predict_proba(text)
        prob = res.get("attack_prob", 0.0)
        label = "attack" if prob >= threshold else "benign"
        res.update({"label": label, "threshold": threshold})
        return res

    def _heuristic_score(self, text: str) -> float:
        t = text.lower()
        score = 0.0
        keywords = ["select ", "union ", "drop ", "sleep(", "benchmark(", " or ", " and ", "--", "/*", "xpath", "<script", "onerror", "../", "../../../", "file://", "curl ", "wget ", "exec(", "system("]
        for kw in keywords:
            if kw in t:
                score += 0.1
        # length-based heuristics
        if len(t) > 200:
            score += 0.05
        # clamp
        return min(1.0, score)

# Simple module-level detector instance for importers
_detector: AIDetector | None = None

def get_detector() -> AIDetector:
    global _detector
    if _detector is None:
        _detector = AIDetector()
    return _detector

if __name__ == "__main__":
    d = get_detector()
    print("AIDetector ready. Model exists:", MODEL_PATH.exists())
