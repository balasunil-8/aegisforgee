"""
Train the AI detector quickly using bundled samples.
Run: python train_ai_detector.py
"""
from ai_detector import AIDetector, SAMPLE_DATA
from pathlib import Path

if __name__ == '__main__':
    detector = AIDetector()
    if SAMPLE_DATA.exists():
        ok, info = detector.train_from_file(Path(SAMPLE_DATA))
        print(ok, info)
    else:
        print("No sample data found at", SAMPLE_DATA)
