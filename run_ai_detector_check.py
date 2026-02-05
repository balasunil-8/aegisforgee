import json
from ai_detector import get_detector


def main():
    detector = get_detector()
    sample = "admin' OR '1'='1 --"
    res = detector.predict_label(sample)
    # persist result so we can inspect embedding fields reliably
    out_path = 'run_ai_detector_result.json'
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(res, f, indent=2)
    print('WROTE', out_path)


if __name__ == '__main__':
    main()
