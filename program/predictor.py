import time
import warnings
import os
from pathlib import Path

import joblib
import pandas as pd

# ---------------------------------------------------------
# 1. 경고 숨기기
# ---------------------------------------------------------
warnings.filterwarnings("ignore")


# ---------------------------------------------------------
# 2. 프로젝트 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/program/predictor.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

FEATURE_FILE = PROJECT_ROOT / "data" / "collected_data" / "live_features.csv"
PREDICT_FILE = PROJECT_ROOT / "data" / "collected_data" / "live_predictions.csv"
MODEL_FILE = PROJECT_ROOT / "ai_model" / "AEGIS.pkl"
ANOMALY_MODEL_FILE = PROJECT_ROOT / "ai_model" / "AEGIS_anomaly.pkl"
SUSPICIOUS_LABEL = -2
UNKNOWN_LABEL = -1
CONFIDENCE_THRESHOLD = float(os.getenv("AEGIS_UNKNOWN_THRESHOLD", "0.80"))
ENABLE_ANOMALY_DETECTION = os.getenv("AEGIS_ENABLE_ANOMALY", "1") != "0"


# ---------------------------------------------------------
# 3. 모델 입력 feature 컬럼
# ---------------------------------------------------------
# AEGIS.py에서 학습할 때 timestamp, label을 제외했으므로
# predictor.py에서도 아래 12개 feature만 모델에 입력해야 함
# ---------------------------------------------------------
FEATURE_COLUMNS = [
    "total_pkt_cnt",
    "tcp_cnt",
    "udp_cnt",
    "icmp_cnt",
    "syn_cnt",
    "ack_cnt",
    "unique_dst_port_cnt",
    "unique_src_ip_cnt",
    "dns_query_cnt",
    "gratuitous_arp_cnt",
    "failed_login_cnt",
    "mac_change_cnt",
]


LABEL_MAP = {
    SUSPICIOUS_LABEL: "SUSPICIOUS",
    UNKNOWN_LABEL: "UNKNOWN",
    0: "NORMAL",
    1: "ICMP Flood",
    2: "Port Scan",
    3: "SSH Brute Force",
    4: "ARP Spoofing",
    5: "DNS Anomaly",
}


# ---------------------------------------------------------
# 4. live_predictions.csv 헤더 생성
# ---------------------------------------------------------
def init_prediction_file():
    PREDICT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not PREDICT_FILE.exists():
        with open(PREDICT_FILE, "w", encoding="utf-8") as f:
            f.write("timestamp,label,model_label,confidence,is_anomaly,anomaly_score\n")
        return

    try:
        df = pd.read_csv(PREDICT_FILE)
    except pd.errors.EmptyDataError:
        with open(PREDICT_FILE, "w", encoding="utf-8") as f:
            f.write("timestamp,label,model_label,confidence,is_anomaly,anomaly_score\n")
        return

    changed = False

    if "model_label" not in df.columns:
        df["model_label"] = df["label"] if "label" in df.columns else UNKNOWN_LABEL
        changed = True

    if "confidence" not in df.columns:
        df["confidence"] = None
        changed = True

    if "is_anomaly" not in df.columns:
        df["is_anomaly"] = False
        changed = True

    if "anomaly_score" not in df.columns:
        df["anomaly_score"] = None
        changed = True

    if changed:
        df.to_csv(PREDICT_FILE, index=False)


def predict_with_confidence(model, X):
    if not hasattr(model, "predict_proba"):
        model_label = int(model.predict(X)[0])
        return model_label, model_label, None

    proba = model.predict_proba(X)[0]
    best_idx = int(proba.argmax())
    confidence = float(proba[best_idx])
    model_label = int(model.classes_[best_idx])

    if confidence < CONFIDENCE_THRESHOLD:
        return UNKNOWN_LABEL, model_label, confidence

    return model_label, model_label, confidence


def load_anomaly_model():
    if not ENABLE_ANOMALY_DETECTION:
        print("[*] anomaly detection disabled")
        return None

    if not ANOMALY_MODEL_FILE.exists():
        print(f"[*] anomaly model not found: {ANOMALY_MODEL_FILE}")
        return None

    print(f"[*] anomaly model file: {ANOMALY_MODEL_FILE}")
    return joblib.load(ANOMALY_MODEL_FILE)


def check_anomaly(anomaly_model, X):
    if anomaly_model is None:
        return False, None

    is_anomaly = int(anomaly_model.predict(X)[0]) == -1
    anomaly_score = None

    if hasattr(anomaly_model, "decision_function"):
        anomaly_score = float(anomaly_model.decision_function(X)[0])

    return is_anomaly, anomaly_score


# ---------------------------------------------------------
# 5. 기존 예측 timestamp 불러오기
# ---------------------------------------------------------
def load_processed_timestamps():
    processed = set()

    if not PREDICT_FILE.exists():
        return processed

    try:
        df = pd.read_csv(PREDICT_FILE)

        if "timestamp" in df.columns:
            processed.update(df["timestamp"].astype(int).tolist())

    except pd.errors.EmptyDataError:
        pass

    return processed


# ---------------------------------------------------------
# 6. feature 파일에서 새 행 읽고 예측
# ---------------------------------------------------------
def predict_new_rows(model, processed_timestamps, anomaly_model=None):
    if not FEATURE_FILE.exists():
        return []

    try:
        df = pd.read_csv(FEATURE_FILE)
    except pd.errors.EmptyDataError:
        return []

    if df.empty:
        return []

    missing_cols = [col for col in FEATURE_COLUMNS if col not in df.columns]

    if missing_cols:
        print(f"[ERROR] live_features.csv에 필요한 컬럼이 없습니다: {missing_cols}")
        return []

    if "timestamp" not in df.columns:
        print("[ERROR] live_features.csv에 timestamp 컬럼이 없습니다.")
        return []

    new_predictions = []

    for _, row in df.iterrows():
        ts = int(row["timestamp"])

        if ts in processed_timestamps:
            continue

        X = pd.DataFrame(
            [row[FEATURE_COLUMNS].to_dict()],
            columns=FEATURE_COLUMNS,
        )

        traffic_sum = (
            int(row["total_pkt_cnt"])
            + int(row["tcp_cnt"])
            + int(row["udp_cnt"])
            + int(row["icmp_cnt"])
            + int(row["dns_query_cnt"])
            + int(row["gratuitous_arp_cnt"])
            + int(row["failed_login_cnt"])
            + int(row["mac_change_cnt"])
        )

        if traffic_sum == 0:
            label = 0
            model_label = 0
            confidence = 1.0
            is_anomaly = False
            anomaly_score = None
        else:
            label, model_label, confidence = predict_with_confidence(model, X)
            is_anomaly, anomaly_score = check_anomaly(anomaly_model, X)

            if is_anomaly and label == UNKNOWN_LABEL:
                label = SUSPICIOUS_LABEL

        new_predictions.append(
            {
                "timestamp": ts,
                "label": label,
                "model_label": model_label,
                "confidence": confidence,
                "is_anomaly": is_anomaly,
                "anomaly_score": anomaly_score,
            }
        )

        processed_timestamps.add(ts)

    return new_predictions


# ---------------------------------------------------------
# 7. 예측 결과 저장
# ---------------------------------------------------------
def append_predictions(predictions):
    if not predictions:
        return

    df_out = pd.DataFrame(predictions)
    df_out.to_csv(PREDICT_FILE, mode="a", header=False, index=False)


# ---------------------------------------------------------
# 8. 메인 루프
# ---------------------------------------------------------
def main():
    if not MODEL_FILE.exists():
        raise FileNotFoundError(f"[ERROR] 모델 파일을 찾을 수 없습니다: {MODEL_FILE}")

    init_prediction_file()

    print("[*] Predictor 가동 중...")
    print(f"[*] 모델 파일: {MODEL_FILE}")
    print(f"[*] 입력 파일: {FEATURE_FILE}")
    print(f"[*] 출력 파일: {PREDICT_FILE}")

    model = joblib.load(MODEL_FILE)
    anomaly_model = load_anomaly_model()
    processed_timestamps = load_processed_timestamps()
    print(f"[*] unknown confidence threshold: {CONFIDENCE_THRESHOLD:.2f}")

    print(f"[*] 기존 예측 완료 timestamp 수: {len(processed_timestamps)}")

    while True:
        try:
            predictions = predict_new_rows(model, processed_timestamps, anomaly_model)

            if predictions:
                append_predictions(predictions)

                for pred in predictions:
                    label = pred["label"]
                    attack_name = LABEL_MAP.get(label, "UNKNOWN")

                    print(
                        f"[+] 예측 완료: "
                        f"timestamp={pred['timestamp']}, "
                        f"label={label}, "
                        f"attack={attack_name}, "
                        f"model_label={pred['model_label']}, "
                        f"confidence={pred['confidence']}, "
                        f"is_anomaly={pred['is_anomaly']}, "
                        f"anomaly_score={pred['anomaly_score']}"
                    )

            time.sleep(1)

        except KeyboardInterrupt:
            print("\n[*] Predictor 종료")
            break

        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
