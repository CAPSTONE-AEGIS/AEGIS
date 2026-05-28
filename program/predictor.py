import time
import warnings
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
    0: "Normal",
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
            f.write("timestamp,label\n")


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
def predict_new_rows(model, processed_timestamps):
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
        else:
            label = int(model.predict(X)[0])

        new_predictions.append(
            {
                "timestamp": ts,
                "label": label,
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
    processed_timestamps = load_processed_timestamps()

    print(f"[*] 기존 예측 완료 timestamp 수: {len(processed_timestamps)}")

    while True:
        try:
            predictions = predict_new_rows(model, processed_timestamps)

            if predictions:
                append_predictions(predictions)

                for pred in predictions:
                    label = pred["label"]
                    attack_name = LABEL_MAP.get(label, "Unknown")

                    print(
                        f"[+] 예측 완료: "
                        f"timestamp={pred['timestamp']}, "
                        f"label={label}, "
                        f"attack={attack_name}"
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
