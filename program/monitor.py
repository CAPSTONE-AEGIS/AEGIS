import time
import json
import pandas as pd
from pathlib import Path

# ---------------------------------------------------------
# 1. 파일 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/program/monitor.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

COLLECTED_DATA_DIR = PROJECT_ROOT / "data" / "collected_data"
COLLECTED_DATA_DIR.mkdir(parents=True, exist_ok=True)

FEATURE_FILE = COLLECTED_DATA_DIR / "live_features.csv"
PREDICT_FILE = COLLECTED_DATA_DIR / "live_predictions.csv"
DASHBOARD_FILE = COLLECTED_DATA_DIR / "live_dashboard.json"


# ---------------------------------------------------------
# 2. label 번호 → 공격 이름 매핑
# ---------------------------------------------------------
LABEL_MAP = {
    0: "Normal",
    1: "ICMP Flood",
    2: "Port Scan",
    3: "SSH Brute Force",
    4: "DNS Anomaly",
    5: "ARP Spoofing",
}


RISK_MAP = {
    0: "Low",
    1: "High",
    2: "Medium",
    3: "High",
    4: "Medium",
    5: "High",
}


# ---------------------------------------------------------
# 3. 이미 처리된 timestamp 로드
# ---------------------------------------------------------
def load_processed_timestamps():
    processed = set()

    if not DASHBOARD_FILE.exists():
        return processed

    try:
        with open(DASHBOARD_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue

                try:
                    record = json.loads(line)
                    if "timestamp" in record:
                        processed.add(int(record["timestamp"]))
                except json.JSONDecodeError:
                    continue

    except FileNotFoundError:
        pass

    return processed


# ---------------------------------------------------------
# 4. pandas/numpy 타입을 JSON 저장 가능한 타입으로 변환
# ---------------------------------------------------------
def clean_value(value):
    if pd.isna(value):
        return None

    if hasattr(value, "item"):
        return value.item()

    return value


def row_to_clean_dict(row):
    record = {}

    for key, value in row.to_dict().items():
        record[key] = clean_value(value)

    return record


# ---------------------------------------------------------
# 5. 메인 루프
# ---------------------------------------------------------
def main():
    print("[*] Monitor 가동: 데이터 병합 및 JSON 변환을 시작합니다.")
    print(f"[*] feature 입력 파일: {FEATURE_FILE}")
    print(f"[*] prediction 입력 파일: {PREDICT_FILE}")
    print(f"[*] dashboard 출력 파일: {DASHBOARD_FILE}")

    processed_timestamps = load_processed_timestamps()

    print(f"[*] 기존 처리 완료 timestamp 수: {len(processed_timestamps)}")

    while True:
        try:
            if not FEATURE_FILE.exists() or not PREDICT_FILE.exists():
                time.sleep(1)
                continue

            df_features = pd.read_csv(FEATURE_FILE)
            df_preds = pd.read_csv(PREDICT_FILE)

            if df_features.empty or df_preds.empty:
                time.sleep(1)
                continue

            if "timestamp" not in df_features.columns:
                print("[ERROR] live_features.csv에 timestamp 컬럼이 없습니다.")
                time.sleep(2)
                continue

            if "timestamp" not in df_preds.columns:
                print("[ERROR] live_predictions.csv에 timestamp 컬럼이 없습니다.")
                time.sleep(2)
                continue

            if "label" not in df_preds.columns:
                print("[ERROR] live_predictions.csv에 label 컬럼이 없습니다.")
                time.sleep(2)
                continue

            df_merged = pd.merge(
                df_features,
                df_preds,
                on="timestamp",
                how="inner",
            )

            if df_merged.empty:
                time.sleep(1)
                continue

            new_logs_count = 0

            with open(DASHBOARD_FILE, "a", encoding="utf-8") as f:
                for _, row in df_merged.iterrows():
                    ts = int(row["timestamp"])

                    if ts in processed_timestamps:
                        continue

                    record = row_to_clean_dict(row)

                    label = int(record["label"])

                    record["timestamp"] = ts
                    record["label"] = label
                    record["attack_type"] = LABEL_MAP.get(label, "Unknown")
                    record["risk_level"] = RISK_MAP.get(label, "Unknown")

                    if label == 0:
                        record["alert_message"] = "정상 트래픽으로 판단됨"
                    else:
                        record["alert_message"] = (
                            f"{record['attack_type']} 공격 의심 트래픽 탐지"
                        )

                    f.write(json.dumps(record, ensure_ascii=False) + "\n")

                    processed_timestamps.add(ts)
                    new_logs_count += 1

            if new_logs_count > 0:
                print(
                    f"[+] {new_logs_count}개의 새 로그 병합 완료 "
                    f"-> {DASHBOARD_FILE}"
                )

            time.sleep(2)

        except pd.errors.EmptyDataError:
            time.sleep(1)

        except KeyboardInterrupt:
            print("\n[*] Monitor 종료")
            break

        except Exception as e:
            print(f"[ERROR] {e}")
            time.sleep(1)


if __name__ == "__main__":
    main()
