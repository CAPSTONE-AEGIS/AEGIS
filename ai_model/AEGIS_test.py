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
# AEGIS/ai_model/AEGIS_test.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

MODEL_PATH = PROJECT_ROOT / "ai_model" / "AEGIS.pkl"

# 테스트할 CSV 파일
# 1) 병합 데이터셋 전체 테스트용
TEST_CSV_PATH = (
    PROJECT_ROOT / "data" / "processed_data" / "merged_data" / "all_dataset.csv"
)

# 2) 실시간 feature 결과 테스트용으로 쓰고 싶으면 위 줄 대신 아래 줄 사용
# TEST_CSV_PATH = PROJECT_ROOT / "program" / "live_features.csv"


# ---------------------------------------------------------
# 3. 모델 입력 feature 컬럼
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


LABEL_MAP_KR = {
    0: "✅ 정상",
    1: "🚨 ICMP Flood",
    2: "🚨 Port Scan",
    3: "🚨 SSH Brute Force",
    4: "🚨 ARP Spoofing",
    5: "🚨 DNS Anomaly",
}


# ---------------------------------------------------------
# 4. 모델과 데이터 불러오기
# ---------------------------------------------------------
if not MODEL_PATH.exists():
    raise FileNotFoundError(f"[ERROR] 모델 파일을 찾을 수 없습니다: {MODEL_PATH}")

if not TEST_CSV_PATH.exists():
    raise FileNotFoundError(
        f"[ERROR] 테스트 CSV 파일을 찾을 수 없습니다: {TEST_CSV_PATH}"
    )

print("[*] AEGIS 모델과 CSV 데이터를 불러옵니다.")
print(f"[*] 모델 경로: {MODEL_PATH}")
print(f"[*] 테스트 CSV 경로: {TEST_CSV_PATH}")

model = joblib.load(MODEL_PATH)
df_test = pd.read_csv(TEST_CSV_PATH)

print(f"✅ 로드 완료: 총 {len(df_test)}행을 테스트합니다.\n")


# ---------------------------------------------------------
# 5. 입력 데이터 검증
# ---------------------------------------------------------
missing_cols = [col for col in FEATURE_COLUMNS if col not in df_test.columns]

if missing_cols:
    raise ValueError(f"[ERROR] 테스트 CSV에 필요한 컬럼이 없습니다: {missing_cols}")


# ---------------------------------------------------------
# 6. 모델 입력 데이터 생성
# ---------------------------------------------------------
# timestamp, label은 모델 입력에서 제외
# FEATURE_COLUMNS 12개만 사용
X_test = df_test[FEATURE_COLUMNS]


# ---------------------------------------------------------
# 7. AEGIS 모델 예측
# ---------------------------------------------------------
predictions = model.predict(X_test)


# ---------------------------------------------------------
# 8. 결과 컬럼 추가
# ---------------------------------------------------------
df_result = df_test.copy()

df_result["AEGIS_Prediction"] = predictions
df_result["AEGIS_Attack_Name"] = df_result["AEGIS_Prediction"].map(LABEL_MAP)
df_result["AEGIS_탐지명"] = df_result["AEGIS_Prediction"].map(LABEL_MAP_KR)


# ---------------------------------------------------------
# 9. 터미널 출력
# ---------------------------------------------------------
print("-" * 80)
print(f"🛡️ AEGIS 모델 CSV 테스트 결과: {len(df_result)}개")
print("-" * 80)

show_cols = [
    "timestamp",
    "total_pkt_cnt",
    "tcp_cnt",
    "udp_cnt",
    "icmp_cnt",
    "syn_cnt",
    "ack_cnt",
    "unique_dst_port_cnt",
    "dns_query_cnt",
    "failed_login_cnt",
    "mac_change_cnt",
    "AEGIS_Prediction",
    "AEGIS_탐지명",
]

existing_show_cols = [col for col in show_cols if col in df_result.columns]

print(df_result[existing_show_cols].to_string(index=False))

print("-" * 80)


# ---------------------------------------------------------
# 10. label이 있는 경우 실제 정답과 비교
# ---------------------------------------------------------
if "label" in df_result.columns:
    correct_count = (df_result["label"] == df_result["AEGIS_Prediction"]).sum()
    total_count = len(df_result)
    acc = correct_count / total_count if total_count > 0 else 0

    print(f"\n[정답 label 비교]")
    print(f"정답 개수: {correct_count}/{total_count}")
    print(f"정확도: {acc * 100:.2f}%")


# ---------------------------------------------------------
# 11. 결과 CSV 저장
# ---------------------------------------------------------
OUTPUT_PATH = TEST_CSV_PATH.with_name(TEST_CSV_PATH.stem + "_result.csv")

df_result.to_csv(OUTPUT_PATH, index=False, encoding="utf-8-sig")

print(f"\n✅ 전체 예측 결과가 저장되었습니다.")
print(f"[*] 저장 위치: {OUTPUT_PATH}")
