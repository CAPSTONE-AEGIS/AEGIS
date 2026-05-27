import pandas as pd
from pathlib import Path

# ---------------------------------------------------------
# 1. 프로젝트 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/ai_model/merge_features.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed_data"
MERGED_DATA_DIR = PROCESSED_DATA_DIR / "merged_data"
OUTPUT_PATH = MERGED_DATA_DIR / "all_dataset.csv"


# ---------------------------------------------------------
# 2. 합칠 feature 파일 목록
# ---------------------------------------------------------
feature_files = [
    "normal_features.csv",
    "icmp_features.csv",
    "port_features.csv",
    "ssh_features.csv",
    "dns_features.csv",
    "arp_features.csv",
]


# ---------------------------------------------------------
# 3. 병합 실행
# ---------------------------------------------------------
def merge_features():
    print("[*] 데이터 병합을 시작합니다.")
    print(f"[*] 입력 폴더: {PROCESSED_DATA_DIR}")

    df_list = []

    for file_name in feature_files:
        file_path = PROCESSED_DATA_DIR / file_name

        if not file_path.exists():
            print(f"❌ 파일 없음: {file_path}")
            continue

        df = pd.read_csv(file_path)
        print(f" - {file_name} 읽기 완료: {len(df)}행")

        df_list.append(df)

    if not df_list:
        print("\n❌ 읽어온 데이터가 없어 병합을 진행하지 못했습니다.")
        return

    combined_df = pd.concat(df_list, ignore_index=True)

    # 저장 폴더 생성
    MERGED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # 저장
    combined_df.to_csv(OUTPUT_PATH, index=False)

    print("\n=========================================")
    print(f"✅ 병합 완료: 총 {len(combined_df)}행")
    print(f"✅ 최종 저장 위치: {OUTPUT_PATH}")
    print("=========================================")

    # label 분포 확인
    if "label" in combined_df.columns:
        print("\n[Label 분포]")
        print(combined_df["label"].value_counts().sort_index())


if __name__ == "__main__":
    merge_features()
