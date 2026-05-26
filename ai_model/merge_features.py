import pandas as pd
import os

# 1. 바뀐 폴더 경로 설정
folder_path = r"C:\Users\kjs64\OneDrive\바탕 화면\AEGIS\data/after_data"

# 2. 합칠 파일 이름 목록
# ⚠️ 실제로 생성하신 5개 파일의 이름과 정확히 일치하는지 확인해 주세요.
file_names = [
    "normal_003.csv",
    "port_scan.csv",
    "DNS.csv",
    "icmp_flood.csv",
    "ssh_login.csv",
    "arp_spoofing.csv"
]
print("데이터 병합을 시작합니다...")

# 데이터를 담을 빈 리스트 준비
df_list = []

# 각 파일을 순서대로 읽어서 리스트에 추가
for file in file_names:
    file_path = os.path.join(folder_path, file)
    
    try:
        df = pd.read_csv(file_path)
        print(f" - '{file}' 읽기 완료 (데이터 {len(df)}줄)")
        df_list.append(df)
    except FileNotFoundError:
        print(f" ❌ 오류: '{file}' 파일을 찾을 수 없습니다. 경로와 이름을 다시 확인해 주세요.")

# 모든 데이터를 하나로 통합
if df_list:
    combined_df = pd.concat(df_list, ignore_index=True)

    # 같은 폴더 안에 total_dataset.csv로 저장
    output_path = os.path.join(folder_path, "all_dataset.csv")
    combined_df.to_csv(output_path, index=False)

    print("\n=========================================")
    print(f"✅ 병합 완료! 총 {len(combined_df)}개의 행이 합쳐졌습니다.")
    print(f"✅ 최종 저장 위치: {output_path}")
    print("=========================================")
else:
    print("\n❌ 읽어온 데이터가 없어 병합을 진행하지 못했습니다.")