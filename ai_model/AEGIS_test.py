import joblib
import pandas as pd
import warnings

# 불필요한 버전 경고창 숨기기
warnings.filterwarnings("ignore")

# =====================================================================
# 1. 파일 경로 세팅 (⚠️ 본인 환경에 맞게 수정하세요)
# =====================================================================
model_path = r"C:\Users\kjs64\OneDrive\바탕 화면\AEGIS\ai_model\AEGIS.pkl"
test_csv_path = r"C:\Users\kjs64\OneDrive\바탕 화면\전처리 파일\live_features.csv" # 테스트할 CSV 파일 경로

# =====================================================================
# 2. 모델과 데이터 불러오기
# =====================================================================
print("[*] AEGIS 모델과 CSV 데이터를 불러옵니다...")
model = joblib.load(model_path)
df_test = pd.read_csv(test_csv_path)

print(f"✅ 로드 완료! 총 {len(df_test)}줄의 데이터를 테스트합니다.\n")

# =====================================================================
# 3. 데이터 손질 (AI가 헷갈려 하는 시간과 정답지 떼어내기)
# =====================================================================
# 모델은 정확히 12개의 특징값만 필요로 하므로, timestamp와 label이 있다면 삭제합니다.
X_test = df_test.copy()

if 'timestamp' in X_test.columns:
    X_test = X_test.drop(columns=['timestamp'])
if 'label' in X_test.columns:
    X_test = X_test.drop(columns=['label'])

# =====================================================================
# 4. AEGIS 모델 예측 (한 번에 싹 다 채점!)
# =====================================================================
predictions = model.predict(X_test)

# =====================================================================
# 5. 결과 확인 및 저장
# =====================================================================
# 원본 엑셀 파일의 맨 오른쪽에 AI가 판별한 '예측 결과' 컬럼을 추가합니다.
df_test['AEGIS_Prediction'] = predictions

# 숫자를 알아보기 쉽게 한글로 변환해 주는 작업
label_map = {
    0: "✅ 정상",
    1: "🚨 ICMP Flood",
    2: "🚨 Port Scan",
    3: "🚨 SSH Brute",
    4: "🚨 DNS Anomaly",
    5: "🚨 ARP Spoofing"
}
df_test['AEGIS_탐지명'] = df_test['AEGIS_Prediction'].map(label_map)

# 💡 1. 터미널 화면에 '모든 데이터' 숨김 없이 전체 출력하기
print("-" * 60)
print(f" 🛡️ AEGIS 모델 CSV 테스트 전체 결과 ({len(df_test)}개) 🛡️")
print("-" * 60)

# .head(15)를 지우고 .to_string()을 붙여서 생략(...) 없이 전부 출력하게 만듭니다.
print(df_test[['timestamp', 'total_pkt_cnt', 'tcp_cnt', 'AEGIS_Prediction', 'AEGIS_탐지명']].to_string())
print("-" * 60)

# 💡 2. 예측 결과가 포함된 새로운 CSV 파일로 굽기
output_path = test_csv_path.replace(".csv", "_result.csv")
df_test.to_csv(output_path, index=False, encoding='utf-8-sig')
print(f"\n✅ 전체 채점 결과가 [{output_path}]에 저장되었습니다!")