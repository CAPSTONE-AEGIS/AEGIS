import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
import os

# 1. 병합된 데이터 불러오기
# (이전 파일 경로와 동일하게 맞춰주세요)
file_path = r"C:\Users\kjs64\OneDrive\바탕 화면\AEGIS\data\total_dataset.csv"
df = pd.read_csv(file_path)

print(f"[*] 데이터 로드 완료: 총 {len(df)}개의 데이터")

# 2. 문제(X)와 정답(y) 분리하기
# 주의: 'timestamp'는 시간 정보일 뿐 공격 패턴 자체가 아니므로 AI가 오해하지 않게 삭제합니다.
# 'label'은 우리가 맞혀야 할 정답이므로 따로 빼둡니다.
X = df.drop(columns=['timestamp', 'label']) 
y = df['label']

# 3. 학습용(Train) 데이터와 테스트용(Test) 데이터 나누기 (8:2 비율)
# 80%의 데이터로 공부하고, 20%의 데이터로 시험을 봅니다.
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

print("[*] AI 모델 학습을 시작합니다. 잠시만 기다려주세요...")

# 4. 랜덤 포레스트 모델 생성 및 학습
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train) # 여기가 실제로 AI가 공부하는 부분입니다!

# 5. 테스트 데이터로 채점(예측)해보기
y_pred = model.predict(X_test)

# 6. 결과 출력
accuracy = accuracy_score(y_test, y_pred)
print("\n=========================================")
print(f"✅ AI 모델 학습 완료! (정확도: {accuracy * 100:.2f}%)")
print("=========================================")
print("\n[상세 성적표]")
print(classification_report(y_test, y_pred))
joblib.dump(model, 'aegis_model.pkl')
print("[*] AI 모델이 'aegis_model.pkl'로 저장되었습니다.")