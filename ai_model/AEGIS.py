import joblib
import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

# ---------------------------------------------------------
# 1. 프로젝트 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/ai_model/AEGIS.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = PROJECT_ROOT / "data" / "processed_data" / "merged_data" / "all_dataset.csv"
MODEL_PATH = PROJECT_ROOT / "ai_model" / "AEGIS.pkl"


# ---------------------------------------------------------
# 2. 병합된 데이터 불러오기
# ---------------------------------------------------------
if not DATA_PATH.exists():
    raise FileNotFoundError(f"[ERROR] 데이터 파일을 찾을 수 없습니다: {DATA_PATH}")

df = pd.read_csv(DATA_PATH)

print(f"[*] 데이터 로드 완료: 총 {len(df)}개의 데이터")
print(f"[*] 데이터 경로: {DATA_PATH}")


# ---------------------------------------------------------
# 3. 문제(X)와 정답(y) 분리
# ---------------------------------------------------------
# timestamp는 시간 정보라서 학습 입력에서 제외
# label은 정답이므로 y로 분리
# ---------------------------------------------------------
X = df.drop(columns=["timestamp", "label"])
y = df["label"]


# ---------------------------------------------------------
# 4. 학습용 / 테스트용 데이터 분리
# ---------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

print("[*] AI 모델 학습을 시작합니다.")


# ---------------------------------------------------------
# 5. 랜덤 포레스트 모델 생성 및 학습
# ---------------------------------------------------------
model = RandomForestClassifier(
    n_estimators=300,
    min_samples_leaf=2,
    class_weight="balanced",
    random_state=42,
)

model.fit(X_train, y_train)


# ---------------------------------------------------------
# 6. 테스트 데이터로 성능 평가
# ---------------------------------------------------------
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\n=========================================")
print(f"✅ AI 모델 학습 완료! 정확도: {accuracy * 100:.2f}%")
print("=========================================")

print("\n[상세 성적표]")
print(classification_report(y_test, y_pred))


# ---------------------------------------------------------
# 7. 학습된 모델 저장
# ---------------------------------------------------------
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

joblib.dump(model, MODEL_PATH)

print(f"\n✅ 완료: 학습된 모델이 저장되었습니다.")
print(f"[*] 모델 저장 경로: {MODEL_PATH}")
