import pandas as pd
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score

from imblearn.over_sampling import SMOTE

# ---------------------------------------------------------
# 1. 프로젝트 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/ai_model/test_model.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

DATA_PATH = PROJECT_ROOT / "data" / "processed_data" / "merged_data" / "all_dataset.csv"


# ---------------------------------------------------------
# 2. 데이터 불러오기
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


print("\n[원본 label 분포]")
print(y.value_counts().sort_index())


# ---------------------------------------------------------
# 4. 학습용 / 테스트용 데이터 분리
# ---------------------------------------------------------
# stratify=y:
# 각 label 비율을 train/test에 최대한 비슷하게 유지
# ---------------------------------------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y,
)


# ---------------------------------------------------------
# 5. SMOTE 적용
# ---------------------------------------------------------
# 데이터 개수가 적은 label을 보간 방식으로 늘림
# k_neighbors=2:
# 소수 class 데이터가 많지 않을 때 안전하게 낮게 설정
# ---------------------------------------------------------
smote = SMOTE(
    random_state=42,
    k_neighbors=2,
)

X_train_smote, y_train_smote = smote.fit_resample(X_train, y_train)

print("\n[*] SMOTE 적용 전 훈련 데이터 수:", len(X_train))
print("[*] SMOTE 적용 후 훈련 데이터 수:", len(X_train_smote))

print("\n[SMOTE 적용 후 train label 분포]")
print(pd.Series(y_train_smote).value_counts().sort_index())


# ---------------------------------------------------------
# 6. RandomForest 모델 학습
# ---------------------------------------------------------
rf_model = RandomForestClassifier(
    n_estimators=100,
    random_state=42,
    class_weight="balanced",
)

print("\n[*] AI 모델 학습을 시작합니다.")
rf_model.fit(X_train_smote, y_train_smote)


# ---------------------------------------------------------
# 7. 테스트 및 평가
# ---------------------------------------------------------
# 테스트 데이터는 SMOTE를 적용하지 않은 원본 테스트 데이터 사용
# ---------------------------------------------------------
y_pred = rf_model.predict(X_test)

acc = accuracy_score(y_test, y_pred)

print("\n=========================================")
print(f"✅ AI 모델 학습 완료! 정확도: {acc * 100:.2f}%")
print("=========================================")

print("\n[상세 성적표]")
print(classification_report(y_test, y_pred))
