import time
import json
import os
import pandas as pd

# --- [초기 설정: 파일 경로] ---
FEATURE_FILE = PROJECT_ROOT / "data" / "collected_data" / "live_features.csv"
PREDICT_FILE = PROJECT_ROOT / "data" / "collected_data" / "live_predictions.csv"
DASHBOARD_FILE = PROJECT_ROOT / "data" / "collected_data" / "live_dashboard.json"

print(f"[*] Monitor 가동: 데이터 병합 및 JSON 변환을 시작합니다...")

# 이미 JSON으로 구워내서 대시보드로 보낸 타임스탬프를 기억 (중복 처리 방지용)
processed_timestamps = set()

while True:
    try:
        # 두 파일이 모두 존재할 때만 병합 시도
        if os.path.exists(FEATURE_FILE) and os.path.exists(PREDICT_FILE):

            # 1. 파일 읽어오기
            df_features = pd.read_csv(FEATURE_FILE)
            df_preds = pd.read_csv(PREDICT_FILE)

            # 2. 'timestamp'를 기준으로 두 데이터 완벽하게 병합 (Inner Join)
            # (같은 시간대에 발생한 특징과 AI 라벨이 한 줄로 합쳐짐)
            df_merged = pd.merge(df_features, df_preds, on="timestamp", how="inner")

            new_logs_count = 0

            # 3. JSON 파일에 이어쓰기 (a 모드)
            with open(DASHBOARD_FILE, "a", encoding="utf-8") as f:
                for _, row in df_merged.iterrows():
                    ts = int(row["timestamp"])

                    # 아직 처리 안 한 새로운 시간대의 데이터라면?
                    if ts not in processed_timestamps:
                        # 데이터프레임 1줄을 딕셔너리로 변환
                        record = row.to_dict()

                        # 대시보드에서 숫자 깨지지 않게 깔끔한 정수(int)로 팩트 체크
                        record["timestamp"] = ts
                        record["label"] = int(record["label"])

                        # (선택) 대시보드에 띄울 직관적인 메시지 추가
                        record["alert_message"] = f"위협 레벨 {record['label']} 탐지"

                        # 4. 딕셔너리를 JSON 문자열로 바꿔서 파일에 한 줄씩 기록
                        f.write(json.dumps(record, ensure_ascii=False) + "\n")

                        # 방금 처리한 시간은 기억해둠
                        processed_timestamps.add(ts)
                        new_logs_count += 1

            if new_logs_count > 0:
                print(
                    f"[+] {new_logs_count}개의 새 로그 병합 완료 -> {DASHBOARD_FILE} 전송"
                )

        # 2초 대기 (CPU 100% 과부하 방지)
        time.sleep(2)

    except pd.errors.EmptyDataError:
        # 파일이 막 생성되어서 내용이 텅 비어있을 때 나는 에러 무시
        time.sleep(1)
    except Exception as e:
        # 파일 동시 접근 충돌 등 기타 에러 발생 시 잠깐 쉬고 재시도
        time.sleep(1)
