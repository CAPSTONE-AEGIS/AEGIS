import streamlit as st
import pandas as pd
import json
import time
import os

# --- [초기 설정: 로그 파일 경로] ---
# 실행하는 메인 폴더(Capstone) 기준으로 경로 수정 완료
LOG_FILE = "live_dashboard.json"

# 웹 페이지 탭 이름과 레이아웃 설정
st.set_page_config(page_title="AEGIS 관제", page_icon="🛡️", layout="wide")
st.title("🛡️ AEGIS 실시간 네트워크 관제 대시보드")


# --- [데이터 로드 함수] ---
def load_data():
    data = []
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():  # 빈 줄 무시
                    data.append(json.loads(line.strip()))
    return pd.DataFrame(data)


# --- [실시간 화면 렌더링 영역] ---
# st.empty()를 사용해 화면이 아래로 늘어나지 않고 제자리에서 새로고침되게 만듦
placeholder = st.empty()

with placeholder.container():
    df = load_data()

    if not df.empty:
        # 1. 상단 요약 (가장 최근 데이터 기준)
        total_logs = len(df)
        recent_label = df.iloc[-1]["label"]

        col1, col2 = st.columns(2)
        col1.metric("총 수집된 트래픽 로그", f"{total_logs} 건")

        if recent_label == 0:
            col2.metric("최근 위협 상태", "✅ 정상 (0)")
        else:
            col2.metric("최근 위협 상태", f"🚨 탐지됨 ({recent_label})")

        st.markdown("---")

        # 2. 좌우 분할 화면 (차트와 상세 표)
        chart_col, table_col = st.columns([1, 2])

        with chart_col:
            st.subheader("📊 위협 레벨 분포")
            label_counts = df["label"].value_counts()
            st.bar_chart(label_counts)

        with table_col:
            st.subheader("📋 최근 10건의 상세 로그")
            # 가장 최근 로그가 맨 위로 오도록 역순 정렬
            st.dataframe(df.iloc[::-1].head(10), use_container_width=True)

    else:
        st.info(
            "데이터 수집 대기 중... (터미널에서 Extractor와 Monitor가 켜져 있는지 확인하세요)"
        )

# --- [무한 새로고침 로직] ---
# 2초마다 화면 전체를 다시 그려서 실시간 관제 효과를 냄
time.sleep(2)
st.rerun()
