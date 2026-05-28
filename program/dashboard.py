import streamlit as st
import pandas as pd
import json
import time
from pathlib import Path

# ---------------------------------------------------------
# 1. 파일 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/program/dashboard.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

COLLECTED_DATA_DIR = PROJECT_ROOT / "data" / "collected_data"
LOG_FILE = COLLECTED_DATA_DIR / "live_dashboard.json"


# ---------------------------------------------------------
# 2. Streamlit 기본 설정
# ---------------------------------------------------------
st.set_page_config(
    page_title="AEGIS 관제",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AEGIS 실시간 네트워크 관제 대시보드")


# ---------------------------------------------------------
# 3. label 매핑
# ---------------------------------------------------------
LABEL_MAP = {
    0: "Normal",
    1: "ICMP Flood",
    2: "Port Scan",
    3: "SSH Brute Force",
    4: "ARP Spoofing",
    5: "DNS Anomaly",
}


# ---------------------------------------------------------
# 4. 데이터 로드 함수
# ---------------------------------------------------------
def load_data():
    data = []

    if not LOG_FILE.exists():
        return pd.DataFrame(data)

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue

            try:
                data.append(json.loads(line.strip()))
            except json.JSONDecodeError:
                continue

    return pd.DataFrame(data)


# ---------------------------------------------------------
# 5. 실시간 화면 렌더링
# ---------------------------------------------------------
placeholder = st.empty()

with placeholder.container():
    df = load_data()

    if not df.empty:
        total_logs = len(df)
        recent = df.iloc[-1]

        recent_label = int(recent.get("label", 0))
        recent_attack = recent.get(
            "attack_type", LABEL_MAP.get(recent_label, "Unknown")
        )
        recent_risk = recent.get("risk_level", "Unknown")

        # -------------------------------------------------
        # 상단 요약
        # -------------------------------------------------
        col1, col2, col3 = st.columns(3)

        col1.metric("총 수집 로그", f"{total_logs} 건")

        if recent_label == 0:
            col2.metric("최근 위협 상태", "✅ 정상")
        else:
            col2.metric("최근 위협 상태", f"🚨 {recent_attack}")

        col3.metric("위험도", recent_risk)

        st.markdown("---")

        # -------------------------------------------------
        # 차트 + 최근 로그
        # -------------------------------------------------
        chart_col, table_col = st.columns([1, 2])

        with chart_col:
            st.subheader("📊 공격 유형 분포")

            if "attack_type" in df.columns:
                attack_counts = df["attack_type"].value_counts()
            else:
                attack_counts = df["label"].value_counts()

            st.bar_chart(attack_counts)

        with table_col:
            st.subheader("📋 최근 10건 탐지 로그")
            st.dataframe(df.iloc[::-1].head(10), use_container_width=True)

        st.markdown("---")

        # -------------------------------------------------
        # 주요 feature 변화
        # -------------------------------------------------
        st.subheader("📈 주요 Feature 변화")

        feature_cols = [
            "total_pkt_cnt",
            "tcp_cnt",
            "udp_cnt",
            "icmp_cnt",
            "syn_cnt",
            "ack_cnt",
            "dns_query_cnt",
            "failed_login_cnt",
            "mac_change_cnt",
        ]

        existing_cols = [col for col in feature_cols if col in df.columns]

        if existing_cols:
            st.line_chart(df[existing_cols].tail(30))
        else:
            st.info("표시할 feature 컬럼이 아직 없습니다.")

    else:
        st.info(
            "데이터 수집 대기 중... "
            "feature_extractor.py, predictor.py, monitor.py가 실행 중인지 확인하세요."
        )


# ---------------------------------------------------------
# 6. 자동 새로고침
# ---------------------------------------------------------
time.sleep(2)
st.rerun()
