import json
import time
from pathlib import Path

import pandas as pd
import streamlit as st


PROJECT_ROOT = Path(__file__).resolve().parents[1]
COLLECTED_DATA_DIR = PROJECT_ROOT / "data" / "collected_data"
LOG_FILE = COLLECTED_DATA_DIR / "live_dashboard.json"


LABEL_MAP = {
    -2: "SUSPICIOUS",
    -1: "UNKNOWN",
    0: "NORMAL",
    1: "ICMP Flood",
    2: "Port Scan",
    3: "SSH Brute Force",
    4: "ARP Spoofing",
    5: "DNS Anomaly",
}

RESPONSE_RECOMMENDATIONS = {
    "NORMAL": "정상 패턴입니다. 현재 모니터링을 유지하세요.",
    "UNKNOWN": "모델 확신도가 낮습니다.",
    "SUSPICIOUS": "정상 패턴에서 벗어난 트래픽입니다. 출발지 IP와 최근 세션을 우선 확인하고 필요 시 차단하세요.",
    "ICMP Flood": "ICMP 요청 비율을 제한하고 반복 출발지 IP를 방화벽에서 차단하세요.",
    "Port Scan": "스캔 출발지 IP를 확인하고 불필요하게 열린 포트와 방화벽 정책을 점검하세요.",
    "SSH Brute Force": "SSH 접속 출발지를 차단하고 계정 잠금, fail2ban, MFA 또는 키 기반 인증을 적용하세요.",
    "ARP Spoofing": "게이트웨이 MAC과 ARP 테이블 변조 여부를 확인하고 스위치 보안 기능을 적용하세요.",
    "DNS Anomaly": "DNS 질의량과 의심 도메인을 확인하고 비정상 클라이언트 또는 도메인을 차단하세요.",
}

PRIORITY_COLUMNS = [
    "anomaly_score",
    "attack_type",
    "risk_level",
    "alert_message",
]


st.set_page_config(
    page_title="AEGIS Dashboard",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AEGIS 실시간 네트워크 관제 대시보드")


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


def get_attack_type(row):
    if "attack_type" in row and pd.notna(row["attack_type"]):
        return row["attack_type"]

    try:
        return LABEL_MAP.get(int(row.get("label", 0)), "UNKNOWN")
    except (TypeError, ValueError):
        return "UNKNOWN"


def add_dashboard_fields(df):
    if df.empty:
        return df

    df = df.copy()
    df["attack_type"] = df.apply(get_attack_type, axis=1)

    if "alert_message" in df.columns:
        df.loc[df["attack_type"] == "UNKNOWN", "alert_message"] = (
            "UNKNOWN traffic detected"
        )

    return df


def reorder_columns(df):
    df = df.drop(columns=["response_recommendation"], errors="ignore")
    first_cols = [col for col in PRIORITY_COLUMNS if col in df.columns]
    other_cols = [col for col in df.columns if col not in first_cols]
    return df[first_cols + other_cols]


placeholder = st.empty()

with placeholder.container():
    df = add_dashboard_fields(load_data())

    if not df.empty:
        total_logs = len(df)
        recent = df.iloc[-1]

        recent_label = int(recent.get("label", 0))
        recent_attack = recent.get(
            "attack_type", LABEL_MAP.get(recent_label, "UNKNOWN")
        )
        recent_risk = recent.get("risk_level", "UNKNOWN")

        col1, col2, col3 = st.columns(3)

        col1.metric("총 수집 로그", f"{total_logs} 건")

        if recent_label == 0:
            col2.metric("최근 위협 상태", "NORMAL")
        else:
            col2.metric("최근 위협 상태", recent_attack)

        col3.metric("위험도", recent_risk)

        st.markdown("---")

        chart_col, table_col = st.columns([1, 2])

        with chart_col:
            st.subheader("공격 유형 분포")
            st.bar_chart(df["attack_type"].value_counts())

        with table_col:
            st.subheader("최근 10건 탐지 로그")
            recent_logs = reorder_columns(df.iloc[::-1].head(10))
            st.dataframe(recent_logs, use_container_width=True, hide_index=True)

        st.markdown("---")

        st.subheader("공격 유형별 대응 권고")
        detected_attacks = list(dict.fromkeys(df.iloc[::-1]["attack_type"].tolist()))

        for attack_type in detected_attacks:
            recommendation = RESPONSE_RECOMMENDATIONS.get(
                attack_type,
                "상세 로그와 원본 패킷을 확인한 뒤 대응 정책을 점검하세요.",
            )
            st.markdown(f"**{attack_type}**: {recommendation}")

        st.markdown("---")

        st.subheader("주요 Feature 변화")

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


time.sleep(2)
st.rerun()
