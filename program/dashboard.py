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
    "NORMAL": """
- 유형: 정상 트래픽
- 의미: 현재 5초 윈도우의 패킷 수, 프로토콜 비율, DNS 질의, 로그인 실패, ARP 변화가 학습된 정상 범위 안에 있습니다.
- 확인: 갑작스러운 total_pkt_cnt 증가, dns_query_cnt 증가, failed_login_cnt 증가가 없는지 추세만 관찰합니다.
- 대응: 별도 차단은 하지 않고 모니터링을 유지합니다. 동일 구간에서 UNKNOWN이나 SUSPICIOUS가 반복되면 원본 패킷과 로그를 함께 확인합니다.
""",
    "UNKNOWN": """
- 유형: 확신도 부족 트래픽
- 의미: 분류 모델이 기존 공격 유형 또는 정상 중 하나로 확정하기에 confidence가 낮은 상태입니다.
- 확인: model_label, confidence, anomaly_score를 함께 보고, 어떤 피처가 평소보다 튀었는지 확인합니다.
- 대응: 즉시 차단보다는 원본 패킷, DNS 로그, SSH 로그, ARP 테이블을 확인합니다. UNKNOWN이 같은 출발지나 같은 시간대에 반복되면 SUSPICIOUS 또는 공격 후보로 격상해 조사합니다.
""",
    "SUSPICIOUS": """
- 유형: 의심 트래픽
- 의미: 분류 모델은 UNKNOWN으로 보류했고, 비지도 이상탐지 모델도 정상 패턴 밖으로 판단한 상태입니다.
- 추가 분리 기준: icmp_cnt가 높으면 ICMP Flood 후보, unique_dst_port_cnt와 syn_cnt가 높으면 Port Scan 후보, failed_login_cnt가 높으면 SSH Brute Force 후보, dns_query_cnt가 높으면 DNS Anomaly 후보, gratuitous_arp_cnt 또는 mac_change_cnt가 높으면 ARP Spoofing 후보입니다.
- 대응: 출발지 IP, 목적지 포트, DNS 질의 도메인, SSH 실패 계정, ARP 변경 이력을 우선 확인합니다. 동일 출발지에서 반복되면 방화벽 차단, 계정 잠금, DNS 차단, ARP 보안 정책 적용을 검토합니다.
""",
    "ICMP Flood": """
- 유형: ICMP Flood
- 공격 설명: 짧은 시간 동안 ICMP Echo Request 또는 유사 ICMP 패킷을 대량 전송해 대상 네트워크나 호스트의 처리량을 소모시키는 공격입니다.
- 주요 피처: icmp_cnt와 total_pkt_cnt가 함께 증가하고, 특정 출발지 또는 다수 출발지에서 반복적으로 관찰됩니다.
- 대응: ICMP rate limit을 적용하고 반복 출발지 IP를 방화벽에서 차단합니다. 서버와 게이트웨이의 CPU, 패킷 드롭, 회선 사용량을 확인하고 필요 시 upstream 장비에서 필터링합니다.
""",
    "Port Scan": """
- 유형: Port Scan
- 공격 설명: 공격자가 열린 포트와 서비스를 찾기 위해 여러 목적지 포트로 SYN 또는 연결 시도를 반복하는 정찰 행위입니다.
- 주요 피처: unique_dst_port_cnt와 syn_cnt가 증가하고, ack_cnt 대비 syn_cnt가 비정상적으로 높을 수 있습니다.
- 대응: 스캔 출발지 IP를 확인하고 방화벽에서 차단합니다. 외부에 노출된 불필요한 포트를 닫고, SSH/RDP/DB 등 관리 포트는 허용 IP 기반으로 제한합니다.
""",
    "SSH Brute Force": """
- 유형: SSH Brute Force
- 공격 설명: SSH 계정에 대해 비밀번호를 반복 대입하거나 여러 계정을 순차적으로 시도하는 인증 공격입니다.
- 주요 피처: failed_login_cnt가 증가하고 auth.log에 Failed password, invalid user, repeated authentication failure가 반복됩니다.
- 대응: 공격 출발지 IP를 차단하고 fail2ban 또는 계정 잠금 정책을 적용합니다. 비밀번호 로그인을 제한하고 SSH 키 기반 인증, MFA, 허용 IP 제한을 적용합니다.
""",
    "ARP Spoofing": """
- 유형: ARP Spoofing
- 공격 설명: 같은 네트워크 안에서 게이트웨이나 피해자 IP의 MAC 주소를 속여 트래픽을 가로채거나 중간자 공격을 시도하는 공격입니다.
- 주요 피처: gratuitous_arp_cnt 또는 mac_change_cnt가 증가하고, 동일 IP에 대해 MAC 주소가 바뀌는 현상이 나타납니다.
- 대응: 게이트웨이와 주요 서버의 ARP 테이블을 확인합니다. 스위치의 DHCP Snooping, Dynamic ARP Inspection, 포트 보안 기능을 적용하고 의심 호스트를 네트워크에서 격리합니다.
""",
    "DNS Anomaly": """
- 유형: DNS Anomaly
- 공격 설명: 비정상적으로 많은 DNS 질의, 랜덤 도메인 질의, DNS 터널링 의심 행위, 특정 도메인 반복 질의가 발생하는 상태입니다.
- 주요 피처: dns_query_cnt와 udp_cnt가 증가하고, DNS 로그에서 동일 클라이언트의 반복 질의 또는 랜덤 문자열 도메인이 관찰됩니다.
- 대응: 의심 클라이언트 IP와 질의 도메인을 확인합니다. 악성 또는 불필요한 도메인을 차단하고, DNS rate limit과 내부 DNS 서버 강제 사용 정책을 적용합니다.
""",
}

PRIORITY_COLUMNS = [
    "anomaly_score",
    "attack_type",
    "suspicious_candidate",
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

    if (df["attack_type"] == "SUSPICIOUS").any():
        df["suspicious_candidate"] = df.apply(infer_suspicious_candidate, axis=1)

    return df


def infer_suspicious_candidate(row):
    if row.get("attack_type") != "SUSPICIOUS":
        return ""

    icmp_cnt = row.get("icmp_cnt", 0) or 0
    unique_dst_port_cnt = row.get("unique_dst_port_cnt", 0) or 0
    syn_cnt = row.get("syn_cnt", 0) or 0
    dns_query_cnt = row.get("dns_query_cnt", 0) or 0
    failed_login_cnt = row.get("failed_login_cnt", 0) or 0
    gratuitous_arp_cnt = row.get("gratuitous_arp_cnt", 0) or 0
    mac_change_cnt = row.get("mac_change_cnt", 0) or 0

    candidates = [
        ("ICMP Flood candidate", icmp_cnt),
        ("Port Scan candidate", unique_dst_port_cnt + syn_cnt),
        ("DNS Anomaly candidate", dns_query_cnt),
        ("SSH Brute Force candidate", failed_login_cnt),
        ("ARP Spoofing candidate", gratuitous_arp_cnt + mac_change_cnt),
    ]
    candidate, score = max(candidates, key=lambda item: item[1])

    if score <= 0:
        return "Unclassified suspicious traffic"

    return candidate


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
            st.markdown(f"#### {attack_type}")
            st.markdown(recommendation)

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
