import os
import re
from pathlib import Path
from collections import defaultdict

import pandas as pd
from scapy.all import PcapReader

# ---------------------------------------------------------
# 1. 프로젝트 경로 설정
# ---------------------------------------------------------
# 현재 파일 위치:
# AEGIS/ai_model/extract_features.py
#
# PROJECT_ROOT:
# AEGIS/
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]

RAW_DATA_DIR = PROJECT_ROOT / "data" / "raw_data"
PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed_data"

WINDOW_SIZE = 5


# ---------------------------------------------------------
# 2. Feature 추출 함수
# ---------------------------------------------------------
def extract_to_csv(input_file, output_csv, label):
    input_file = Path(input_file)
    output_csv = Path(output_csv)

    if not input_file.exists():
        print(f"❌ 입력 파일 없음: {input_file}")
        return

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    # 5초 단위 feature 저장소
    time_stats = defaultdict(
        lambda: {
            "total_pkt_cnt": 0,
            "tcp_cnt": 0,
            "udp_cnt": 0,
            "icmp_cnt": 0,
            "syn_cnt": 0,
            "ack_cnt": 0,
            "dns_query_cnt": 0,
            "gratuitous_arp_cnt": 0,
            "failed_login_cnt": 0,
            "mac_change_cnt": 0,
            "_src_ips": set(),
            "_dst_ports": set(),
        }
    )

    file_ext = input_file.suffix.lower()

    print(f"[*] 분석 시작: {input_file}")
    print(f"[*] 출력 파일: {output_csv}")
    print(f"[*] label: {label}")

    # ---------------------------------------------------------
    # 3. PCAP / PCAPNG 파일 분석
    # ---------------------------------------------------------
    if file_ext in [".pcap", ".pcapng"]:
        ip_mac_table = {}

        with PcapReader(str(input_file)) as pcap_reader:
            for pkt in pcap_reader:
                # 5초 단위 timestamp
                ts = (int(pkt.time) // WINDOW_SIZE) * WINDOW_SIZE
                s = time_stats[ts]

                s["total_pkt_cnt"] += 1

                # IP 패킷 분석
                if pkt.haslayer("IP"):
                    s["_src_ips"].add(pkt["IP"].src)

                    if pkt.haslayer("TCP"):
                        s["tcp_cnt"] += 1
                        s["_dst_ports"].add(pkt["TCP"].dport)

                        if pkt["TCP"].flags & 0x02:
                            s["syn_cnt"] += 1

                        if pkt["TCP"].flags & 0x10:
                            s["ack_cnt"] += 1

                    elif pkt.haslayer("UDP"):
                        s["udp_cnt"] += 1
                        s["_dst_ports"].add(pkt["UDP"].dport)

                        # DNS query만 카운트
                        if pkt.haslayer("DNS") and pkt["DNS"].qr == 0:
                            s["dns_query_cnt"] += 1

                    elif pkt.haslayer("ICMP"):
                        s["icmp_cnt"] += 1

                # ARP 패킷 분석
                elif pkt.haslayer("ARP"):
                    # 현재 코드는 ARP Reply를 카운트함
                    # 변수명은 gratuitous_arp_cnt지만 실제 의미는 arp_reply_cnt에 가까움
                    if pkt["ARP"].op == 2:
                        s["gratuitous_arp_cnt"] += 1

                    arp_ip = pkt["ARP"].psrc
                    arp_mac = pkt["ARP"].hwsrc

                    if arp_ip in ip_mac_table and ip_mac_table[arp_ip] != arp_mac:
                        s["mac_change_cnt"] += 1

                    ip_mac_table[arp_ip] = arp_mac

    # ---------------------------------------------------------
    # 4. LOG / TXT 파일 분석
    # ---------------------------------------------------------
    elif file_ext in [".txt", ".log"]:
        fail_pattern = re.compile(r"Failed password", re.IGNORECASE)
        time_pattern = re.compile(r"\d{2}:\d{2}:\d{2}")

        with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
            for line_idx, line in enumerate(f):
                time_match = time_pattern.search(line)

                if time_match:
                    h, m, sec = map(int, time_match.group().split(":"))
                    sec_5 = (sec // WINDOW_SIZE) * WINDOW_SIZE
                    ts = f"{h:02d}:{m:02d}:{sec_5:02d}"
                else:
                    # 시간이 없는 로그는 5줄 단위 임시 bucket
                    ts = f"block_{(line_idx // WINDOW_SIZE) * WINDOW_SIZE}"

                s = time_stats[ts]

                # 로그 파일에서는 이 값을 "로그 라인 수"처럼 사용
                s["total_pkt_cnt"] += 1

                if fail_pattern.search(line):
                    s["failed_login_cnt"] += 1

    else:
        print(f"❌ 지원하지 않는 확장자: {file_ext}")
        return

    # ---------------------------------------------------------
    # 5. CSV 저장
    # ---------------------------------------------------------
    rows = []

    for ts, s in sorted(time_stats.items(), key=lambda x: str(x[0])):
        rows.append(
            {
                "timestamp": ts,
                "total_pkt_cnt": s["total_pkt_cnt"],
                "tcp_cnt": s["tcp_cnt"],
                "udp_cnt": s["udp_cnt"],
                "icmp_cnt": s["icmp_cnt"],
                "syn_cnt": s["syn_cnt"],
                "ack_cnt": s["ack_cnt"],
                "unique_dst_port_cnt": len(s["_dst_ports"]),
                "unique_src_ip_cnt": len(s["_src_ips"]),
                "dns_query_cnt": s["dns_query_cnt"],
                "gratuitous_arp_cnt": s["gratuitous_arp_cnt"],
                "failed_login_cnt": s["failed_login_cnt"],
                "mac_change_cnt": s["mac_change_cnt"],
                "label": label,
            }
        )

    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)

    print(f"✅ 완료: {output_csv} ({len(df)}행 생성)")


# ---------------------------------------------------------
# 6. 실행부
# ---------------------------------------------------------
if __name__ == "__main__":
    # label 기준
    # 0: Normal
    # 1: ICMP Flood
    # 2: Port Scan
    # 3: SSH Brute Force
    # 4: DNS Anomaly
    # 5: ARP Spoofing

    jobs = [
        {
            "input": RAW_DATA_DIR / "normal" / "normal.pcap",
            "output": PROCESSED_DATA_DIR / "normal_features.csv",
            "label": 0,
        },
        {
            "input": RAW_DATA_DIR / "icmp_flood" / "icmp_flood.pcap",
            "output": PROCESSED_DATA_DIR / "icmp_features.csv",
            "label": 1,
        },
        {
            "input": RAW_DATA_DIR / "port_scan" / "port_scan.pcap",
            "output": PROCESSED_DATA_DIR / "port_features.csv",
            "label": 2,
        },
        {
            "input": RAW_DATA_DIR / "ssh_bruteforce" / "ssh_login_attempts.log",
            "output": PROCESSED_DATA_DIR / "ssh_features.csv",
            "label": 3,
        },
        {
            "input": RAW_DATA_DIR / "dns_anomaly" / "dns_anomaly.pcap",
            "output": PROCESSED_DATA_DIR / "dns_features.csv",
            "label": 4,
        },
        {
            "input": RAW_DATA_DIR / "arp_spoofing" / "arp_spoofing.pcap",
            "output": PROCESSED_DATA_DIR / "arp_features.csv",
            "label": 5,
        },
    ]

    for job in jobs:
        extract_to_csv(
            input_file=job["input"],
            output_csv=job["output"],
            label=job["label"],
        )
        print("-" * 60)
