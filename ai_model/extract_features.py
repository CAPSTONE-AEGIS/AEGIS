import pandas as pd
from scapy.all import PcapReader
from collections import defaultdict


def extract_to_csv(pcap_file, output_csv, label):
    # 1초 단위로 12가지 통합 특징을 담을 딕셔너리
    time_stats = defaultdict(
        lambda: {
            # 1. [기본 트래픽 통계]
            "total_pkt_cnt": 0,  # 전체 패킷 수: 트래픽 급증을 유발하는 모든 Flood 계열 공격의 기초 지표
            # 2. [프로토콜별 분포]
            "tcp_cnt": 0,  # TCP 패킷 수: Port Scan, SYN Flood, SSH 공격의 기본 관찰 대상
            "udp_cnt": 0,  # UDP 패킷 수: UDP Flood나 비정상적인 데이터 전송 탐지
            "icmp_cnt": 0,  # ICMP 패킷 수: ICMP Flood(Ping 공격) 탐지의 핵심 지표
            # 3. [TCP 상태 제어]
            "syn_cnt": 0,  # TCP SYN 수: Port Scan(포트 찌르기) 및 SYN Flood(연결 고갈) 탐지의 핵심
            "ack_cnt": 0,  # TCP ACK 수: SYN 대비 ACK 비율이 너무 낮으면 SYN Flood로 판단하는 근거
            # 4. [공격 패턴 탐지 지표]
            "unique_dst_port_cnt": 0,  # 목적지 포트 수: 짧은 시간 내 포트가 다양하게 바뀌면 100% Port Scan
            "unique_src_ip_cnt": 0,  # 출발지 IP 수: 패킷은 많은데 IP가 1개면 DoS, 많으면 DDoS로 구분
            # 5. [애플리케이션/계층 특화]
            "dns_query_cnt": 0,  # DNS 질의 수: DNS 증폭 공격(Amplification)이나 DNS 이상 트래픽 탐지
            "gratuitous_arp_cnt": 0,  # 비요청 ARP 응답: ARP Spoofing(주소 변조) 공격이 발생했다는 직접적 증거
            # 6. [외부 로그 연동 피처]
            "failed_login_cnt": 0,  # 로그인 실패 횟수: auth.log 기반, SSH Brute Force(무차별 대입) 탐지의 유일한 단서
            "mac_change_cnt": 0,  # MAC 주소 변경 횟수: ip neigh 기반, ARP Spoofing으로 인한 'MAC 플래핑' 탐지
            # [계산용 임시 데이터 - CSV 저장 안 함]
            "_src_ips": set(),  # unique_src_ip_cnt를 계산하기 위한 중복 제거 집합
            "_dst_ports": set(),  # unique_dst_port_cnt를 계산하기 위한 중복 제거 집합
        }
    )

    ip_mac_table = {}

    print(f"[*] [{pcap_file}] 분석 시작 (라벨: {label})...")

    with PcapReader(pcap_file) as pcap_reader:
        for pkt in pcap_reader:
            ts = int(pkt.time)
            s = time_stats[ts]

            # [수정된 핵심 1] IP/ARP 상관없이 이 패킷을 무조건 전체 패킷 수에 포함시킨다!
            s["total_pkt_cnt"] += 1

            # 1. IP 계층이 있는 일반 패킷 (TCP/UDP/ICMP)
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
                    if pkt.haslayer("DNS") and pkt["DNS"].qr == 0:
                        s["dns_query_cnt"] += 1

                elif pkt.haslayer("ICMP"):
                    s["icmp_cnt"] += 1

            # 2. ARP 패킷 분석
            elif pkt.haslayer("ARP"):
                if pkt["ARP"].op == 2:  # ARP Reply
                    s["gratuitous_arp_cnt"] += 1

                # MAC 변조 탐지
                arp_ip = pkt["ARP"].psrc
                arp_mac = pkt["ARP"].hwsrc

                if arp_ip in ip_mac_table:
                    if ip_mac_table[arp_ip] != arp_mac:
                        s["mac_change_cnt"] += 1
                        ip_mac_table[arp_ip] = arp_mac
                else:
                    ip_mac_table[arp_ip] = arp_mac

    rows = []
    for ts, s in sorted(time_stats.items()):
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
                "failed_login_cnt": 0,
                "mac_change_cnt": s["mac_change_cnt"],
                "label": label,
            }
        )

    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"✅ 완료: {output_csv} ({len(df)}개 행 생성)")


# 파이썬 파일을 실행할 때 동작하는 부분입니다.
if __name__ == "__main__":
    # 알려주신 폴더 경로에 파일명만 추가하여 세팅했습니다.
    # ⚠️ '파일명.pcap'과 '결과.csv' 부분을 실제 파일 이름으로 바꿔주세요.

    input_pcap = r"C:\Users\kjs64\OneDrive\문서\카카오톡 받은 파일\normal_001.pcap"
    output_csv = r"C:\Users\kjs64\OneDrive\문서\카카오톡 받은 파일\normal_001.csv"

    # ⚠️ 분석하려는 파일의 성격에 맞게 라벨(label)을 0~5 사이로 수정하세요.
    # 0: 정상, 1: ICMP Flood, 2: Port Scan, 3: SSH Brute Force, 4: DNS 이상 트래픽, 5: ARP Spoofing
    target_label = 0

    # 변환 실행
    extract_to_csv(input_pcap, output_csv, label=target_label)
