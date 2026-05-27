import pandas as pd
from scapy.all import PcapReader
from collections import defaultdict
import re
import os

def extract_to_csv(input_file, output_csv, label):
    # 5초 단위로 12가지 통합 특징을 담을 딕셔너리
    time_stats = defaultdict(lambda: {
        'total_pkt_cnt': 0, 'tcp_cnt': 0, 'udp_cnt': 0, 'icmp_cnt': 0,
        'syn_cnt': 0, 'ack_cnt': 0, 'unique_dst_port_cnt': 0, 'unique_src_ip_cnt': 0,
        'dns_query_cnt': 0, 'gratuitous_arp_cnt': 0, 'failed_login_cnt': 0, 'mac_change_cnt': 0,
        '_src_ips': set(), '_dst_ports': set()
    })
    
    file_ext = os.path.splitext(input_file)[1].lower()
    print(f"[*] [{input_file}] 5초 단위 분석 시작 (라벨: {label})...")

    # ---------------------------------------------------------
    # 1. PCAP 파일 분석 모드 (5초 단위 묶기)
    # ---------------------------------------------------------
    if file_ext in ['.pcap', '.pcapng']:
        ip_mac_table = {}
        with PcapReader(input_file) as pcap_reader:
            for pkt in pcap_reader:
                # 💡 핵심: 5초 단위로 버림 계산 (예: 14초 -> 10초, 19초 -> 15초)
                ts = (int(pkt.time) // 5) * 5
                s = time_stats[ts]
                
                s['total_pkt_cnt'] += 1
                if pkt.haslayer('IP'):
                    s['_src_ips'].add(pkt['IP'].src)
                    if pkt.haslayer('TCP'):
                        s['tcp_cnt'] += 1
                        s['_dst_ports'].add(pkt['TCP'].dport)
                        if pkt['TCP'].flags & 0x02: s['syn_cnt'] += 1
                        if pkt['TCP'].flags & 0x10: s['ack_cnt'] += 1
                    elif pkt.haslayer('UDP'):
                        s['udp_cnt'] += 1
                        s['_dst_ports'].add(pkt['UDP'].dport)
                        if pkt.haslayer('DNS') and pkt['DNS'].qr == 0:
                            s['dns_query_cnt'] += 1
                    elif pkt.haslayer('ICMP'):
                        s['icmp_cnt'] += 1
                
                elif pkt.haslayer('ARP'):
                    if pkt['ARP'].op == 2: s['gratuitous_arp_cnt'] += 1
                    arp_ip, arp_mac = pkt['ARP'].psrc, pkt['ARP'].hwsrc
                    if arp_ip in ip_mac_table and ip_mac_table[arp_ip] != arp_mac:
                        s['mac_change_cnt'] += 1
                    ip_mac_table[arp_ip] = arp_mac

    # ---------------------------------------------------------
    # 2. TXT / LOG 파일 분석 모드 (5초 단위 묶기)
    # ---------------------------------------------------------
    elif file_ext in ['.txt', '.log']:
        fail_pattern = re.compile(r"Failed password", re.IGNORECASE)
        time_pattern = re.compile(r"\d{2}:\d{2}:\d{2}")
        
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as f:
            for line_idx, line in enumerate(f):
                time_match = time_pattern.search(line)
                
                if time_match:
                    h, m, sec = map(int, time_match.group().split(':'))
                    # 💡 핵심: 초 단위를 5초 단위로 내림하여 문자열 생성 (예: 14:23:07 -> 14:23:05)
                    sec_5 = (sec // 5) * 5
                    ts = f"{h:02d}:{m:02d}:{sec_5:02d}"
                else:
                    # 시간이 없으면 5줄씩 한 그룹으로 묶음
                    ts = f"block_{(line_idx // 5) * 5}"
                    
                s = time_stats[ts]
                s['total_pkt_cnt'] += 1
                
                if fail_pattern.search(line):
                    s['failed_login_cnt'] += 1

    else:
        print(f"❌ 지원하지 않는 확장자입니다: {file_ext}")
        return

    # ---------------------------------------------------------
    # 3. 데이터 집계 및 CSV 저장
    # ---------------------------------------------------------
    rows = []
    for ts, s in sorted(time_stats.items(), key=lambda x: str(x[0])):
        rows.append({
            'timestamp': ts,
            'total_pkt_cnt': s['total_pkt_cnt'],
            'tcp_cnt': s['tcp_cnt'],
            'udp_cnt': s['udp_cnt'],
            'icmp_cnt': s['icmp_cnt'],
            'syn_cnt': s['syn_cnt'],
            'ack_cnt': s['ack_cnt'],
            'unique_dst_port_cnt': len(s['_dst_ports']), # 5초 동안 쌓인 고유 포트 수 (Port Scan 탐지에 최고)
            'unique_src_ip_cnt': len(s['_src_ips']),     # 5초 동안 접근한 고유 IP 수
            'dns_query_cnt': s['dns_query_cnt'],
            'gratuitous_arp_cnt': s['gratuitous_arp_cnt'],
            'failed_login_cnt': s['failed_login_cnt'],   # 5초 동안 실패한 로그인 횟수
            'mac_change_cnt': s['mac_change_cnt'],   
            'label': label
        })

    df = pd.DataFrame(rows)
    df.to_csv(output_csv, index=False)
    print(f"✅ 완료: {output_csv} ({len(df)}개 데이터 행 생성)")

# =========================================================
# 실행 환경 설정
# =========================================================
if __name__ == "__main__":
    
    # ⚠️ 바탕화면 경로 설정
    input_file = r"C:\Users\kjs64\OneDrive\바탕 화면\전처리 파일\normal_003.pcap"
    output_csv = r"C:\Users\kjs64\OneDrive\바탕 화면\전처리 파일\normal_003.csv"
    
    # 라벨 세팅 (0: normal, 1:icmp, 2: port scan, 3: ssh, 4: arp, 5: DNS)   
    target_label = 0
    
    # 실행
    extract_to_csv(input_file, output_csv, label=target_label)