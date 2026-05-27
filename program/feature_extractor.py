import time
from scapy.all import sniff
from collections import defaultdict
import threading
import csv
import os

# ---------------------------------------------------------
# 1. 초기 환경 설정 (Configuration)
# ---------------------------------------------------------
# 리눅스 시스템의 SSH 접속 시도 로그가 저장되는 기본 경로 (Ubuntu/Debian 기준)
AUTH_LOG_PATH = "/var/log/auth.log"

# 특징 추출기가 데이터를 모아서 던져줄 중간 파일 (Predictor가 이걸 읽어감)
FEATURE_OUT_FILE = PROJECT_ROOT / "data" / "collected_data" / "live_features.csv"

# 시간 바구니 크기 (5초 동안 들어오는 패킷/로그를 하나로 뭉침)
WINDOW_SIZE = 5

# ---------------------------------------------------------
# 2. CSV 파일 헤더(컬럼명) 초기 세팅
# ---------------------------------------------------------
# 파일이 없을 때만 1회 생성 (AI 모델 학습 시 사용했던 순서와 100% 동일해야 함)
if not os.path.exists(FEATURE_OUT_FILE):
    with open(FEATURE_OUT_FILE, "w", newline="", encoding="utf-8") as f:
        f.write(
            "timestamp,total_pkt_cnt,tcp_cnt,udp_cnt,icmp_cnt,syn_cnt,ack_cnt,unique_dst_port_cnt,unique_src_ip_cnt,dns_query_cnt,gratuitous_arp_cnt,failed_login_cnt,mac_change_cnt\n"
        )

# ---------------------------------------------------------
# 3. 데이터 저장소 (Time Bucket) 설계
# ---------------------------------------------------------
# 5초 단위의 타임스탬프(예: 100, 105, 110...)를 키(Key)로 사용하는 딕셔너리.
# 해당 시간에 데이터가 처음 들어오면 자동으로 0이나 빈 집합(set)으로 초기화됨.
time_stats = defaultdict(
    lambda: {
        "total_pkt_cnt": 0,
        "tcp_cnt": 0,
        "udp_cnt": 0,
        "icmp_cnt": 0,
        "syn_cnt": 0,
        "ack_cnt": 0,
        "unique_dst_port_cnt": 0,
        "unique_src_ip_cnt": 0,
        "dns_query_cnt": 0,
        "gratuitous_arp_cnt": 0,
        "failed_login_cnt": 0,
        "mac_change_cnt": 0,
        "_src_ips": set(),
        "_dst_ports": set(),  # 중복 제거를 위해 집합(set) 자료형 사용
    }
)

# ARP 스푸핑 탐지용 (IP에 매칭되는 진짜 MAC 주소를 기억해두는 캐시 테이블)
ip_mac_table = {}


# ---------------------------------------------------------
# 4. [스레드 1] 시스템 로그 감시 (SSH Brute Force 담당)
# ---------------------------------------------------------
def monitor_auth_log():
    try:
        with open(AUTH_LOG_PATH, "r") as f:
            f.seek(
                0, 2
            )  # 파일의 맨 끝(최신 로그)으로 이동 (리눅스의 'tail -f' 명령어와 같은 역할)
            while True:
                line = f.readline()
                if not line:
                    time.sleep(
                        0.1
                    )  # 새 로그가 없으면 0.1초 쉬고 다시 확인 (CPU 100% 과부하 방지)
                    continue

                # 새 로그 중 "비밀번호 실패" 문구가 발견되면
                if "Failed password" in line:
                    # 현재 시간을 5초 단위 바구니로 환산해서 실패 카운트 1 증가
                    current_bucket = (int(time.time()) // WINDOW_SIZE) * WINDOW_SIZE
                    time_stats[current_bucket]["failed_login_cnt"] += 1
    except PermissionError:
        # auth.log는 루트 권한 없이 못 읽으므로 권한 부족 시 에러 메시지 출력
        print("[!] 권한 에러: sudo로 실행해야 로그를 읽을 수 있습니다.")


# ---------------------------------------------------------
# 5. [스레드 2] 실시간 네트워크 패킷 감시 (Scapy Sniffer)
# ---------------------------------------------------------
def process_packet(pkt):
    # 패킷 도착 시간을 5초 단위 바구니 시간으로 환산
    current_bucket = (int(pkt.time) // WINDOW_SIZE) * WINDOW_SIZE
    s = time_stats[current_bucket]

    s["total_pkt_cnt"] += 1  # 무조건 전체 패킷 수 1 증가

    # IP 계층이 있는 패킷 분석
    if pkt.haslayer("IP"):
        s["_src_ips"].add(pkt["IP"].src)  # 출발지 IP 수집 (set이라 자동 중복 제거)

        # TCP 패킷 분석 (Port Scan 등 탐지용)
        if pkt.haslayer("TCP"):
            s["tcp_cnt"] += 1
            s["_dst_ports"].add(pkt["TCP"].dport)
            # 비트 연산자로 TCP 플래그 확인 (0x02 = SYN 플래그, 0x10 = ACK 플래그)
            if pkt["TCP"].flags & 0x02:
                s["syn_cnt"] += 1
            if pkt["TCP"].flags & 0x10:
                s["ack_cnt"] += 1

        # UDP 패킷 분석 (DNS 이상 트래픽 탐지용)
        elif pkt.haslayer("UDP"):
            s["udp_cnt"] += 1
            s["_dst_ports"].add(pkt["UDP"].dport)
            # DNS 쿼리 요청(qr == 0)일 때만 카운트
            if pkt.haslayer("DNS") and pkt["DNS"].qr == 0:
                s["dns_query_cnt"] += 1

        # ICMP 패킷 분석 (Ping Flood 탐지용)
        elif pkt.haslayer("ICMP"):
            s["icmp_cnt"] += 1

    # ARP 계층 패킷 분석 (ARP Spoofing 탐지용)
    elif pkt.haslayer("ARP"):
        # op == 2 는 ARP Reply (응답) 패킷
        if pkt["ARP"].op == 2:
            s["gratuitous_arp_cnt"] += 1

        arp_ip = pkt["ARP"].psrc
        arp_mac = pkt["ARP"].hwsrc

        # 기존에 알던 IP-MAC 정보와 다르면 'MAC 변조 시도'로 간주하여 카운트 증가
        if arp_ip in ip_mac_table and ip_mac_table[arp_ip] != arp_mac:
            s["mac_change_cnt"] += 1
        # 최신 MAC 정보로 테이블 갱신
        ip_mac_table[arp_ip] = arp_mac


def run_sniffer():
    # store=False: 캡처한 패킷을 메모리에 저장하지 않고 바로바로 버림 (메모리 폭발 방지 핵심 옵션)
    # 현재 sniff() 함수에는 패킷 개수(count)나 시간(timeout) 제한 옵션이 없습니다.
    # 따라서 이 스크립트는 강제 종료하기 전까지 365일 24시간 무한정 패킷을 캡처
    # 현업 관제(SOC) 환경과 동일하게 '실시간 감시 모드'로 동작하기 위함

    # 멈추고 싶을 때: 터미널 창에서 'Ctrl + C'를 누르면 즉시 강제 종료

    # 만약 "딱 10분(600초)만 수집하고 자동으로 꺼지게" 만들고 싶다면 아래처럼 수정
    # sniff(prn=process_packet, store=False, timeout=600)

    # 종료 전까지 계속 캡쳐
    sniff(prn=process_packet, store=False)

    # 수정 후 (저장된 PCAP 파일 순식간에 읽기)
    # sniff(offline="ex_feature.pcap", prn=process_packet, store=False)


# ---------------------------------------------------------
# 6. 병렬 스레드 가동 (Background Execution)
# ---------------------------------------------------------
# daemon=True: 메인 프로그램이 종료되면 이 스레드들도 같이 강제 종료되도록 설정
threading.Thread(target=monitor_auth_log, daemon=True).start()
threading.Thread(target=run_sniffer, daemon=True).start()

print(f"[*] Extractor 가동 중... (5초 단위 특징 추출 -> {FEATURE_OUT_FILE})")

# ---------------------------------------------------------
# 7. [메인 스레드] 결산 및 CSV 내보내기 (File I/O)
# ---------------------------------------------------------
# 프로그램 시작 시점의 5초 단위 바구니 기준시간 확보
last_processed_bucket = (int(time.time()) // WINDOW_SIZE) * WINDOW_SIZE

while True:
    time.sleep(1)  # 1초마다 무한 루프 돌면서 시간 체크
    current_bucket = (int(time.time()) // WINDOW_SIZE) * WINDOW_SIZE

    # 현실 시간이 흘러서 새로운 5초 바구니가 시작되었다면? -> 이전 바구니 결산 시작
    if current_bucket > last_processed_bucket:
        # 딕셔너리에 이전 바구니 데이터가 남아있으면 꺼내옴 (pop: 꺼내면서 메모리에서 지움)
        if last_processed_bucket in time_stats:
            s = time_stats.pop(last_processed_bucket)

            # set()으로 모았던 IP와 Port는 개수(len)로 변환하여 AI가 읽을 수 있는 포맷으로 맞춤
            row = [
                last_processed_bucket,
                s["total_pkt_cnt"],
                s["tcp_cnt"],
                s["udp_cnt"],
                s["icmp_cnt"],
                s["syn_cnt"],
                s["ack_cnt"],
                len(s["_dst_ports"]),
                len(s["_src_ips"]),
                s["dns_query_cnt"],
                s["gratuitous_arp_cnt"],
                s["failed_login_cnt"],
                s["mac_change_cnt"],
            ]

            # CSV 파일에 결산된 한 줄 추가 (a = Append 모드)
            with open(FEATURE_OUT_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(row)

            print(f"[{last_processed_bucket}] 특징 추출 완료 (파일로 전송됨)")

        # 다음 결산을 위해 기준 시간 업데이트
        last_processed_bucket = current_bucket
