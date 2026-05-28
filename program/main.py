import subprocess
import sys
import time
import signal
from pathlib import Path

# ---------------------------------------------------------
# 1. 프로젝트 경로 설정
# ---------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROGRAM_DIR = PROJECT_ROOT / "program"
COLLECTED_DATA_DIR = PROJECT_ROOT / "data" / "collected_data"

FEATURE_FILE = COLLECTED_DATA_DIR / "live_features.csv"
PREDICT_FILE = COLLECTED_DATA_DIR / "live_predictions.csv"
DASHBOARD_FILE = COLLECTED_DATA_DIR / "live_dashboard.json"


# ---------------------------------------------------------
# 2. 실행할 파일 경로
# ---------------------------------------------------------
FEATURE_EXTRACTOR = PROGRAM_DIR / "feature_extractor.py"
PREDICTOR = PROGRAM_DIR / "predictor.py"
MONITOR = PROGRAM_DIR / "monitor.py"
DASHBOARD = PROGRAM_DIR / "dashboard.py"


processes = []


# ---------------------------------------------------------
# 3. 기존 실시간 파일 초기화
# ---------------------------------------------------------
def reset_runtime_files():
    COLLECTED_DATA_DIR.mkdir(parents=True, exist_ok=True)

    for file_path in [FEATURE_FILE, PREDICT_FILE, DASHBOARD_FILE]:
        if file_path.exists():
            file_path.unlink()
            print(f"[*] 기존 파일 삭제: {file_path}")


# ---------------------------------------------------------
# 4. 프로세스 실행 함수
# ---------------------------------------------------------
def start_process(name, command):
    print(f"[*] {name} 시작: {' '.join(map(str, command))}")

    process = subprocess.Popen(
        command,
        cwd=PROJECT_ROOT,
    )

    processes.append((name, process))
    time.sleep(1)

    if process.poll() is not None:
        print(f"[ERROR] {name} 실행 직후 종료됨. 코드를 확인하세요.")

    return process


# ---------------------------------------------------------
# 5. 전체 종료 처리
# ---------------------------------------------------------
def stop_all_processes():
    print("\n[*] AEGIS 전체 종료 중...")

    for name, process in processes:
        if process.poll() is None:
            print(f"[*] {name} 종료")
            process.terminate()

    time.sleep(2)

    for name, process in processes:
        if process.poll() is None:
            print(f"[!] {name} 강제 종료")
            process.kill()

    print("[*] 종료 완료")


def handle_exit(signum, frame):
    stop_all_processes()
    sys.exit(0)


# ---------------------------------------------------------
# 6. 메인 실행
# ---------------------------------------------------------
def main():
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    print("=========================================")
    print("🛡️ AEGIS 실시간 네트워크 공격 탐지 시스템")
    print("=========================================")

    reset_runtime_files()

    python_cmd = sys.executable

    # 1. Feature Extractor
    # 패킷 캡처 때문에 main.py 자체를 sudo -E로 실행해야 함
    start_process(
        "Feature Extractor",
        [python_cmd, str(FEATURE_EXTRACTOR)],
    )

    # 2. Predictor
    start_process(
        "Predictor",
        [python_cmd, str(PREDICTOR)],
    )

    # 3. Monitor
    start_process(
        "Monitor",
        [python_cmd, str(MONITOR)],
    )

    # 4. Streamlit Dashboard
    start_process(
        "Dashboard",
        [python_cmd, "-m", "streamlit", "run", str(DASHBOARD)],
    )

    print("\n=========================================")
    print("✅ AEGIS 실행 완료")
    print("브라우저에서 Streamlit 대시보드를 확인하세요.")
    print("종료하려면 Ctrl + C")
    print("=========================================\n")

    try:
        while True:
            time.sleep(3)

            for name, process in processes:
                if process.poll() is not None:
                    print(f"[WARN] {name} 프로세스가 종료되었습니다.")

    except KeyboardInterrupt:
        stop_all_processes()


if __name__ == "__main__":
    main()
