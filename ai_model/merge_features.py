from pathlib import Path

import pandas as pd


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROCESSED_DATA_DIR = PROJECT_ROOT / "data" / "processed_data"
MERGED_DATA_DIR = PROCESSED_DATA_DIR / "merged_data"
OUTPUT_PATH = MERGED_DATA_DIR / "all_dataset.csv"


# Prefer freshly generated files from extract_features.py. If they are absent,
# fall back to the grouped CSV files already committed in merged_data.
FEATURE_FILE_GROUPS = [
    ["normal_features.csv", MERGED_DATA_DIR / "normal.csv"],
    ["icmp_features.csv", MERGED_DATA_DIR / "icmp_flood.csv"],
    ["port_features.csv", MERGED_DATA_DIR / "port_scan.csv"],
    ["ssh_features.csv", MERGED_DATA_DIR / "ssh_login.csv"],
    ["arp_features.csv", MERGED_DATA_DIR / "arp_spoofing.csv"],
    ["dns_features.csv", MERGED_DATA_DIR / "DNS.csv"],
]


def resolve_feature_file(candidates):
    for candidate in candidates:
        path = candidate if isinstance(candidate, Path) else PROCESSED_DATA_DIR / candidate

        if path.exists():
            return path

    return None


def merge_features():
    print("[*] Starting feature merge")
    print(f"[*] Processed data dir: {PROCESSED_DATA_DIR}")

    df_list = []

    for candidates in FEATURE_FILE_GROUPS:
        file_path = resolve_feature_file(candidates)

        if file_path is None:
            print(f"[WARN] Missing feature group: {candidates}")
            continue

        df = pd.read_csv(file_path)
        print(f" - loaded {file_path.name}: {len(df)} rows")

        df_list.append(df)

    if not df_list:
        print("[ERROR] No feature files were found; merge skipped.")
        return

    combined_df = pd.concat(df_list, ignore_index=True)

    MERGED_DATA_DIR.mkdir(parents=True, exist_ok=True)
    combined_df.to_csv(OUTPUT_PATH, index=False)

    print("=========================================")
    print(f"[OK] Merge complete: {len(combined_df)} rows")
    print(f"[OK] Output: {OUTPUT_PATH}")
    print("=========================================")

    if "label" in combined_df.columns:
        print("\n[Label distribution]")
        print(combined_df["label"].value_counts().sort_index())


if __name__ == "__main__":
    merge_features()
