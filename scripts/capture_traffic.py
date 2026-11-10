import csv
import time

from datetime import datetime
from pathlib import Path

from scapy.all import sniff, IP, TCP, UDP, ICMP


WINDOW_DURATION = 5
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# OUTPUT_FILE = Path("data/processed/network_features.csv")
OUTPUT_FILE = PROJECT_ROOT / "data" / "processed" / "network_features.csv"


def create_window():

    return {
        "packet_count": 0,
        "total_bytes": 0,
        "tcp_count": 0,
        "udp_count": 0,
        "icmp_count": 0,
        "other_count": 0,
        "src_ips": set(),
        "dst_ips": set(),
    }


def process_packet(packet, window):

    window["packet_count"] += 1

    window["total_bytes"] += len(packet)

    if IP in packet:

        window["src_ips"].add(packet[IP].src)

        window["dst_ips"].add(packet[IP].dst)

        if TCP in packet:
            window["tcp_count"] += 1

        elif UDP in packet:
            window["udp_count"] += 1

        elif ICMP in packet:
            window["icmp_count"] += 1

        else:
            window["other_count"] += 1

    else:
        window["other_count"] += 1


def calculate_features(window, duration):

    packet_count = window["packet_count"]

    total_bytes = window["total_bytes"]

    avg_packet_size = (
        total_bytes / packet_count
        if packet_count > 0
        else 0
    )

    packet_rate = packet_count / duration

    bytes_per_second = total_bytes / duration

    return {

        "timestamp": datetime.now().isoformat(),

        "packet_count": packet_count,

        "packet_rate": packet_rate,

        "avg_packet_size": avg_packet_size,

        "bytes_per_second": bytes_per_second,

        "tcp_count": window["tcp_count"],

        "udp_count": window["udp_count"],

        "icmp_count": window["icmp_count"],

        "other_count": window["other_count"],

        "unique_src_ips": len(window["src_ips"]),

        "unique_dst_ips": len(window["dst_ips"]),

    }


def save_features(features):

    OUTPUT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    file_exists = OUTPUT_FILE.exists()

    with open(
        OUTPUT_FILE,
        "a",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=features.keys()
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(features)


def main():

    print("Démarrage de la capture réseau...")

    print(f"Fenêtre temporelle : {WINDOW_DURATION} secondes")

    window = create_window()

    window_start = time.time()

    def packet_callback(packet):

        nonlocal window_start
        nonlocal window

        process_packet(packet, window)

        current_time = time.time()

        elapsed_time = current_time - window_start

        if elapsed_time >= WINDOW_DURATION:

            features = calculate_features(
                window,
                elapsed_time
            )

            save_features(features)
            print('______________')
            for feature in features:
                print(f"{feature} : {features[feature]}")
            print('______________')

            window = create_window()

            window_start = current_time

    sniff(
        prn=packet_callback,
        store=False
    )


if __name__ == "__main__":

    main()