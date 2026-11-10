from scapy.all import sniff

from src.feature_extractor import extract_packet_features


def capture_packets(count=10, iface=None):

    captured_packets = []

    def process_packet(packet):

        features = extract_packet_features(packet)

        captured_packets.append(features)

        print(features)

    sniff(
        count=count,
        iface=iface,
        prn=process_packet,
        store=False
    )

    return captured_packets