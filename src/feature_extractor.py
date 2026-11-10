from scapy.all import IP, TCP, UDP, ICMP


def extract_packet_features(packet):
    """
    Extrait les caractéristiques d'un paquet réseau.
    """

    features = {
        "packet_size": len(packet),
        "src_ip": None,
        "dst_ip": None,
        "protocol": "OTHER",
    }

    if IP in packet:

        features["src_ip"] = packet[IP].src
        features["dst_ip"] = packet[IP].dst

        if TCP in packet:
            features["protocol"] = "TCP"

        elif UDP in packet:
            features["protocol"] = "UDP"

        elif ICMP in packet:
            features["protocol"] = "ICMP"

    return features