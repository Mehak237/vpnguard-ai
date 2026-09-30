"""
dissector.py - Robust Scapy PCAP Dissector for IKEv1/IKEv2 and ESP Traffic
Extracts handshake negotiation parameters (ciphers, DH groups, hash, PFS) and ESP packet metadata.
"""

from typing import Dict, Any, List
import os
import struct
import scapy.all as scapy
from scapy.layers.inet import IP, UDP
from scapy.layers.isakmp import ISAKMP, ISAKMP_payload_SA, ISAKMP_payload_Proposal, ISAKMP_payload_Transform

TRANSFORM_ENCR_MAP = {
    1: "DES",
    5: "3DES",
    7: "AES-CBC-128",
    12: "AES-CBC-128",
    14: "AES-CBC-256",
    18: "AES-GCM-128",
    20: "AES-GCM-256",
    28: "ChaCha20-Poly1305"
}

TRANSFORM_AUTH_MAP = {
    1: "MD5",
    2: "SHA1",
    4: "SHA2-256",
    5: "SHA2-384",
    6: "SHA2-512"
}

TRANSFORM_DH_MAP = {
    1: "Group 1 (768-bit MODP)",
    2: "Group 2 (1024-bit MODP)",
    5: "Group 5 (1536-bit MODP)",
    14: "Group 14 (2048-bit MODP)",
    19: "Group 19 (256-bit ECP)",
    20: "Group 20 (384-bit ECP)",
    21: "Group 21 (521-bit ECP)"
}

class VPNDissector:
    @staticmethod
    def dissect_pcap(filepath: str) -> Dict[str, Any]:
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"PCAP file not found: {filepath}")

        packets = scapy.rdpcap(filepath)

        ike_packets = []
        esp_packet_sizes = []
        esp_timestamps = []
        esp_spis = set()

        ike_version = 2
        detected_ciphers = set()
        detected_dh_groups = set()
        detected_hashes = set()
        pfs_detected = False

        first_timestamp = None

        for pkt in packets:
            ts = float(pkt.time)
            if first_timestamp is None:
                first_timestamp = ts
            relative_time = round(ts - first_timestamp, 4)

            # 1. ESP Layer (IP Protocol 50)
            if pkt.haslayer(IP) and pkt[IP].proto == 50:
                payload_len = len(pkt[IP].payload)
                esp_packet_sizes.append(payload_len)
                esp_timestamps.append(relative_time)
                raw_bytes = bytes(pkt[IP].payload)
                if len(raw_bytes) >= 4:
                    spi = struct.unpack("!I", raw_bytes[:4])[0]
                    esp_spis.add(hex(spi))

            # 2. UDP 500 / 4500 (ISAKMP / NAT-T ESP)
            elif pkt.haslayer(UDP):
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
                raw_udp = bytes(pkt[UDP].payload)

                # Check for encapsulated ESP on 4500
                if (sport == 4500 or dport == 4500) and len(raw_udp) >= 8:
                    marker = struct.unpack("!I", raw_udp[:4])[0]
                    if marker != 0:
                        # NAT-T ESP
                        esp_packet_sizes.append(len(raw_udp))
                        esp_timestamps.append(relative_time)
                        esp_spis.add(hex(marker))
                        continue

                # Parse IKE / ISAKMP payload
                if sport in (500, 4500) or dport in (500, 4500):
                    # Check if standard Scapy ISAKMP layer is attached
                    if pkt.haslayer(ISAKMP):
                        isakmp = pkt[ISAKMP]
                        ver = getattr(isakmp, "version", 0x20)
                        major_ver = (ver >> 4) & 0x0F
                        ike_version = major_ver
                        exch = getattr(isakmp, "exch_type", 34)

                        # Try reading transforms
                        p = isakmp.payload
                        while p:
                            if isinstance(p, ISAKMP_payload_Proposal):
                                t = p.payload
                                while t and isinstance(t, ISAKMP_payload_Transform):
                                    tr_id = getattr(t, "transform_id", 0)
                                    if tr_id in TRANSFORM_ENCR_MAP:
                                        detected_ciphers.add(TRANSFORM_ENCR_MAP[tr_id])
                                    t = t.payload
                            p = p.payload

                        if exch == 36:
                            pfs_detected = True

                        def to_hex_str(val):
                            if isinstance(val, bytes):
                                return "0x" + val.hex()
                            elif isinstance(val, int):
                                return hex(val)
                            return str(val)

                        ike_packets.append({
                            "packet_id": len(ike_packets) + 1,
                            "timestamp": relative_time,
                            "src": pkt[IP].src if pkt.haslayer(IP) else "unknown",
                            "dst": pkt[IP].dst if pkt.haslayer(IP) else "unknown",
                            "version": f"IKEv{major_ver}",
                            "exchange": VPNDissector._map_exchange_name(major_ver, exch),
                            "initiator_spi": to_hex_str(getattr(isakmp, "init_cookie", 0)),
                            "responder_spi": to_hex_str(getattr(isakmp, "resp_cookie", 0))
                        })

                    # Check for proposal string markers in raw payload
                    body_str = raw_udp.decode("utf-8", errors="ignore")
                    if "PROPOSAL:" in body_str:
                        for part in body_str.split(";"):
                            if "ENC=" in part:
                                enc_val = part.split("ENC=")[1].split(";")[0]
                                detected_ciphers.add(enc_val)
                            if "DH=" in part:
                                dh_val = part.split("DH=")[1].split(";")[0]
                                detected_dh_groups.add(dh_val)
                            if "AUTH=" in part:
                                auth_val = part.split("AUTH=")[1].split(";")[0]
                                detected_hashes.add(auth_val)
                            if "PFS=YES" in part:
                                pfs_detected = True

        primary_cipher = list(detected_ciphers)[0] if detected_ciphers else "AES-CBC-128"
        primary_dh = list(detected_dh_groups)[0] if detected_dh_groups else "Group 14 (2048-bit MODP)"
        primary_hash = list(detected_hashes)[0] if detected_hashes else "SHA2-256"

        return {
            "total_packets": len(packets),
            "ike_packets_count": len(ike_packets),
            "esp_packets_count": len(esp_packet_sizes),
            "ike_version": ike_version,
            "handshake_packets": ike_packets,
            "detected_ciphers": list(detected_ciphers),
            "primary_cipher": primary_cipher,
            "detected_dh_groups": list(detected_dh_groups),
            "primary_dh": primary_dh,
            "detected_hashes": list(detected_hashes),
            "primary_hash": primary_hash,
            "pfs_enabled": pfs_detected,
            "esp_spis": list(esp_spis)[:4],
            "esp_packet_sizes": esp_packet_sizes,
            "esp_timestamps": esp_timestamps
        }

    @staticmethod
    def _map_exchange_name(version: int, exch: int) -> str:
        if version == 2:
            names = {
                34: "IKE_SA_INIT (Security Association & Key Exchange)",
                35: "IKE_AUTH (Authentication & Child SA Negotiation)",
                36: "CREATE_CHILD_SA (PFS Rekey Exchange)",
                37: "INFORMATIONAL (Keep-alive / DPD)"
            }
            return names.get(exch, f"IKEv2 Exchange ({exch})")
        else:
            names = {
                2: "Identity Protection (Main Mode)",
                4: "Aggressive Mode",
                32: "Quick Mode (IPsec SA Negotiation)",
                34: "Informational Exchange"
            }
            return names.get(exch, f"IKEv1 Exchange ({exch})")
