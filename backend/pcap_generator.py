"""
pcap_generator.py - Synthesizes 4 Benchmark Test PCAPs for Manual Upload Testing
1. 01_Legacy_3DES_Insecure.pcap (IKEv1, 3DES-CBC, SHA-1, DH Group 2, No PFS)
2. 02_Enterprise_AES_CBC_NoPFS.pcap (IKEv2, AES-128-CBC, SHA2-256, DH Group 14, No PFS)
3. 03_Critical_DES_MD5_Broken.pcap (IKEv1, DES, MD5, DH Group 1, No PFS)
4. 04_Hardened_ZeroTrust_AES_GCM.pcap (IKEv2, AES-256-GCM, SHA2-384, DH Group 19, PFS Active)
"""

import os
import random
import time
import struct
import scapy.all as scapy
from scapy.layers.inet import IP, UDP

def build_ike_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                     ike_ver: int, exch_type: int, init_spi: bytes, resp_spi: bytes,
                     cipher_name: str, dh_group: str, hash_name: str, has_pfs: bool = False) -> scapy.Packet:
    next_p = 33 if ike_ver == 2 else 1
    ver_byte = (ike_ver << 4) & 0xF0
    flags = 0x08 if resp_spi == b"\x00"*8 else 0x20
    msg_id = 0

    sa_desc = f"PROPOSAL:ENC={cipher_name};DH={dh_group};AUTH={hash_name};PFS={'YES' if has_pfs else 'NO'}".encode("utf-8")
    sa_body = struct.pack("!BBH", 0, 0, len(sa_desc) + 4) + sa_desc

    total_len = 28 + len(sa_body)
    ike_hdr = struct.pack("!8s8sBBBBII", init_spi, resp_spi, next_p, ver_byte, exch_type, flags, msg_id, total_len)

    pkt = IP(src=src_ip, dst=dst_ip) / UDP(sport=sport, dport=dport) / scapy.Raw(load=ike_hdr + sa_body)
    return pkt

def generate_all_pcaps(dirs):
    random.seed(42)

    for target_dir in dirs:
        os.makedirs(target_dir, exist_ok=True)

        # -------------------------------------------------------------------------
        # File 1: Legacy 3DES Insecure
        # -------------------------------------------------------------------------
        pkts1 = []
        t0 = time.time() - 400
        init_spi = b"\x3d\x3e\x50\x01\x11\x22\x33\x44"
        resp_spi = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        p1 = build_ike_packet("192.168.1.10", "198.51.100.1", 500, 500, 1, 2, init_spi, resp_spi,
                              "3DES", "Group 2 (1024-bit MODP)", "SHA1", has_pfs=False)
        p1.time = t0
        pkts1.append(p1)

        resp_spi = b"\xfa\xeb\xdc\xcb\xba\xa9\x98\x87"
        p2 = build_ike_packet("198.51.100.1", "192.168.1.10", 500, 500, 1, 2, init_spi, resp_spi,
                              "3DES", "Group 2 (1024-bit MODP)", "SHA1", has_pfs=False)
        p2.time = t0 + 0.035
        pkts1.append(p2)

        curr_t = t0 + 0.12
        spi_val = b"\x0a\x1b\x2c\x3d"
        for i in range(85):
            raw_len = random.choice([60, 110, 245, 430, 680, 950, 1380])
            padded_esp = ((raw_len + 2 + 7) // 8) * 8 + 8 + 12
            esp_raw = spi_val + struct.pack("!I", i + 1) + os.urandom(padded_esp - 8)
            esp_pkt = IP(src="192.168.1.10", dst="198.51.100.1", proto=50) / scapy.Raw(load=esp_raw)
            esp_pkt.time = curr_t
            pkts1.append(esp_pkt)
            curr_t += random.uniform(0.003, 0.025)

        # -------------------------------------------------------------------------
        # File 2: Enterprise AES-CBC No PFS
        # -------------------------------------------------------------------------
        pkts2 = []
        t0 = time.time() - 300
        init_spi = b"\xa1\xb2\xc3\xd4\xe5\xf6\x07\x18"
        resp_spi = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        p3 = build_ike_packet("10.0.4.50", "203.0.113.88", 500, 500, 2, 34, init_spi, resp_spi,
                              "AES-CBC-128", "Group 14 (2048-bit MODP)", "SHA2-256", has_pfs=False)
        p3.time = t0
        pkts2.append(p3)

        resp_spi = b"\x81\x70\x6f\x5e\x4d\x3c\x2b\x1a"
        p4 = build_ike_packet("203.0.113.88", "10.0.4.50", 500, 500, 2, 34, init_spi, resp_spi,
                              "AES-CBC-128", "Group 14 (2048-bit MODP)", "SHA2-256", has_pfs=False)
        p4.time = t0 + 0.028
        pkts2.append(p4)

        curr_t = t0 + 0.09
        spi_val = b"\x4e\x5f\x6a\x7b"
        for i in range(95):
            raw_len = random.choice([64, 120, 280, 510, 780, 1020, 1420])
            padded_esp = ((raw_len + 2 + 15) // 16) * 16 + 8 + 16 + 16
            esp_raw = spi_val + struct.pack("!I", i + 1) + os.urandom(padded_esp - 8)
            esp_pkt = IP(src="10.0.4.50", dst="203.0.113.88", proto=50) / scapy.Raw(load=esp_raw)
            esp_pkt.time = curr_t
            pkts2.append(esp_pkt)
            curr_t += random.uniform(0.002, 0.020)

        # -------------------------------------------------------------------------
        # File 3: Critical Broken DES + MD5 + DH Group 1
        # -------------------------------------------------------------------------
        pkts3 = []
        t0 = time.time() - 200
        init_spi = b"\xde\xad\xbe\xef\x00\x11\x22\x33"
        resp_spi = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        p5 = build_ike_packet("192.168.100.5", "198.51.100.99", 500, 500, 1, 2, init_spi, resp_spi,
                              "DES", "Group 1 (768-bit MODP)", "MD5", has_pfs=False)
        p5.time = t0
        pkts3.append(p5)

        resp_spi = b"\xca\xfe\xba\xbe\x44\x55\x66\x77"
        p6 = build_ike_packet("198.51.100.99", "192.168.100.5", 500, 500, 1, 2, init_spi, resp_spi,
                              "DES", "Group 1 (768-bit MODP)", "MD5", has_pfs=False)
        p6.time = t0 + 0.040
        pkts3.append(p6)

        curr_t = t0 + 0.10
        spi_val = b"\xee\xff\x00\x11"
        for i in range(70):
            raw_len = random.choice([55, 95, 210, 390, 620, 890, 1200])
            padded_esp = ((raw_len + 2 + 7) // 8) * 8 + 8 + 12
            esp_raw = spi_val + struct.pack("!I", i + 1) + os.urandom(padded_esp - 8)
            esp_pkt = IP(src="192.168.100.5", dst="198.51.100.99", proto=50) / scapy.Raw(load=esp_raw)
            esp_pkt.time = curr_t
            pkts3.append(esp_pkt)
            curr_t += random.uniform(0.003, 0.024)

        # -------------------------------------------------------------------------
        # File 4: Hardened Zero-Trust AES-256-GCM + DH Group 19 + PFS
        # -------------------------------------------------------------------------
        pkts4 = []
        t0 = time.time() - 100
        init_spi = b"\x99\x88\x77\x66\x55\x44\x33\x22"
        resp_spi = b"\x00\x00\x00\x00\x00\x00\x00\x00"

        p7 = build_ike_packet("172.16.20.5", "198.51.100.254", 500, 500, 2, 34, init_spi, resp_spi,
                              "AES-GCM-256", "Group 19 (256-bit ECP)", "SHA2-384", has_pfs=True)
        p7.time = t0
        pkts4.append(p7)

        resp_spi = b"\x11\x22\x33\x44\x55\x66\x77\x88"
        p8 = build_ike_packet("198.51.100.254", "172.16.20.5", 500, 500, 2, 34, init_spi, resp_spi,
                              "AES-GCM-256", "Group 19 (256-bit ECP)", "SHA2-384", has_pfs=True)
        p8.time = t0 + 0.022
        pkts4.append(p8)

        # PFS Rekey
        p9 = build_ike_packet("172.16.20.5", "198.51.100.254", 4500, 4500, 2, 36, init_spi, resp_spi,
                              "AES-GCM-256", "Group 19 (256-bit ECP)", "SHA2-384", has_pfs=True)
        p9.time = t0 + 0.065
        pkts4.append(p9)

        curr_t = t0 + 0.11
        spi_val = b"\x88\x99\xaa\xbb"
        for i in range(110):
            raw_len = random.choice([75, 128, 295, 412, 615, 873, 1024, 1367, 1440])
            padded_esp = ((raw_len + 2 + 3) // 4) * 4 + 8 + 8 + 16
            esp_raw = spi_val + struct.pack("!I", i + 1) + os.urandom(padded_esp - 8)
            esp_pkt = IP(src="172.16.20.5", dst="198.51.100.254", proto=50) / scapy.Raw(load=esp_raw)
            esp_pkt.time = curr_t
            pkts4.append(esp_pkt)
            curr_t += random.uniform(0.002, 0.018)

        # Write files with both names
        scapy.wrpcap(os.path.join(target_dir, "01_Legacy_3DES_Insecure.pcap"), pkts1)
        scapy.wrpcap(os.path.join(target_dir, "02_Enterprise_AES_CBC_NoPFS.pcap"), pkts2)
        scapy.wrpcap(os.path.join(target_dir, "03_Critical_DES_MD5_Broken.pcap"), pkts3)
        scapy.wrpcap(os.path.join(target_dir, "04_Hardened_ZeroTrust_AES_GCM.pcap"), pkts4)

        # Also support legacy names for presets
        scapy.wrpcap(os.path.join(target_dir, "legacy_insecure_3des.pcap"), pkts1)
        scapy.wrpcap(os.path.join(target_dir, "vulnerable_enterprise_cbc.pcap"), pkts2)
        scapy.wrpcap(os.path.join(target_dir, "hardened_zero_trust_gcm.pcap"), pkts4)

        print(f"Generated 4 test PCAP captures in: {target_dir}")

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(base_dir, "..", "sample_pcaps")
    upload_test_dir = os.path.join(base_dir, "..", "test_upload_pcaps")
    generate_all_pcaps([sample_dir, upload_test_dir])
