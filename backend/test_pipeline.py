import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from dissector import VPNDissector
from ml_engine import classifier
from compliance import evaluate_vpn_security

scenarios = [
    ("Legacy 3DES", "sample_pcaps/legacy_insecure_3des.pcap"),
    ("Enterprise CBC", "sample_pcaps/vulnerable_enterprise_cbc.pcap"),
    ("Zero-Trust GCM", "sample_pcaps/hardened_zero_trust_gcm.pcap")
]

base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

for label, rel_path in scenarios:
    full_path = os.path.join(base_dir, rel_path)
    res = VPNDissector.dissect_pcap(full_path)
    ml_res = classifier.predict(res["esp_packet_sizes"], res["esp_timestamps"])
    comp = evaluate_vpn_security({
        "ike_version": res["ike_version"],
        "cipher": res["primary_cipher"],
        "dh_group": res["primary_dh"],
        "hash_algo": res["primary_hash"],
        "pfs_enabled": res["pfs_enabled"],
        "inferred_esp_mode": ml_res["mode_flag"]
    })
    print(f"\n==========================================")
    print(f"Scenario: {label}")
    print(f"IKE: v{res['ike_version']} | Cipher: {res['primary_cipher']} | DH: {res['primary_dh']} | PFS: {res['pfs_enabled']}")
    print(f"Score: {comp['score']}/100 | Grade: {comp['grade']} | Posture: {comp['posture']}")
    print(f"Compliance: NIST={comp['compliance_nist']}, CNSA={comp['compliance_cnsa']}")
    print(f"ML Mode: {ml_res['predicted_mode']} ({ml_res['confidence']}%)")
    print(f"Threats ({len(comp['threats'])}):")
    for t in comp["threats"]:
        print(f"  - [{t['severity']}] {t['name']}")
