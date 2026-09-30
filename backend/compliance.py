"""
compliance.py - NIST SP 800-77 Rev. 1 & NSA CNSA 2.0 Compliance Engine
Evaluates IKE/ESP negotiation parameters and generates security scores, threat matrices, and remediations.
"""

from typing import Dict, Any, List

# Cryptographic evaluation policies
CIPHER_RATINGS = {
    "3DES": {"level": "CRITICAL", "penalty": 45, "cve": "CVE-2016-2183 (Sweet32)", "desc": "64-bit block cipher vulnerable to collision attacks after 32GB of data."},
    "DES": {"level": "CRITICAL", "penalty": 50, "cve": "Brute Force Insecure", "desc": "56-bit key length easily crackable in minutes."},
    "AES-CBC-128": {"level": "MEDIUM", "penalty": 15, "cve": "Padding Oracle Risks", "desc": "CBC mode lacks built-in AEAD integrity, susceptible to bit-flipping/oracle without strict HMAC."},
    "AES-CBC-256": {"level": "LOW", "penalty": 10, "cve": "Non-AEAD", "desc": "Strong key length, but non-AEAD cipher mode requires secondary HMAC."},
    "AES-GCM-128": {"level": "ACCEPTABLE", "penalty": 0, "cve": None, "desc": "AEAD authenticated encryption, high throughput, compliant with modern standards."},
    "AES-GCM-256": {"level": "RECOMMENDED", "penalty": -5, "cve": None, "desc": "NSA CNSA 2.0 approved, top-tier AEAD authenticated encryption."},
    "CHACHA20-POLY1305": {"level": "RECOMMENDED", "penalty": -5, "cve": None, "desc": "Modern AEAD stream cipher with robust resistance against timing attacks."}
}

DH_GROUP_RATINGS = {
    "Group 1": {"bits": 768, "level": "CRITICAL", "penalty": 40, "cve": "Logjam (CVE-2015-4000)", "desc": "768-bit MODP broken by academic clusters, zero forward security."},
    "Group 2": {"bits": 1024, "level": "CRITICAL", "penalty": 35, "cve": "Logjam (CVE-2015-4000)", "desc": "1024-bit MODP vulnerable to state-sponsored precomputation attacks. Deprecated by NIST."},
    "Group 5": {"bits": 1536, "level": "HIGH", "penalty": 25, "cve": "NIST Deprecated", "desc": "1536-bit MODP below 112-bit security threshold, discontinued by NIST SP 800-131A."},
    "Group 14": {"bits": 2048, "level": "MEDIUM", "penalty": 10, "cve": None, "desc": "2048-bit MODP minimum legacy standard. Provides 112-bit security strength."},
    "Group 19": {"bits": 256, "level": "RECOMMENDED", "penalty": 0, "cve": None, "desc": "256-bit ECP (NIST P-256). Provides 128-bit security, high performance."},
    "Group 20": {"bits": 384, "level": "RECOMMENDED", "penalty": -5, "cve": None, "desc": "384-bit ECP (NIST P-384). CNSA 2.0 compliant, high quantum resistance headroom."},
    "Group 21": {"bits": 521, "level": "RECOMMENDED", "penalty": -5, "cve": None, "desc": "521-bit ECP (NIST P-521). Top-tier cryptographic security."}
}

HASH_RATINGS = {
    "MD5": {"level": "CRITICAL", "penalty": 35, "cve": "MD5 Collisions (RFC 6151)", "desc": "Broken cryptanalytic collisions, forgeable authentication signatures."},
    "SHA1": {"level": "HIGH", "penalty": 25, "cve": "SHAttered (RFC 8598)", "desc": "Practical collision attacks demonstrated; forbidden in NIST SP 800-77r1."},
    "SHA2-256": {"level": "RECOMMENDED", "penalty": 0, "cve": None, "desc": "Standard 256-bit secure hash function."},
    "SHA2-384": {"level": "RECOMMENDED", "penalty": -2, "cve": None, "desc": "CNSA 2.0 compliant integrity hashing."},
    "SHA2-512": {"level": "RECOMMENDED", "penalty": -2, "cve": None, "desc": "CNSA 2.0 compliant high-assurance hashing."}
}

def evaluate_vpn_security(audit_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Computes overall risk score (0-100, where 100 is pristine security, 0 is fatally compromised),
    generates threat matrix, compliance checks, and strongSwan remediation.
    """
    base_score = 100
    threats: List[Dict[str, Any]] = []
    recommendations: List[str] = []

    ike_version = audit_data.get("ike_version", 2)
    cipher = audit_data.get("cipher", "AES-CBC-128").upper()
    dh_group = audit_data.get("dh_group", "Group 14")
    hash_algo = audit_data.get("hash_algo", "SHA2-256").upper()
    pfs_enabled = audit_data.get("pfs_enabled", False)
    inferred_esp_mode = audit_data.get("inferred_esp_mode", "CBC")

    # 1. Evaluate IKE Version
    if ike_version == 1:
        base_score -= 20
        threats.append({
            "category": "Protocol Deprecation",
            "severity": "HIGH",
            "name": "IKEv1 Protocol Active",
            "impact": "IKEv1 suffers from aggressive mode identity exposure, offline PSK dictionary attacks, and lacks native anti-DoS cookie mechanism.",
            "cve": "RFC 7296 Deprecation",
            "reference": "NIST SP 800-77 Rev. 1 Section 3.1"
        })
        recommendations.append("Migrate all tunnels from IKEv1 to IKEv2 (RFC 7296) to enable modern cookie exchanges and eliminate offline PSK dictionary cracking.")

    # 2. Evaluate Encryption Cipher
    matched_cipher_key = next((k for k in CIPHER_RATINGS if k in cipher), None)
    if matched_cipher_key:
        rating = CIPHER_RATINGS[matched_cipher_key]
        base_score -= rating["penalty"]
        if rating["level"] in ["CRITICAL", "HIGH", "MEDIUM"]:
            threats.append({
                "category": "Cryptographic Vulnerability",
                "severity": rating["level"],
                "name": f"Weak Cipher: {cipher}",
                "impact": rating["desc"],
                "cve": rating["cve"] or "Cryptographic Weakness",
                "reference": "NIST SP 800-77 Rev. 1 Section 3.2"
            })
            recommendations.append(f"Replace {cipher} with AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption (AEAD).")

    # 3. Evaluate Diffie-Hellman Group
    import re
    m = re.search(r"Group\s+(\d+)", dh_group, re.IGNORECASE)
    dh_norm = f"Group {m.group(1)}" if m else "Group 14"
    dh_rating = DH_GROUP_RATINGS.get(dh_norm, {"bits": 2048, "level": "MEDIUM", "penalty": 10, "cve": None, "desc": "Standard DH group."})
    base_score -= dh_rating["penalty"]
    if dh_rating["level"] in ["CRITICAL", "HIGH"]:
        threats.append({
            "category": "Key Exchange Weakness",
            "severity": dh_rating["level"],
            "name": f"Insecure Key Exchange: {dh_group} ({dh_rating['bits']}-bit)",
            "impact": dh_rating["desc"],
            "cve": dh_rating["cve"],
            "reference": "NIST SP 800-131A Rev. 2"
        })
        recommendations.append(f"Upgrade Diffie-Hellman exchange to Group 19 (ECP-256) or Group 20 (ECP-384) to eliminate Logjam vulnerability.")
    elif dh_norm == "Group 14":
        recommendations.append("Consider upgrading from Group 14 (MODP 2048) to Elliptic Curve Group 19 (ECP-256) for faster negotiation and higher security margin.")

    # 4. Evaluate Hash Algorithm (if applicable for non-AEAD)
    if "GCM" not in cipher:
        hash_norm = next((k for k in HASH_RATINGS if k in hash_algo), "SHA2-256")
        hash_rating = HASH_RATINGS[hash_norm]
        base_score -= hash_rating["penalty"]
        if hash_rating["level"] in ["CRITICAL", "HIGH"]:
            threats.append({
                "category": "Integrity Vulnerability",
                "severity": hash_rating["level"],
                "name": f"Deprecated Hash: {hash_algo}",
                "impact": hash_rating["desc"],
                "cve": hash_rating["cve"],
                "reference": "NIST SP 800-77 Rev. 1 Section 3.3"
            })
            recommendations.append(f"Deprecate {hash_algo} immediately and configure HMAC-SHA2-256 or adopt AEAD ciphers.")

    # 5. Evaluate Perfect Forward Secrecy (PFS)
    if not pfs_enabled:
        base_score -= 15
        threats.append({
            "category": "Forward Secrecy Absence",
            "severity": "HIGH",
            "name": "Perfect Forward Secrecy (PFS) Disabled",
            "impact": "Child SA keys are derived purely from master IKE SA keys without a fresh Diffie-Hellman exchange. If long-term private key is compromised, ALL past captured traffic can be decrypted retroactively.",
            "cve": "Lack of Ephemeral Rekeying",
            "reference": "NIST SP 800-77 Rev. 1 Section 3.4"
        })
        recommendations.append("Enforce Perfect Forward Secrecy (PFS) by configuring 'esp = ...-ecp256' in your IPsec child SA configuration.")

    # 6. ESP ML Inference Check
    if inferred_esp_mode == "CBC" and "GCM" in cipher:
        threats.append({
            "category": "Traffic Anomaly / Downgrade",
            "severity": "MEDIUM",
            "name": "Cipher Mode Mismatch Detected",
            "impact": "Handshake proposed AEAD GCM, but statistical analysis of ESP payload lengths detects 16-byte block alignment indicative of CBC fallback.",
            "cve": "Negotiation Drift / Anomaly",
            "reference": "Encrypted ESP ML Model"
        })
        base_score -= 10

    # Normalization
    final_score = max(5, min(100, base_score))

    if final_score >= 90:
        grade = "A+"
        posture = "Hardened / Zero-Trust Ready"
        compliance_nist = "COMPLIANT"
        compliance_cnsa = "COMPLIANT"
        badge_color = "#10b981"  # Emerald
    elif final_score >= 80:
        grade = "A"
        posture = "Secure / Modern Baseline"
        compliance_nist = "COMPLIANT"
        compliance_cnsa = "PARTIAL"
        badge_color = "#06b6d4"  # Cyan
    elif final_score >= 65:
        grade = "B"
        posture = "Acceptable with Weaknesses"
        compliance_nist = "PARTIAL"
        compliance_cnsa = "NON-COMPLIANT"
        badge_color = "#eab308"  # Yellow
    elif final_score >= 50:
        grade = "C"
        posture = "Elevated Risk Profile"
        compliance_nist = "NON-COMPLIANT"
        compliance_cnsa = "NON-COMPLIANT"
        badge_color = "#f97316"  # Orange
    elif final_score >= 35:
        grade = "D"
        posture = "High Risk of Interception"
        compliance_nist = "NON-COMPLIANT"
        compliance_cnsa = "NON-COMPLIANT"
        badge_color = "#ef4444"  # Red
    else:
        grade = "F"
        posture = "Fatally Compromised / Legacy"
        compliance_nist = "FAIL"
        compliance_cnsa = "FAIL"
        badge_color = "#dc2626"  # Dark Red

    # strongSwan Remediation Snippet
    remediation_config = f"""# strongSwan Hardened Configuration (/etc/ipsec.conf)
conn hardened-tunnel
    keyexchange = ikev2
    ike = aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256!
    esp = aes256gcm16-ecp384,aes256gcm16-ecp256!
    dpdaction = restart
    closeaction = restart
    auto = start
"""

    return {
        "score": final_score,
        "grade": grade,
        "posture": posture,
        "compliance_nist": compliance_nist,
        "compliance_cnsa": compliance_cnsa,
        "badge_color": badge_color,
        "threats": threats,
        "recommendations": recommendations,
        "remediation_config": remediation_config
    }
