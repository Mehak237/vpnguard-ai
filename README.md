# VPNGuard AI: Automated IPsec Security Auditing & Traffic ML

> **Autonomous Defensive Cybersecurity Platform**  
> Inspects IKE handshakes, classifies encrypted ESP traffic cipher modes via Machine Learning (CBC vs AEAD-GCM), and evaluates cryptographic posture against NIST SP 800-77 Rev. 1 & NSA CNSA 2.0.

---

## ⚡ Live Features

- **Automated Handshake Dissection:** Extracts IKEv1/v2 versions, SA proposals, Diffie-Hellman groups, and validates Perfect Forward Secrecy (PFS).
- **Encrypted ESP ML Inference:** Random Forest model detects 8-byte (3DES) vs 16-byte (AES-CBC) PKCS#7 block padding vs continuous AEAD-GCM dispersion without breaking encryption.
- **Risk & Threat Matrix:** Correlates findings to CVE-2016-2183 (Sweet32), CVE-2015-4000 (Logjam), RFC 8598 (SHA-1), and generates actionable strongSwan `/etc/ipsec.conf` remediation snippets.
- **Executive Audit Certificate:** One-click exportable compliance report.

---

## 🚀 Deployment

Designed for instant zero-config deployment on **[Vercel](https://vercel.com)**:
1. Import repository `Mehak237/vpnguard-ai` into Vercel.
2. Click **Deploy**.
3. Upload any `.pcap` or `.pcapng` capture file to audit security posture in real time.
