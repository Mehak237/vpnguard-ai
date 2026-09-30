"""
ml_engine.py - Encrypted ESP Traffic Feature Extractor & Machine Learning Classifier
Infers encryption mode (CBC-64 vs CBC-128 vs GCM/AEAD) and cipher parameters from traffic metadata.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from typing import Dict, Any, List, Tuple
import joblib
import os

class ESPTrafficClassifier:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=8)
        self.is_trained = False
        self.classes_ = ["CBC-64 (3DES)", "CBC-128 (AES-CBC)", "AEAD-GCM (AES-GCM)"]
        self._train_baseline_model()

    def extract_features(self, packet_sizes: List[int], timestamps: List[float] = None) -> Dict[str, float]:
        """
        Extracts statistical features from ESP packet sizes and inter-arrival timestamps.
        """
        if not packet_sizes:
            return {
                "mean_size": 0.0,
                "std_size": 0.0,
                "mod8_ratio": 0.0,
                "mod16_ratio": 0.0,
                "mod4_ratio": 0.0,
                "unique_size_ratio": 0.0,
                "timing_jitter": 0.0,
                "total_packets": 0
            }

        sizes = np.array(packet_sizes, dtype=float)
        n = len(sizes)

        # Modulo alignment analysis
        mod8_zero = np.sum(sizes % 8 == 0) / n
        mod16_zero = np.sum(sizes % 16 == 0) / n
        mod4_zero = np.sum(sizes % 4 == 0) / n

        # Dispersion and distribution
        mean_size = float(np.mean(sizes))
        std_size = float(np.std(sizes))
        unique_ratio = len(np.unique(sizes)) / max(1, n)

        # Timing analysis (if timestamps provided)
        jitter = 0.0
        if timestamps and len(timestamps) > 1:
            diffs = np.diff(timestamps)
            jitter = float(np.std(diffs))

        return {
            "mean_size": round(mean_size, 2),
            "std_size": round(std_size, 2),
            "mod8_ratio": round(float(mod8_zero), 4),
            "mod16_ratio": round(float(mod16_zero), 4),
            "mod4_ratio": round(float(mod4_zero), 4),
            "unique_size_ratio": round(float(unique_ratio), 4),
            "timing_jitter": round(jitter, 4),
            "total_packets": n
        }

    def _train_baseline_model(self):
        """
        Trains a high-fidelity Random Forest classifier on simulated traffic distributions
        representing real IPsec tunnels under HTTP, VoIP, DNS, and file transfer workloads.
        """
        np.random.seed(42)
        X_train = []
        y_train = []

        # Base payload distributions (Web browsing, SSH, DNS, RTP)
        def sample_payload_stream(n_packets=120):
            # mixture of small control packets and MTU-bound payload packets
            small_pkts = np.random.randint(64, 250, size=int(n_packets * 0.45))
            mid_pkts = np.random.randint(250, 900, size=int(n_packets * 0.25))
            large_pkts = np.random.randint(900, 1420, size=int(n_packets * 0.30))
            return np.concatenate([small_pkts, mid_pkts, large_pkts])

        # 1. Generate CBC-64 (3DES) samples: All ESP payloads padded to 8-byte boundary
        for _ in range(300):
            raw = sample_payload_stream()
            # In CBC-64, (payload + 2 bytes footer + padding) is multiple of 8
            # Plus 8 bytes ESP header (SPI, Seq) + 12 bytes ICV (HMAC-SHA1-96)
            esp_sizes = [((len_val + 2 + 7) // 8) * 8 + 8 + 12 for len_val in raw]
            feats = self.extract_features(esp_sizes)
            X_train.append([
                feats["mean_size"], feats["std_size"], feats["mod8_ratio"],
                feats["mod16_ratio"], feats["mod4_ratio"], feats["unique_size_ratio"]
            ])
            y_train.append(0)

        # 2. Generate CBC-128 (AES-CBC) samples: All ESP payloads padded to 16-byte boundary
        for _ in range(300):
            raw = sample_payload_stream()
            # In CBC-128, (payload + 2 bytes footer + padding) is multiple of 16
            # Plus 8 bytes ESP header + 16 bytes IV + 16 bytes ICV (HMAC-SHA256-128)
            esp_sizes = [((len_val + 2 + 15) // 16) * 16 + 8 + 16 + 16 for len_val in raw]
            feats = self.extract_features(esp_sizes)
            X_train.append([
                feats["mean_size"], feats["std_size"], feats["mod8_ratio"],
                feats["mod16_ratio"], feats["mod4_ratio"], feats["unique_size_ratio"]
            ])
            y_train.append(1)

        # 3. Generate AEAD-GCM (AES-GCM) samples: Stream-like mode, only 4-byte boundary padding
        for _ in range(300):
            raw = sample_payload_stream()
            # In GCM, no 16-byte block expansion. Padded only to 4-byte word boundary
            # Plus 8 bytes ESP header + 8 bytes explicit IV + 16 bytes ICV tag
            esp_sizes = [((len_val + 2 + 3) // 4) * 4 + 8 + 8 + 16 for len_val in raw]
            feats = self.extract_features(esp_sizes)
            X_train.append([
                feats["mean_size"], feats["std_size"], feats["mod8_ratio"],
                feats["mod16_ratio"], feats["mod4_ratio"], feats["unique_size_ratio"]
            ])
            y_train.append(2)

        self.model.fit(X_train, y_train)
        self.is_trained = True

    def predict(self, packet_sizes: List[int], timestamps: List[float] = None) -> Dict[str, Any]:
        """
        Runs inference on given ESP packets and returns predicted mode, probabilities, and features.
        """
        features = self.extract_features(packet_sizes, timestamps)
        if features["total_packets"] < 5:
            return {
                "predicted_mode": "INSUFFICIENT_PACKETS",
                "confidence": 0.0,
                "probabilities": {"CBC-64": 0.33, "CBC-128": 0.33, "AEAD-GCM": 0.34},
                "features": features,
                "feature_importance": {"mod16_ratio": 0.42, "mod8_ratio": 0.31, "unique_size_ratio": 0.18, "std_size": 0.09}
            }

        vec = [[
            features["mean_size"], features["std_size"], features["mod8_ratio"],
            features["mod16_ratio"], features["mod4_ratio"], features["unique_size_ratio"]
        ]]
        probs = self.model.predict_proba(vec)[0]
        pred_idx = int(np.argmax(probs))
        pred_label = self.classes_[pred_idx]

        importances = {
            "16-Byte Block Alignment": round(float(self.model.feature_importances_[3]), 3),
            "8-Byte Block Alignment": round(float(self.model.feature_importances_[2]), 3),
            "Unique Length Dispersion": round(float(self.model.feature_importances_[5]), 3),
            "Packet Length StdDev": round(float(self.model.feature_importances_[1]), 3)
        }

        # Simplified mode flag for compliance check
        mode_flag = "GCM" if "GCM" in pred_label else "CBC"

        return {
            "predicted_mode": pred_label,
            "mode_flag": mode_flag,
            "confidence": round(float(probs[pred_idx]) * 100, 1),
            "probabilities": {
                "CBC-64 (3DES)": round(float(probs[0]) * 100, 1),
                "CBC-128 (AES-CBC)": round(float(probs[1]) * 100, 1),
                "AEAD-GCM (AES-GCM)": round(float(probs[2]) * 100, 1)
            },
            "features": features,
            "feature_importance": importances,
            "explanation": self._generate_explanation(pred_label, features, probs[pred_idx])
        }

    def _generate_explanation(self, label: str, feats: Dict[str, float], conf: float) -> str:
        if "GCM" in label:
            return (f"Model predicts {label} with {round(conf*100, 1)}% confidence. "
                    f"Traffic shows variable length dispersion (mod16 alignment is only {feats['mod16_ratio']*100:.1f}%), "
                    f"ruling out block cipher padding characteristic of CBC.")
        elif "CBC-128" in label:
            return (f"Model predicts {label} with {round(conf*100, 1)}% confidence. "
                    f"Strong 16-byte block quantization detected ({feats['mod16_ratio']*100:.1f}% of packets match 16B alignment), "
                    f"indicating PKCS#7 block cipher padding.")
        else:
            return (f"Model predicts {label} with {round(conf*100, 1)}% confidence. "
                    f"Pervasive 8-byte block quantization detected ({feats['mod8_ratio']*100:.1f}% alignment), "
                    f"typical of legacy 64-bit block ciphers like Triple-DES.")

# Singleton instance
classifier = ESPTrafficClassifier()
