# VPNGuard AI - strongSwan Docker Lab Guide

This lab allows you to run real containerized IPsec tunnels and capture traffic live for VPNGuard AI.

---

### Benchmark Configurations Included:

#### 1. Config A: Legacy & Vulnerable (3DES-CBC, DH Group 2, IKEv1, No PFS)
```ini
conn legacy-tunnel
    keyexchange=ikev1
    ike=3des-sha1-modp1024!
    esp=3des-sha1!
    left=198.51.100.1
    right=198.51.100.10
    authby=secret
    auto=start
```

#### 2. Config B: Flawed Enterprise (AES-128-CBC, SHA2-256, DH Group 14, No PFS)
```ini
conn enterprise-tunnel
    keyexchange=ikev2
    ike=aes128-sha256-modp2048!
    esp=aes128-sha256!
    left=198.51.100.1
    right=198.51.100.10
    authby=secret
    auto=start
```

#### 3. Config C: Hardened Zero-Trust (AES-256-GCM, DH Group 19, IKEv2, PFS Active)
```ini
conn hardened-tunnel
    keyexchange=ikev2
    ike=aes256gcm16-prfsha384-ecp384,aes256gcm16-prfsha256-ecp256!
    esp=aes256gcm16-ecp384,aes256gcm16-ecp256!
    left=198.51.100.1
    right=198.51.100.10
    authby=secret
    auto=start
```

---

### How to Run & Capture Live PCAPs:

1. **Launch the containers**:
   ```bash
   docker compose up -d
   ```

2. **Capture traffic on the Docker network**:
   ```bash
   tcpdump -i br-<network-id> -w live_capture.pcap "udp port 500 or udp port 4500 or proto 50"
   ```

3. **Generate workload through tunnel**:
   ```bash
   docker exec -it vpnguard-client ping 198.51.100.1 -c 100
   ```

4. **Upload `live_capture.pcap` directly to the VPNGuard AI Web Dashboard!**
