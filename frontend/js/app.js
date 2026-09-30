/**
 * app.js - VPNGuard AI Frontend Controller
 * Handles scenario switching, custom PCAP uploads, Canvas chart rendering, and audit report generation.
 */

let currentAuditData = null;

// Initialize on DOM ready
document.addEventListener("DOMContentLoaded", () => {
    initTabs();
    initDropzone();
    initScenarios();
    // Load default scenario (Legacy 3DES) to showcase threat detection immediately
    loadScenario("legacy");
});

// Tab switching logic
function initTabs() {
    const tabBtns = document.querySelectorAll(".tab-btn");
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const targetId = btn.getAttribute("data-tab");
            tabBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");

            document.querySelectorAll(".tab-pane").forEach(pane => {
                pane.classList.remove("active");
            });
            const targetPane = document.getElementById(targetId);
            if (targetPane) {
                targetPane.classList.add("active");
                if (targetId === "tab-ml" && currentAuditData) {
                    renderPacketHistogram(currentAuditData.dissection.esp_packet_sizes);
                }
            }
        });
    });
}

// Scenario buttons
function initScenarios() {
    const scenarioBtns = document.querySelectorAll(".scenario-btn");
    scenarioBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            scenarioBtns.forEach(b => b.classList.remove("active"));
            btn.classList.add("active");
            const scId = btn.getAttribute("data-scenario");
            loadScenario(scId);
        });
    });
}

// Fetch scenario analysis from backend
async function loadScenario(scenarioId) {
    showLoadingState(true);
    try {
        const response = await fetch(`/api/analyze/${scenarioId}`);
        if (!response.ok) {
            throw new Error(`Failed to load scenario: ${response.statusText}`);
        }
        const data = await response.json();
        currentAuditData = data;
        updateDashboard(data);
    } catch (err) {
        console.error("Scenario load error:", err);
        alert("Failed to load scenario audit. Ensure backend is running.");
    } finally {
        showLoadingState(false);
    }
}

// Dropzone & File Upload
function initDropzone() {
    const dropzone = document.getElementById("pcapDropzone");
    const fileInput = document.getElementById("pcapFileInput");

    dropzone.addEventListener("click", () => fileInput.click());

    fileInput.addEventListener("change", (e) => {
        if (e.target.files.length > 0) {
            uploadPcap(e.target.files[0]);
        }
    });

    ["dragenter", "dragover"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        }, false);
    });

    ["dragleave", "drop"].forEach(eventName => {
        dropzone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
        }, false);
    });

    dropzone.addEventListener("drop", (e) => {
        if (e.dataTransfer.files.length > 0) {
            uploadPcap(e.dataTransfer.files[0]);
        }
    });
}

async function uploadPcap(file) {
    showLoadingState(true);
    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch("/api/upload", {
            method: "POST",
            body: formData
        });
        if (!response.ok) {
            const errData = await response.json();
            throw new Error(errData.detail || "Upload error");
        }
        const data = await response.json();
        currentAuditData = data;

        // Deselect scenario buttons
        document.querySelectorAll(".scenario-btn").forEach(b => b.classList.remove("active"));
        updateDashboard(data);
    } catch (err) {
        console.error("Upload error:", err);
        alert(`PCAP Analysis Failed: ${err.message}`);
    } finally {
        showLoadingState(false);
    }
}

// Update DOM with audit results
function updateDashboard(data) {
    const comp = data.compliance;
    const ml = data.ml_inference;
    const diss = data.dissection;
    const scen = data.scenario;

    // 1. Top KPI Cards
    const scoreEl = document.getElementById("kpiScore");
    const gradeEl = document.getElementById("kpiGrade");
    const postureEl = document.getElementById("kpiPosture");

    scoreEl.innerText = `${comp.score}/100`;
    scoreEl.style.color = comp.badge_color;
    gradeEl.innerText = comp.grade;
    gradeEl.style.backgroundColor = `${comp.badge_color}25`;
    gradeEl.style.color = comp.badge_color;
    postureEl.innerText = comp.posture;

    // Handshake KPI
    document.getElementById("kpiIkeVer").innerText = `IKEv${diss.ike_version}`;
    document.getElementById("kpiPrimaryDh").innerText = diss.primary_dh.split(" ")[0] + " " + (diss.primary_dh.split(" ")[1] || "");
    const pfsBadge = document.getElementById("kpiPfsBadge");
    if (diss.pfs_enabled) {
        pfsBadge.innerText = "PFS Active";
        pfsBadge.className = "badge badge-pass";
    } else {
        pfsBadge.innerText = "No PFS";
        pfsBadge.className = "badge badge-critical";
    }

    // Inferred ESP ML Mode KPI
    const mlModeEl = document.getElementById("kpiMlMode");
    const mlConfEl = document.getElementById("kpiMlConf");
    mlModeEl.innerText = ml.predicted_mode;
    mlConfEl.innerText = `${ml.confidence}% Confidence`;
    if (ml.predicted_mode.includes("GCM")) {
        mlModeEl.style.color = "#10b981";
    } else if (ml.predicted_mode.includes("CBC-128")) {
        mlModeEl.style.color = "#f97316";
    } else {
        mlModeEl.style.color = "#ef4444";
    }

    // Compliance KPI
    const nistEl = document.getElementById("kpiNist");
    const cnsaEl = document.getElementById("kpiCnsa");
    nistEl.innerText = `NIST: ${comp.compliance_nist}`;
    nistEl.className = comp.compliance_nist === "COMPLIANT" ? "badge badge-pass" : "badge badge-critical";
    cnsaEl.innerText = `CNSA 2.0: ${comp.compliance_cnsa}`;
    cnsaEl.className = comp.compliance_cnsa === "COMPLIANT" ? "badge badge-pass" : "badge badge-critical";

    // 2. Handshake Tab
    renderHandshakeTimeline(diss.handshake_packets);
    renderTransformTable(diss, comp);

    // 3. ML Encrypted Traffic Tab
    renderMlPanel(ml, diss);

    // 4. Threat Matrix Tab
    renderThreatMatrix(comp.threats);

    // 5. Remediation Tab
    document.getElementById("remediationCode").innerText = comp.remediation_config;
    const recsList = document.getElementById("recsList");
    recsList.innerHTML = comp.recommendations.map(r => `<li>${r}</li>`).join("");

    // 6. Report Tab
    updateReportView(data);
}

function renderHandshakeTimeline(packets) {
    const container = document.getElementById("timelineContainer");
    if (!packets || packets.length === 0) {
        container.innerHTML = `<p style="color:var(--text-dim);font-size:0.85rem;">No IKE control packets found in this capture.</p>`;
        return;
    }

    container.innerHTML = packets.map(p => `
        <div class="packet-card">
            <div class="packet-flow">
                <span class="packet-pill">${p.version}</span>
                <div class="packet-info">
                    <h4>${p.exchange}</h4>
                    <p>${p.src} &rarr; ${p.dst} | Init SPI: ${p.initiator_spi.slice(0, 10)}... | Resp SPI: ${p.responder_spi.slice(0, 10)}...</p>
                </div>
            </div>
            <span class="packet-time">+${p.timestamp}s</span>
        </div>
    `).join("");
}

function renderTransformTable(diss, comp) {
    const tbody = document.getElementById("transformTableBody");
    tbody.innerHTML = `
        <tr>
            <td><strong>IKE Version</strong></td>
            <td>IKEv${diss.ike_version}</td>
            <td>${diss.ike_version === 2 ? '<span class="badge badge-pass">RFC 7296 (Modern)</span>' : '<span class="badge badge-critical">RFC 2409 (Deprecated)</span>'}</td>
        </tr>
        <tr>
            <td><strong>Negotiated Cipher</strong></td>
            <td>${diss.primary_cipher}</td>
            <td>${diss.primary_cipher.includes('GCM') ? '<span class="badge badge-pass">AEAD Authenticated</span>' : (diss.primary_cipher.includes('3DES') ? '<span class="badge badge-critical">Sweet32 Vulnerable</span>' : '<span class="badge badge-medium">Legacy CBC Block</span>')}</td>
        </tr>
        <tr>
            <td><strong>Diffie-Hellman Group</strong></td>
            <td>${diss.primary_dh}</td>
            <td>${diss.primary_dh.includes('Group 19') || diss.primary_dh.includes('Group 20') ? '<span class="badge badge-pass">Elliptic Curve (Secure)</span>' : (diss.primary_dh.includes('Group 14') ? '<span class="badge badge-medium">MODP 2048 (Baseline)</span>' : '<span class="badge badge-critical">Logjam Vulnerable</span>')}</td>
        </tr>
        <tr>
            <td><strong>Integrity / PRF</strong></td>
            <td>${diss.primary_hash}</td>
            <td>${diss.primary_hash.includes('SHA2') ? '<span class="badge badge-pass">SHA-256+ Standard</span>' : '<span class="badge badge-critical">Collision Risk (SHA-1/MD5)</span>'}</td>
        </tr>
        <tr>
            <td><strong>Perfect Forward Secrecy</strong></td>
            <td>${diss.pfs_enabled ? 'Enforced in Child SA' : 'Disabled (Key Re-use)'}</td>
            <td>${diss.pfs_enabled ? '<span class="badge badge-pass">PFS Active</span>' : '<span class="badge badge-critical">Past Traffic Decryptable</span>'}</td>
        </tr>
    `;
}

function renderMlPanel(ml, diss) {
    const f = ml.features;
    document.getElementById("mlMod8Val").innerText = `${(f.mod8_ratio * 100).toFixed(1)}%`;
    document.getElementById("mlMod8Fill").style.width = `${f.mod8_ratio * 100}%`;

    document.getElementById("mlMod16Val").innerText = `${(f.mod16_ratio * 100).toFixed(1)}%`;
    document.getElementById("mlMod16Fill").style.width = `${f.mod16_ratio * 100}%`;

    document.getElementById("mlMod4Val").innerText = `${(f.mod4_ratio * 100).toFixed(1)}%`;
    document.getElementById("mlMod4Fill").style.width = `${f.mod4_ratio * 100}%`;

    document.getElementById("mlExplanation").innerText = ml.explanation;
    document.getElementById("mlTotalEspPkts").innerText = `${diss.esp_packets_count} ESP Packets Analyzed`;

    // Probability meters
    const probs = ml.probabilities;
    document.getElementById("probCbc64").innerText = `${probs['CBC-64 (3DES)']}%`;
    document.getElementById("probCbc64Fill").style.width = `${probs['CBC-64 (3DES)']}%`;

    document.getElementById("probCbc128").innerText = `${probs['CBC-128 (AES-CBC)']}%`;
    document.getElementById("probCbc128Fill").style.width = `${probs['CBC-128 (AES-CBC)']}%`;

    document.getElementById("probGcm").innerText = `${probs['AEAD-GCM (AES-GCM)']}%`;
    document.getElementById("probGcmFill").style.width = `${probs['AEAD-GCM (AES-GCM)']}%`;

    renderPacketHistogram(diss.esp_packet_sizes);
}

// Canvas Packet Size Distribution Histogram
function renderPacketHistogram(sizes) {
    const canvas = document.getElementById("packetHistogramCanvas");
    if (!canvas || !sizes || sizes.length === 0) return;

    const ctx = canvas.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.getBoundingClientRect();
    canvas.width = rect.width * dpr;
    canvas.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    ctx.clearRect(0, 0, w, h);

    // Compute bins
    const minSize = 50;
    const maxSize = 1500;
    const numBins = 24;
    const binWidth = (maxSize - minSize) / numBins;
    const bins = new Array(numBins).fill(0);

    sizes.forEach(s => {
        const idx = Math.min(numBins - 1, Math.max(0, Math.floor((s - minSize) / binWidth)));
        bins[idx]++;
    });

    const maxCount = Math.max(...bins, 1);
    const barW = (w - 40) / numBins;

    // Draw grid lines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.06)";
    ctx.lineWidth = 1;
    for (let i = 1; i <= 3; i++) {
        const y = h - 25 - (i / 4) * (h - 40);
        ctx.beginPath();
        ctx.moveTo(25, y);
        ctx.lineTo(w - 15, y);
        ctx.stroke();
    }

    // Draw bars
    bins.forEach((count, i) => {
        const barH = (count / maxCount) * (h - 55);
        const x = 30 + i * barW;
        const y = h - 25 - barH;

        // Gradient
        const grad = ctx.createLinearGradient(0, y, 0, h - 25);
        grad.addColorStop(0, "#06b6d4");
        grad.addColorStop(1, "rgba(6, 182, 212, 0.2)");

        ctx.fillStyle = grad;
        ctx.fillRect(x + 2, y, barW - 4, barH);

        // Border
        ctx.strokeStyle = "#38bdf8";
        ctx.strokeRect(x + 2, y, barW - 4, barH);
    });

    // Draw axes labels
    ctx.fillStyle = "#64748b";
    ctx.font = "10px Inter, sans-serif";
    ctx.fillText("64B", 25, h - 8);
    ctx.fillText("MTU (1420B)", w - 75, h - 8);
    ctx.fillText("Frequency", 5, 15);
}

function renderThreatMatrix(threats) {
    const container = document.getElementById("threatsContainer");
    if (!threats || threats.length === 0) {
        container.innerHTML = `
            <div style="background:rgba(16,185,129,0.08);border:1px solid rgba(16,185,129,0.25);border-radius:var(--radius-md);padding:1.5rem;text-align:center;">
                <h4 style="color:#10b981;font-size:1.1rem;margin-bottom:0.25rem;">Zero Vulnerabilities Detected</h4>
                <p style="color:var(--text-muted);font-size:0.85rem;">This tunnel configuration satisfies NIST SP 800-77 Rev. 1 and NSA CNSA 2.0 cryptographic mandates.</p>
            </div>
        `;
        return;
    }

    container.innerHTML = threats.map(t => `
        <div class="threat-card" style="border-left-color:${t.severity === 'CRITICAL' ? '#ef4444' : (t.severity === 'HIGH' ? '#f97316' : '#eab308')};">
            <div class="threat-top">
                <h4>${t.name}</h4>
                <span class="badge ${t.severity === 'CRITICAL' ? 'badge-critical' : (t.severity === 'HIGH' ? 'badge-high' : 'badge-medium')}">${t.severity}</span>
            </div>
            <p class="threat-desc">${t.impact}</p>
            <div class="threat-meta">
                <span><strong>CVE/RFC:</strong> ${t.cve}</span>
                <span><strong>Policy:</strong> ${t.reference}</span>
            </div>
        </div>
    `).join("");
}

function updateReportView(data) {
    document.getElementById("reportTimestamp").innerText = new Date().toLocaleString();
    document.getElementById("reportScenarioName").innerText = data.scenario.title;
    document.getElementById("reportScore").innerText = `${data.compliance.score}/100 (${data.compliance.grade})`;
    document.getElementById("reportPosture").innerText = data.compliance.posture;
    document.getElementById("reportNist").innerText = data.compliance.compliance_nist;
    document.getElementById("reportCnsa").innerText = data.compliance.compliance_cnsa;
}

function showLoadingState(isLoading) {
    const overlay = document.getElementById("loadingOverlay");
    if (overlay) {
        overlay.style.display = isLoading ? "flex" : "none";
    }
}

// Print / PDF Export
window.printReport = function() {
    window.print();
};
