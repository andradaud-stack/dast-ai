# DAST-AI Enterprise Engine

Sistem orkestrasi DAST (*Dynamic Application Security Testing*) enterprise berbasis **OWASP ZAP** dan **LLM Triage (Anthropic / Claude)** menggunakan FastAPI. Sistem ini dirancang untuk memetakan permukaan serangan aplikasi web secara nyata, mengeksekusi pemeriksaan keamanan, memverifikasi bukti temuan, mendeteksi proteksi target (seperti Vercel Deployment Protection atau Auth Wall), dan menghasilkan laporan berbasis bukti (*evidence-based report*) yang dapat dipertanggungjawabkan.

---

## 🛡️ Filosofi Keamanan & Prinsip Kerja

1. **Kejujuran Pelaporan (No False Sense of Security)**:
   - Scan yang tidak menemukan kerentanan karena terhalang halaman login atau tantangan Vercel **TIDAK PERNAH** dilaporkan sebagai "Aman".
   - Status pemindaian dinyatakan secara transparan: `completed`, `inconclusive`, `blocked`, atau `failed`.
2. **Lapisan Triase AI Bersifat Advisory**:
   - Alert teknis asli dari OWASP ZAP selalu disimpan secara utuh (`technical_alerts`).
   - Analisis LLM tidak dapat menghapus temuan pemindai teknis, melainkan berfungsi sebagai asisten analis untuk mengevaluasi *false positive* dan menyusun rekomendasi patch remediasi.
3. **Guardrails & Proteksi SSRF**:
   - **Target Allowlist**: Hanya target yang diizinkan dalam `ALLOWED_HOSTS` yang dapat dipindai. Mendukung hostname eksak dan subdomain wildcard ketat (misal `*.staging.example.com`).
   - **Blokir Cloud Metadata & SSRF**: Alamat metadata cloud (`169.254.169.254`), link-local (`169.254.0.0/16`, `fe80::/10`), dan multicast diblokir secara mutlak.
   - **Strict Scope Regex**: ZAP Context dibatasi menggunakan regex berjangkar (*anchored regex*) untuk mencegah manipulasi subdomain mirip (contoh `http://target.com.attacker.com`).
4. **Proteksi Integritas Data Target**:
   - Endpoint destruktif (`logout`, `delete`, `destroy`, `reset-db`, `drop`, `truncate`, `purge`) secara otomatis dikecualikan dari crawling dan active testing.
   - Throttling bawaan (delay milidetik, thread per host, batasan durasi spider/ascan) untuk mencegah *Denial of Service* pada target.
5. **Sanitasi Rahasia (*Secret Sanitization*)**:
   - Token JWT, kredensial Basic/Bearer auth, API keys, password, email, private key, dan secret bypass Vercel disanitasi otomatis sebelum disimpan atau dikirim ke prompt LLM.

---

## 🎯 Mode Pemindaian (*Scan Modes*)

| Mode | Deskripsi | Perilaku | Kapan Digunakan |
| :--- | :--- | :--- | :--- |
| **`passive`** *(Default)* | Discovery & Analisis Pasif | Menjalankan ZAP Spider dan Passive Scanner. **Tidak mengirim payload serangan aktif**. | Pemindaian awal yang aman untuk produksi atau lingkungan yang sensitif. |
| **`active`** | Active Security Testing | Menjalankan Active Scanner ZAP terhadap target dengan rule terkontrol, throttling, dan exclusion list. | Pengujian kerentanan mendalam (SQLi, XSS, Path Traversal, dll.) pada staging. |
| **`full`** | Komprehensif | Menggabungkan Discovery Spidering, Passive Scan, dan Active Testing terkontrol. | Siklus pengujian keamanan menyeluruh pada pipeline CI/CD staging. |

---

## ⚙️ Variabel Lingkungan (`.env`)

Salin file `.env.example` ke `.env` dan sesuaikan nilainya:

```ini
ENVIRONMENT=staging
ALLOWED_HOSTS=["localhost","127.0.0.1","*.staging.example.com","*.dast-test.vercel.app"]
REQUIRE_PRIVATE_IP=true
ZAP_URL=http://localhost:8090
ZAP_API_KEY=kunci-api-zap-anda
LLM_API_KEY=sk-ant-api-key-anda
LLM_MODEL=claude-sonnet-5-5
THREADS_PER_HOST=2
DELAY_MS=200
MAX_SPIDER_MINUTES=5
MAX_SCAN_MINUTES=20

# Keamanan API & Kontrol Beban
API_AUTH_TOKEN=rahasia-bearer-token-untuk-api-orchestrator
DEFAULT_SCAN_MODE=passive
MAX_CONCURRENT_SCANS=2
PREFLIGHT_TIMEOUT_SECONDS=10

# Vercel Deployment Protection (Opsional)
VERCEL_PROTECTION_BYPASS_SECRET=secret-bypass-token-jika-ada
```

---

## 🚀 Panduan Menjalankan

### Menjalankan Tanpa Docker (Host / Virtualenv)

#### 1. Setup Virtual Environment
```powershell
# Windows
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```
```bash
# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

#### 2. Jalankan OWASP ZAP Daemon di Host
Pastikan OWASP ZAP berjalan sebagai daemon di port 8090:
```powershell
# Windows
zap.bat -daemon -port 8090 -config api.key=kunci-api-zap-anda
```
```bash
# Linux / macOS
zap.sh -daemon -port 8090 -config api.key=kunci-api-zap-anda
```

#### 3. Jalankan DAST-AI Orchestrator
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Aplikasi aktif di `http://127.0.0.1:8000` dengan Swagger UI di `http://127.0.0.1:8000/docs`.

---

## 📡 Penggunaan API

### 1. Health Check
```bash
curl http://localhost:8000/health
```

### 2. Memulai Pemindaian (`POST /scans`)
```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer rahasia-bearer-token-untuk-api-orchestrator" \
  -d '{
    "target_url": "http://127.0.0.1:3000",
    "scan_mode": "passive",
    "framework": "node-express"
  }'
```
Response `202 Accepted`:
```json
{
  "scan_id": "4a8c9f1e2b3d4e5f60718293a4b5c6d7",
  "state": "queued",
  "error": null,
  "report": null
}
```

### 3. Memeriksa Status & Laporan (`GET /scans/{scan_id}`)
```bash
curl http://localhost:8000/scans/4a8c9f1e2b3d4e5f60718293a4b5c6d7 \
  -H "Authorization: Bearer rahasia-bearer-token-untuk-api-orchestrator"
```

Laporan akhir berisi:
- **`verdict_status`**: `completed` | `inconclusive` | `blocked` | `failed`.
- **`target_health`**: status kode HTTP, diagnosa proteksi Vercel/auth wall, redirect scope status.
- **`coverage`**: daftar URL dan endpoint yang berhasil ditemukan, durasi per tahap, jumlah rule aktif yang dijalankan.
- **`technical_alerts`**: temuan teknis murni dari OWASP ZAP (CWE, WASC, pluginId, evidence, solution).
- **`ai_triage`**: analisis penilaian *true positive* / *false positive*, kutipan bukti, dan saran kode perbaikan.
- **`limitations`**: daftar batasan pemeriksaan yang belum dapat diuji secara jujur.

---

## 🧪 Menjalankan Test Suite

Proyek memiliki unit test komprehensif dan integration test berbasis live fixture app:

```bash
pytest -v
```

Cakupan pengujian (46 automated tests):
1. **Guardrails**: Scheme/port validation, userinfo blocking, allowlist enforcement, private IP checks, cloud metadata rejection, Vercel wildcard matching, scope regex anchoring, dan out-of-scope redirect detection.
2. **Sanitizer**: Redaksi JWT, Bearer token, basic auth, Vercel bypass header, URL query tokens, private keys, dan alert deduplication tanpa kehilangan variasi attack nyata.
3. **API Security**: Autentikasi Bearer token, pencegahan unauthorized access, format scan ID kriptografis (32 hex char), LRU store eviction, dan penolakan target liar pada level API.
4. **Lifecycle & Modes**: Pre-flight checks (accessible, Vercel challenge detection, HTTP auth, WAF 403, network error), ZAP connectivity verification, isolasi mode passive vs active.
5. **Integration & Destructive Control**: Uji coba live terhadap `tests/fixture_app.py` yang membuktikan tautan dapat ditemukan, missing security headers terdeteksi, dan endpoint kontrol destruktif (`/delete-account`) **tidak pernah tersentuh**.

---

## 🤖 Integrasi CI/CD (`scripts/ci_scan.py`)

Gunakan script CLI `scripts/ci_scan.py` untuk mengintegrasikan pemindaian pada pipeline CI/CD:

```bash
python scripts/ci_scan.py \
  --api-url http://localhost:8000 \
  --target-url http://staging.internal:3000 \
  --scan-mode passive \
  --token rahasia-bearer-token \
  --fail-on high \
  --output-json report.json
```

### Exit Codes CI/CD:
- **`0`**: Sukses (Scan selesai dan tidak ada alert melebihi ambang batas).
- **`1`**: Temuan Keamanan (Ditemukan kerentanan High/Critical).
- **`2`**: Inconclusive / Blocked (Target terhalang proteksi, Vercel challenge, atau login wall — **pipeline gagal karena keamanan belum terbukti**).
- **`3`**: Error Scanner / Timeout (Koneksi ke orchestrator atau ZAP gagal).
