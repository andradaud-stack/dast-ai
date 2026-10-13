# DAST-AI

Sistem orkestrasi DAST (*Dynamic Application Security Testing*) berbasis **OWASP ZAP** dan **LLM (Claude / Anthropic)** menggunakan FastAPI. Sistem ini memetakan endpoint target, melakukan active scanning terkontrol, membersihkan temuan dari data rahasia (*secret sanitization*), dan menggunakan LLM untuk melakukan triase temuan serta meminimalkan *false positive*.

---

## Fitur & Guardrails Keamanan
- **Target Allowlist**: Hanya target yang terdaftar di `ALLOWED_HOSTS` yang dapat dipindai.
- **Private IP Restriction**: Secara default (`REQUIRE_PRIVATE_IP=true`), scanning ke IP publik dicegah untuk menghindari pengujian tidak sengaja ke luar sistem lokal/staging.
- **Data Sanitization**: Token JWT, Bearer token, API key, password, dan email dibersihkan secara otomatis sebelum dikirim ke LLM.
- **Scan Throttling & Protected Scope**: Pengaturan rate limit scan dan pengecualian endpoint destruktif (seperti logout, delete, destroy, reset-db).

---

## Prasyarat
- Python 3.10+
- OWASP ZAP (versi 2.14+ disarankan)
- API Key Anthropic (untuk LLM triage)

---

## Panduan Menjalankan

### Opsi 1: Tanpa Docker (Virtualenv)

#### 1. Setup Virtual Environment & Dependencies
Buka terminal di root direktori proyek:

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt pytest
```

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt pytest
```

#### 2. Konfigurasi Environment File
Salin file template `.env.example` menjadi `.env`:
```bash
cp .env.example .env
```
Sesuaikan isi file `.env`:
```ini
ENVIRONMENT=staging
ALLOWED_HOSTS=["localhost", "127.0.0.1"]
REQUIRE_PRIVATE_IP=true
ZAP_URL=http://localhost:8090
ZAP_API_KEY=kunci-api-zap-anda
LLM_API_KEY=sk-ant-api-key-anda
LLM_MODEL=claude-sonnet-5-5
THREADS_PER_HOST=2
DELAY_MS=200
MAX_SPIDER_MINUTES=5
MAX_SCAN_MINUTES=20
```

#### 3. Jalankan OWASP ZAP di Host (Daemon Mode)
Jalankan daemon ZAP pada port 8090 dengan API key yang sesuai dengan konfigurasi di atas:

**Windows:**
```powershell
zap.bat -daemon -port 8090 -config api.key=kunci-api-zap-anda
```

**Linux / macOS:**
```bash
zap.sh -daemon -port 8090 -config api.key=kunci-api-zap-anda
```

#### 4. Jalankan FastAPI Orchestrator
Jalankan server uvicorn:
```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
Aplikasi akan aktif di `http://127.0.0.1:8000` dan dokumentasi API interaktif dapat diakses di `http://127.0.0.1:8000/docs`.

---

### Opsi 2: Menggunakan Docker Compose

Jika ingin menjalankan ZAP dan orchestrator di dalam container Docker:

1. Buat file `.env`:
   ```bash
   cp .env.example .env
   ```
   *(Pastikan `ZAP_URL=http://zap:8090` dan sesuaikan `ALLOWED_HOSTS` seperti `["host.docker.internal"]`)*

2. Jalankan docker compose:
   ```bash
   docker compose up --build
   ```

---

## Menjalankan Pengujian (Testing)

Proyek ini dilengkapi dengan unit test untuk memverifikasi guardrails keamanan dan fungsi pembersihan sanitasi data:

```bash
pytest -v
```

Semua pengujian berjalan secara offline dan mandiri tanpa mengirim traffic ke target eksternal.

---

## Cara Penggunaan API

### 1. Memulai Pemindaian Target (Trigger Scan)
Kirim permintaan POST ke endpoint `/scans` (target **harus** sudah terdaftar di `ALLOWED_HOSTS`):

```bash
curl -X POST http://localhost:8000/scans \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "http://127.0.0.1:3000",
    "framework": "node-express"
  }'
```

Response (HTTP 202 Accepted):
```json
{
  "scan_id": "a1b2c3d4e5f6",
  "state": "queued",
  "error": null,
  "report": null
}
```

### 2. Memeriksa Status & Hasil Laporan
Gunakan `scan_id` yang didapat untuk melihat status pemindaian (`scanning`, `analyzing`, atau `done`):

```bash
curl http://localhost:8000/scans/a1b2c3d4e5f6
```

Saat selesai (`done`), field `report` akan berisi total alert terdeteksi, ringkasan triase (*true positive*, *false positive*, *needs review*), serta detail setiap temuan beserta rekomendasi patch perbaikan kodenya.
