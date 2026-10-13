# DAST-AI

1. `cp .env.example .env` lalu isi `ZAP_API_KEY`, `LLM_API_KEY`, dan `ALLOWED_HOSTS`.
2. `docker compose up --build`
3. Jalankan scan:
   curl -X POST localhost:8000/scans -H 'content-type: application/json' \
     -d '{"target_url":"http://host.docker.internal:3000","framework":"node-express"}'
4. Cek hasil: `curl localhost:8000/scans/<scan_id>`
