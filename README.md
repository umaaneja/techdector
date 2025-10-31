TechFinder — proof-of-concept

Quickstart (local):
1. python -m venv .venv && source .venv/bin/activate
2. pip install -r requirements.txt
3. playwright install chromium
4. uvicorn app.main:app --reload

Example:
POST http://127.0.0.1:8000/lookup
Body:
{
  "url":"https://example.com",
  "run_dynamic": true
}

Bulk:
POST http://127.0.0.1:8000/bulk
Body: ["https://example.com","https://example.org"]

Notes:
- fingerprints.json is minimal. Replace or extend with Wappalyzer fingerprint DB (convert into matchers types used here).
- Add robots.txt honor by checking robotsparser before enqueueing fetches.
- Add per-host semaphore/ratelimit to be polite.
- For GeoIP/ASN, provide local MaxMind DB & use geoip2; ipwhois used for RDAP lookups.
- For production, run Playwright dynamic checks selectively (only when static results are inconclusive) and behind a worker queue.
- Add authentication/rate limits on the API and access control for storing/indexing outputs (fingerprinting info can be sensitive).
