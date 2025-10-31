# app/main.py
import asyncio
from fastapi import FastAPI, BackgroundTasks, HTTPException
from pydantic import BaseModel
from .crawler import Crawler
from .detector import StaticDetector
from .dynamic import DynamicDetector
from .enrich import resolve_a, resolve_cname, get_tls_certificate, get_whois, get_ip_asn
from .storage import Storage
from datetime import datetime
import socket

app = FastAPI(title="TechFinder API")
crawler = Crawler(concurrency=6)
detector = StaticDetector()
dyn = DynamicDetector(headless=True)
storage = Storage(es_url=None)  # set ES url if you want

class LookupRequest(BaseModel):
    url: str
    run_dynamic: bool = False
    save_snapshot: bool = True

async def process_page(url, raw_resp):
    # static detection
    evidence = detector.collect_static(raw_resp)
    static_results = detector.match(evidence)

    # select fingerprints which require dynamic checks
    dynamic_candidates = []
    for t in detector.db.get("tech",[]):
        if any(m.get('type','').startswith("global_js") for m in t.get('matchers',[])):
            dynamic_candidates.append(t)

    dynamic_results = []
    if raw_resp and raw_resp.get("status_code",0) and raw_resp.get("status_code") < 500:
        # do not run dynamic here — run on-demand from API to save resources
        pass

    # enrich
    parsed = socket.getfqdn(url.split("//")[-1].split("/")[0])
    host = parsed
    ips = resolve_a(host)
    cnames = resolve_cname(host)
    tls = get_tls_certificate(host)
    whois = get_whois(host)
    asn = None
    if ips:
        try:
            asn = get_ip_asn(ips[0])
        except Exception:
            asn = None

    payload = {
        "url": url,
        "timestamp": datetime.utcnow().isoformat(),
        "static_results": static_results,
        "dynamic_results": dynamic_results,
        "evidence": {k: (v if len(str(v))<20000 else str(v)[:20000]) for k,v in evidence.items()},
        "enrichment": {"ips": ips, "cnames": cnames, "tls": tls, "whois": whois, "asn": asn},
        "raw_response": {"status_code": raw_resp.get("status_code"), "headers": raw_resp.get("headers")}
    }
    # save snapshot
    path = storage.save_snapshot(host, {**payload, "timestamp": payload["timestamp"]})
    payload["snapshot_path"] = path
    # optionally index to ES
    if storage.es:
        storage.index_es("techfinder", payload)
    return payload

@app.post("/lookup")
async def lookup(req: LookupRequest, background: BackgroundTasks):
    url = req.url
    # fetch synchronously using crawler client
    try:
        raw = await crawler.fetch(url)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    payload = await process_page(url, raw)

    # run dynamic detection if requested (in background to keep API responsive)
    if req.run_dynamic:
        async def run_dyn():
            # dynamic candidates from fingerprint DB
            dynamic_candidates = [t for t in detector.db.get("tech",[]) if any(m.get('type','').startswith("global_js") for m in t.get('matchers',[]))]
            dyn_res = await dyn.analyze(url, dynamic_candidates)
            payload['dynamic_results'] = dyn_res
            storage.save_snapshot(url.replace("://","_"), payload)
        background.add_task(run_dyn)

    return payload

@app.post("/bulk")
async def bulk(urls: list[str]):
    # simple: add all to crawler queue and process in main loop
    results = []
    async def handler(url, raw):
        pl = await process_page(url, raw)
        results.append(pl)
    await crawler.run(handler, urls)
    return {"processed": len(results), "results": results}

@app.on_event("shutdown")
async def shutdown_event():
    await crawler.close()
