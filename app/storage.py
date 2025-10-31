# app/storage.py
import json
from pathlib import Path
from elasticsearch import Elasticsearch, ElasticsearchException
import os

BASE = Path(__file__).resolve().parent.parent
SNAP_DIR = BASE / "snapshots"
SNAP_DIR.mkdir(exist_ok=True)

class Storage:
    def __init__(self, es_url=None):
        self.es = None
        if es_url:
            try:
                self.es = Elasticsearch(es_url)
            except ElasticsearchException:
                self.es = None

    def save_snapshot(self, domain, payload):
        fname = SNAP_DIR / f"{domain.replace('/', '_')}-{payload.get('timestamp','')}.json"
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return str(fname)

    def index_es(self, index_name, doc):
        if not self.es:
            return False
        try:
            self.es.index(index=index_name, document=doc)
            return True
        except Exception as e:
            print("ES index error:", e)
            return False
