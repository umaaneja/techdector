# app/crawler.py
import asyncio
import httpx
from typing import Optional
from urllib.parse import urlparse
from asyncio import Queue
from datetime import datetime
from .utils import load_fingerprints

HEADERS = {
    "User-Agent": "TechFinder/0.1 (+https://yourdomain.example)"
}

class Crawler:
    def __init__(self, concurrency: int = 8, timeout: int = 20, trust_env: bool = True):
        self.concurrency = concurrency
        self.timeout = timeout
        self.trust_env = trust_env
        self.queue: Queue = Queue()
        self.client = httpx.AsyncClient(http2=True, headers=HEADERS, timeout=timeout, follow_redirects=True)

    async def close(self):
        await self.client.aclose()

    def enqueue(self, url: str):
        self.queue.put_nowait(url)

    async def worker(self, handler):
        while True:
            url = await self.queue.get()
            try:
                result = await self.fetch(url)
                # handler is a coroutine that accepts (url, response, timestamp)
                await handler(url, result)
            except Exception as e:
                print("Crawler fetch error:", url, e)
            finally:
                self.queue.task_done()

    async def fetch(self, url: str):
        # polite: simple host-level delay could be added (per-host semaphores)
        resp = await self.client.get(url)
        timestamp = datetime.utcnow().isoformat()
        return {"status_code": resp.status_code, "text": resp.text, "headers": dict(resp.headers), "url": str(resp.url), "timestamp": timestamp}

    async def run(self, handler, initial_urls):
        for u in initial_urls:
            self.enqueue(u)
        workers = [asyncio.create_task(self.worker(handler)) for _ in range(self.concurrency)]
        await self.queue.join()
        for w in workers:
            w.cancel()
