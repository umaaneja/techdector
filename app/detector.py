# app/detector.py
import re
from bs4 import BeautifulSoup
from collections import defaultdict
from pathlib import Path
from .utils import load_fingerprints

class StaticDetector:
    def __init__(self, fingerprints_path=None):
        self.db = load_fingerprints(fingerprints_path)
        self.tech = self.db.get("tech", [])

    def collect_static(self, resp):
        evid = defaultdict(list)
        text = resp.get("text","") or ""
        headers = "\n".join(f"{k}: {v}" for k,v in resp.get("headers",{}).items())
        evid['html'] = text
        evid['headers'] = headers

        soup = BeautifulSoup(text, "html.parser")
        # script srcs
        for s in soup.find_all("script"):
            if s.get("src"):
                evid['script_src'].append(s.get("src"))
            elif s.string:
                evid['inline_js'].append(s.string[:2000])
        # meta tags
        for m in soup.find_all("meta"):
            attrs = " ".join([f'{k}=\"{v}\"' for k,v in m.attrs.items()])
            evid['meta'].append(attrs)
        # links
        for l in soup.find_all("link"):
            if l.get("href"):
                evid['links'].append(l.get("href"))
        # cookies - best-effort (Set-Cookie)
        cookies = resp.get("headers",{}).get("set-cookie","") or resp.get("headers",{}).get("Set-Cookie","")
        evid['cookies'].append(cookies)
        return evid

    def match(self, evidence):
        results = []
        html = evidence.get('html',"")
        headers = evidence.get('headers',"")
        scripts = " ".join(evidence.get('script_src',[]))
        metas = " ".join(evidence.get('meta',[]))
        cookies = " ".join(evidence.get('cookies',[]))

        for t in self.tech:
            name = t['name']
            weight = t.get('weight',1.0)
            matches = []
            score = 0.0
            for m in t.get('matchers',[]):
                typ = m['type']
                pat = m['pattern']
                try:
                    rx = re.compile(pat, re.IGNORECASE)
                except re.error:
                    continue
                if typ == "html_regex" and rx.search(html):
                    matches.append(f"html:{pat}")
                    score += 1.0
                elif typ == "header_regex" and rx.search(headers):
                    matches.append(f"header:{pat}")
                    score += 0.6
                elif typ == "script_src_regex" and rx.search(scripts):
                    matches.append(f"script_src:{pat}")
                    score += 0.9
                elif typ == "meta_regex" and rx.search(metas):
                    matches.append(f"meta:{pat}")
                    score += 0.8
                elif typ == "cookie_regex" and rx.search(cookies):
                    matches.append(f"cookie:{pat}")
                    score += 0.8
                elif typ == "link_regex" and rx.search(" ".join(evidence.get('links',[]))):
                    matches.append(f"link:{pat}")
                    score += 0.4
                # global_js_regex are for dynamic detection only (skipped here)
            if matches:
                confidence = min(0.99, 1 - (0.5 ** (score * weight)))
                results.append({"name": name, "confidence": round(confidence,3), "evidence": matches})
        return results
