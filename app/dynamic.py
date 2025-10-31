# app/dynamic.py
import asyncio
from playwright.async_api import async_playwright
import re

class DynamicDetector:
    def __init__(self, headless: bool = True, timeout: int = 30000):
        self.headless = headless
        self.timeout = timeout

    async def analyze(self, url, matchers):
        """
        matchers: list of fingerprint dicts (only those that include global_js or dynamic patterns)
        returns list of detections
        """
        results = []
        async with async_playwright() as pw:
            browser = await pw.chromium.launch(headless=self.headless)
            page = await browser.new_page()
            await page.goto(url, timeout=self.timeout)
            # get window keys (limited)
            globals_list = await page.evaluate("() => Object.keys(window).slice(0,500)")
            globals_text = " ".join(globals_list)
            # get scripts loaded after runtime
            scripts = await page.eval_on_selector_all("script[src]", "els => els.map(e => e.src)")
            scripts_text = " ".join(scripts)
            # optional: collect network requests
            await asyncio.sleep(0.5)  # let more network requests settle
            # match
            for fp in matchers:
                name = fp['name']
                matches = []
                score = 0.0
                for m in fp.get('matchers',[]):
                    typ = m['type']; pat = m['pattern']
                    if typ == "global_js_regex":
                        try:
                            if re.search(pat, globals_text, re.I):
                                matches.append(f"global_js:{pat}")
                                score += 1.2
                        except re.error:
                            continue
                    if typ == "script_src_regex":
                        try:
                            if re.search(pat, scripts_text, re.I):
                                matches.append(f"script_src:{pat}")
                                score += 0.9
                        except re.error:
                            continue
                if matches:
                    confidence = min(0.99, 1 - (0.5 ** score))
                    results.append({"name": name, "confidence": round(confidence,3), "evidence": matches})
            await browser.close()
        return results
