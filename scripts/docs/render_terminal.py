#!/usr/bin/env python3
"""Rendert eine Textausgabe als Terminalbild (PNG) für die README.

    python3 render_terminal.py ausgabe.txt bild.png "$ befehl"
"""
import html
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

src, dst, prompt = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
lines = src.read_text(encoding="utf-8").splitlines()


def color(line: str) -> str:
    e = html.escape(line)
    if line.startswith(("Ergebnis", "Zusammenfassung", "Aktion", "exit=")):
        return f'<span class="bold">{e}</span>'
    if "[FUND" in line or "Fund:" in line:
        return f'<span class="red">{e}</span>'
    if "NICHT VOLLST" in line or "Lücke" in line or "ACHTUNG" in line or "NUR FUNKTIONSTEST" in line:
        return f'<span class="amber">{e}</span>'
    if "[bereit]" in line or "OHNE FUND" in line:
        return f'<span class="green">{e}</span>'
    return e


body = "\n".join(color(l) for l in lines)
page = f"""<!doctype html><meta charset="utf-8"><style>
body{{margin:0;background:#0B1220}}
.win{{margin:24px;border-radius:10px;background:#0F1A2E;box-shadow:0 10px 30px #0008;overflow:hidden;width:1180px}}
.bar{{background:#16233D;padding:10px 14px;color:#94A7C6;font:13px "Segoe UI",sans-serif}}
.dot{{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:6px}}
pre{{margin:0;padding:16px 20px;color:#E8EEF8;font:14px/1.45 "DejaVu Sans Mono",Consolas,monospace;white-space:pre-wrap}}
.red{{color:#F87171}}.amber{{color:#FBBF24}}.green{{color:#34D399}}.bold{{font-weight:bold;color:#22D3EE}}.p{{color:#818CF8}}
</style><div class="win"><div class="bar"><span class="dot" style="background:#F87171"></span><span class="dot" style="background:#FBBF24"></span><span class="dot" style="background:#34D399"></span>
&nbsp;echter Lauf · AXSafe-CLI · Linux-Testumgebung · nur Testsignaturen</div><pre><span class="p">{html.escape(prompt)}</span>
{body}</pre></div>"""
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(viewport={"width": 1228, "height": 400}, device_scale_factor=1)
    pg.set_content(page)
    pg.locator(".win").screenshot(path=str(dst))
    b.close()
print("geschrieben:", dst)
