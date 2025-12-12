#!/usr/bin/env python3
import os
import re

BASE_DIR = "/media/sf_vremen/hackerone/Bybit Fintech Ltd/recon_data"

# Источники потенциально пользовательских данных
SOURCE_PATTERNS = [
    r"window\.location",
    r"location\.href",
    r"location\.search",
    r"location\.hash",
    r"document\.URL",
    r"new URL\(",
    r"URLSearchParams\(",
    r"searchParams\.get\(",
    r"localStorage\.getItem\(",
    r"sessionStorage\.getItem\(",
    r"document\.cookie",
    r"postMessage",
    r"tmp_token",
]

# Опасные sink-и
SINK_PATTERNS = [
    r"innerHTML\s*\+=?",
    r"outerHTML\s*\+=?",
    r"dangerouslySetInnerHTML",
    r"eval\s*\(",
    r"Function\s*\(",
    r"setTimeout\s*\(\s*['\"]",
    r"setInterval\s*\(\s*['\"]",
    r"location\.href\s*=",
    r"\.href\s*=",
    r"\.src\s*=",
    r"document\.write\(",
]

print("="*80)
print("DEEP JS DATA FLOW ANALYSIS (STATIC)")
print("Base dir:", BASE_DIR)
print("="*80)

js_files = [f for f in os.listdir(BASE_DIR) if f.endswith('.js')]

print(f"Found {len(js_files)} JS files to analyze\n")

# Вспомогательная функция

def find_all(patterns, text):
    results = []
    for p in patterns:
        for m in re.finditer(p, text):
            results.append((p, m.start(), m.end()))
    return results

suspicious_flows = []

for fname in js_files:
    path = os.path.join(BASE_DIR, fname)
    try:
        with open(path, 'r', errors='ignore') as f:
            content = f.read()
    except Exception as e:
        continue

    sources = find_all(SOURCE_PATTERNS, content)
    sinks = find_all(SINK_PATTERNS, content)

    if not sources or not sinks:
        continue

    print("\n" + "-"*80)
    print(f"FILE: {fname}")
    print(f"  Sources: {len(sources)}, Sinks: {len(sinks)}")

    # Попробуем найти простые связи: var X = <source> ... потом X возле sink
    # Шаг 1: вытащим переменные, которым присваивается результат источника
    var_candidates = set()
    for pattern, start, end in sources:
        # Возьмём небольшой контекст до паттерна
        ctx_start = max(0, start - 80)
        ctx = content[ctx_start:start]
        # Ищем что-то вроде "var x =" или "const x =" или "x="
        m = re.search(r"(var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*$", ctx)
        if m:
            var_name = m.group(2)
            var_candidates.add(var_name)
        else:
            # fallback: взять последнее слово перед '=' перед паттерном
            m2 = re.search(r"([a-zA-Z0-9_$]+)\s*=\s*$", ctx)
            if m2:
                var_candidates.add(m2.group(1))

    if not var_candidates:
        # Просто вывести источники и sink-и для ручного анализа
        print("  No clear var assignments from sources. Showing raw context.")
        for pattern, start, end in sources[:3]:
            ctx_start = max(0, start - 120)
            ctx_end = min(len(content), end + 120)
            print(f"\n  SOURCE [{pattern}]:\n  ...{content[ctx_start:ctx_end]}...")
        for pattern, start, end in sinks[:3]:
            ctx_start = max(0, start - 120)
            ctx_end = min(len(content), end + 120)
            print(f"\n  SINK [{pattern}]:\n  ...{content[ctx_start:ctx_end]}...")
        continue

    print(f"  Candidate vars from sources: {list(var_candidates)[:5]}")

    # Шаг 2: ищем эти переменные рядом с sink-ами
    for pattern, s_start, s_end in sinks:
        ctx_start = max(0, s_start - 200)
        ctx_end = min(len(content), s_end + 200)
        snippet = content[ctx_start:ctx_end]

        for var in var_candidates:
            if re.search(rf"\b{re.escape(var)}\b", snippet):
                print("\n  🚨 POSSIBLE FLOW:")
                print(f"    Source var: {var}")
                print(f"    Sink: {pattern}")
                print(f"    Context: ...{snippet[:300]}...")
                suspicious_flows.append((fname, var, pattern, snippet[:300]))

print("\n" + "="*80)
print("SUMMARY")
print("="*80)
print(f"Total suspicious flows found: {len(suspicious_flows)}")
if suspicious_flows:
    print("Top 5 flows:")
    for item in suspicious_flows[:5]:
        fname, var, pattern, snippet = item
        print("\nFILE:", fname)
        print("  VAR:", var)
        print("  SINK:", pattern)
        print("  SNIPPET:", snippet)
