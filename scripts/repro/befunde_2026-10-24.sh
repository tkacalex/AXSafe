#!/usr/bin/env bash
# Reproduktion der unabhängig gemeldeten Befunde 1, 2, 3, 4 und 6 (Stand 491956e).
# Läuft gegen eine beliebige axsafe-Binärdatei und gibt beobachtete Werte aus,
# damit derselbe Ablauf vor und nach der Korrektur verglichen werden kann.
#
#   scripts/repro/befunde_2026-10-24.sh <pfad/zu/axsafe> <rules-ordner>
#
# Nur harmlose Testdaten; EICAR wird zur Laufzeit zusammengesetzt.
# Benötigt: python3, zip (Befund 3).
set -u
B="$1"; RULES="$2"
R="$(mktemp -d)"; trap 'rm -rf "$R"' EXIT
cd "$R"

cat > fake-clamscan-error <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then echo "ClamAV 0.0-test"; exit 0; fi
cat >/dev/null
if [ -f "$(dirname "$0")/probed" ]; then echo "LibClamAV Error: Testfehler" >&2; exit 2; fi
touch "$(dirname "$0")/probed"; echo "stdin: OK"; exit 0
EOF
cat > fake-clamscan-orphan <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then echo "ClamAV 0.0-test"; exit 0; fi
cat >/dev/null
( sleep 4 ) &
echo "stdin: OK"; exit 0
EOF
cat > fake-clamscan-orphan-scan <<'EOF'
#!/bin/sh
if [ "$1" = "--version" ]; then echo "ClamAV 0.0-test"; exit 0; fi
n=$(cat | wc -c)
if [ "$n" -eq 0 ]; then echo "stdin: OK"; exit 0; fi   # Funktionstest besteht
( sleep 4 ) &
echo "stdin: OK"; exit 0
EOF
chmod +x fake-clamscan-*
eicar() { python3 -c "import sys; open(sys.argv[1],'w').write('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\$'+'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*')" "$1"; }
show() { python3 - "$1" <<'PY'
import json, sys
try:
    r = json.load(open(sys.argv[1]))
except Exception as e:
    print("  Bericht nicht lesbar:", e); sys.exit()
keys = [k for k in ("schema", "outcome", "overall", "complete") if k in r]
print("  " + ", ".join(f"{k}={r[k]}" for k in keys))
s = r.get("summary", {})
print("  summary:", {k: v for k, v in s.items() if not isinstance(v, dict)})
for f in r.get("files", []):
    name = f["path"].split("/")[-1]
    det = f.get("detection", f.get("verdict"))
    gaps = [g.get("state") for g in f.get("gaps", [])]
    print(f"  {name}: detection/verdict={det} gaps={gaps}")
for g in r.get("job_gaps", []):
    print("  job_gap:", g.get("state"), g.get("reason"))
PY
}

echo "=== Befund 1: dieselbe Datei als Scanobjekt und --json-Ziel"
printf 'Wichtige Nutzdaten\n' > nutz.txt
echo "  vorher:  $(sha256sum nutz.txt | cut -c1-16)"
"$B" scan --no-clamav --rules "$RULES" --json nutz.txt nutz.txt >/dev/null 2>err.txt; echo "  exit=$?"
echo "  nachher: $(sha256sum nutz.txt | cut -c1-16)"; sed 's/^/  stderr: /' err.txt | head -2

echo "=== Befund 2: YARA-X Fund + ClamAV Fehler"
mkdir b2 && eicar b2/e.com
"$B" scan --rules "$RULES" --clamscan "$R/fake-clamscan-error" --json b2.json b2 >/dev/null; echo "  exit=$?"; show b2.json

echo "=== Befund 3: normales und passwortgeschütztes ZIP ohne ClamAV"
mkdir b3 && (cd b3 && echo hallo > a.txt && zip -q normal.zip a.txt && zip -q -P pw geheim.zip a.txt && rm a.txt)
"$B" scan --no-clamav --rules "$RULES" --json b3.json b3 >/dev/null; echo "  exit=$?"; show b3.json

echo "=== Befund 4: Budget 1 s, Elternprozess endet, Nachkomme hält Pipes 4 s"
rm -f probed; mkdir b4 && echo x > b4/x.txt
s=$(date +%s%N)
"$B" scan --rules "$RULES" --clamscan "$R/fake-clamscan-orphan" --timeout-secs 1 --json b4.json b4 >/dev/null; rc=$?
echo "  exit=$rc Dauer=$(( ($(date +%s%N) - s) / 1000000 )) ms"; show b4.json

echo "=== Befund 4b: wie 4, Nachkomme entsteht erst beim eigentlichen Scan"
mkdir b4b && echo x > b4b/x.txt
s=$(date +%s%N)
"$B" scan --rules "$RULES" --clamscan "$R/fake-clamscan-orphan-scan" --timeout-secs 1 --json b4b.json b4b >/dev/null; rc=$?
echo "  exit=$rc Dauer=$(( ($(date +%s%N) - s) / 1000000 )) ms"; show b4b.json
python3 - b4b.json <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for f in r.get("files", []):
    for g in f.get("gaps", []):
        print("  Lücke:", g["reason"], "-", g["detail"])
PY

echo "=== Befund 6: leerer Ordner, beauftragte Engine (ClamAV) fehlt"
mkdir b6
"$B" scan --rules "$RULES" --clamscan /nicht/vorhanden --json b6.json b6 >/dev/null; echo "  exit=$?"; show b6.json
