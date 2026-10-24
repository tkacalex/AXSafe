#!/usr/bin/env bash
# Erzeugt docs/images/cli-demo.png aus einem ECHTEN Lauf von axsafe (keine Montage).
# Testdaten nur zur Laufzeit (EICAR aus zwei Teilen, harmlose Dateien),
# ClamAV mit einer AXSafe-Testsignatur. Benötigt: clamscan, zip, python3 + playwright.
#
#   scripts/docs/cli_demo.sh <pfad/zu/axsafe>
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
B="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT
mkdir "$W/Downloads"; cd "$W/Downloads"
python3 -c "open('eicar-test.com','w').write('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\$'+'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*')"
echo "Sehr geehrte Damen und Herren" > brief.txt
printf '%%PDF-1.7\nharmloses Beispiel\n' > rechnung.pdf
echo geheim > inhalt.txt && zip -q -P passwort archiv-mit-passwort.zip inhalt.txt && rm inhalt.txt
zip -q fotos.zip brief.txt
ln -s brief.txt verknuepfung
cd "$W"
python3 -c "import hashlib; e=open('Downloads/eicar-test.com','rb').read(); print(f'{hashlib.md5(e).hexdigest()}:{len(e)}:AXSafe.Test.EICAR-HDB')" > test.hdb
set +e; "$B" scan --rules "$ROOT/rules" --clamav-db test.hdb -- Downloads > out.txt 2>&1; rc=$?; set -e
echo "exit=$rc" >> out.txt
python3 "$ROOT/scripts/docs/render_terminal.py" out.txt "$ROOT/docs/images/cli-demo.png" "\$ axsafe scan Downloads"
cat out.txt
