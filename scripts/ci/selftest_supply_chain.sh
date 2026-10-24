#!/usr/bin/env bash
# Negativtests für die Lieferkettenprüfung (T-010):
#  1. Ein absichtlich eingefügtes Testgeheimnis muss Gitleaks fehlschlagen lassen.
#  2. Eine Abhängigkeit aus unbekannter Quelle muss cargo-deny fehlschlagen lassen.
# Beide Fälle laufen in temporären Ordnern, nie im echten Repository.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "== Selbsttest 1: Gitleaks erkennt eingefügtes Testgeheimnis"
mkdir -p "$TMP/leak" && cd "$TMP/leak"
git init -q && git config user.email ci@example.invalid && git config user.name ci
# Künstlicher, ungültiger Schlüssel im Format eines GitHub-Tokens (zur Laufzeit zusammengesetzt).
printf 'token = "%s%s"\n' "ghp_" "1234567890abcdefghijABCDEFGHIJ1234ab" > config.txt
git add config.txt && git commit -q -m test
if gitleaks detect --no-banner --source . >"$TMP/gl.txt" 2>&1; then
  echo "FEHLER: Gitleaks hat das Testgeheimnis NICHT erkannt"; exit 1
fi
grep -qi "leaks found" "$TMP/gl.txt" || { echo "FEHLER: Gitleaks scheiterte aus anderem Grund"; cat "$TMP/gl.txt"; exit 1; }
echo "OK: Gitleaks schlägt wie erwartet fehl"

echo "== Selbsttest 2: manipulierte Abhängigkeit (Prüfsumme in Cargo.lock) bricht den Build ab"
mkdir -p "$TMP/dep/src" && cd "$TMP/dep"
cat > Cargo.toml <<'EOF2'
[package]
name = "lock-selftest"
version = "0.0.0"
edition = "2021"
publish = false
[dependencies]
hex = "=0.4.3"
EOF2
echo 'fn main() { println!("{}", hex::encode([1u8])); }' > src/main.rs
cargo generate-lockfile -q
# Prüfsumme von hex verfälschen (simuliert ein manipuliertes Paket/Lockfile).
python3 - <<'PY'
import re, pathlib
p = pathlib.Path("Cargo.lock"); s = p.read_text()
s2 = re.sub(r'(name = "hex"\nversion = "0.4.3"\nsource = "[^"]+"\nchecksum = ")[0-9a-f]{64}', lambda m: m.group(1) + "0" * 64, s)
assert s2 != s, "Prüfsumme nicht gefunden"
p.write_text(s2)
PY
if cargo build -q --locked >"$TMP/build.txt" 2>&1; then
  echo "FEHLER: Build mit manipulierter Prüfsumme war erfolgreich"; exit 1
fi
grep -qi "checksum" "$TMP/build.txt" || { echo "FEHLER: Build scheiterte aus anderem Grund"; cat "$TMP/build.txt"; exit 1; }
echo "OK: manipulierte Abhängigkeit wird abgelehnt"

echo "== Selbsttest 3: Releaseinventar erkennt EICAR und Schlüsselmaterial (T-012)"
mkdir -p "$TMP/pkg-bad" "$TMP/pkg-ok"
python3 -c "import sys; open(sys.argv[1],'w').write('X5O!P%@AP[4\\\\PZX54(P^)7CC)7}\$'+'EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H+H*')" "$TMP/pkg-bad/probe.com"
echo "harmlos" > "$TMP/pkg-ok/readme.txt"
if python3 "$ROOT/scripts/check_release_inventory.py" "$TMP/pkg-bad" >/dev/null; then
  echo "FEHLER: Inventarprüfung hat EICAR NICHT erkannt"; exit 1
fi
python3 "$ROOT/scripts/check_release_inventory.py" "$TMP/pkg-ok" >/dev/null || { echo "FEHLER: sauberes Paket abgelehnt"; exit 1; }
echo "OK: Inventarprüfung unterscheidet sauberes und belastetes Paket"
