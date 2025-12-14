set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${ROOT_DIR}/reports"
TMP_DIR="${OUT_DIR}/tmp"

SEMgrep_JSON="${ROOT_DIR}/sast/semgrep-report.json"
CHECKOV_JSON="${ROOT_DIR}/sast/checkov-report/results_json.json"
DC_JSON="${ROOT_DIR}/sca/dependency-check-report/dependency-check-report.json"

mkdir -p "${OUT_DIR}" "${TMP_DIR}"

missing=0
for f in "${SEMgrep_JSON}" "${CHECKOV_JSON}" "${DC_JSON}"; do
  if [[ ! -f "$f" ]]; then
    echo "[WARN] Missing input report: $f"
    missing=1
  fi
done

echo "[INFO] Building unified report..."
python3 "${ROOT_DIR}/sca/unify_reports.py" \
  --semgrep "${SEMgrep_JSON}" \
  --checkov "${CHECKOV_JSON}" \
  --dependency-check "${DC_JSON}" \
  --outdir "${OUT_DIR}"

echo "[INFO] Done."
echo "[INFO] JSON:  ${OUT_DIR}/unified-report.json"
echo "[INFO] CSV:   ${OUT_DIR}/unified-report.csv"
echo "[INFO] HTML:  ${OUT_DIR}/unified-report.html"

if [[ $missing -eq 1 ]]; then
  echo "[WARN] Some inputs were missing — unified report may be partial."
fi
