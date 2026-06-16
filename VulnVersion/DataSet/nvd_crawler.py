from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import httpx
from bs4 import BeautifulSoup

BASE_URL = "https://nvd.nist.gov/vuln/detail/"
USER_AGENT = (
  "Mozilla/5.0 (X11; Linux x86_64) "
  "AppleWebKit/537.36 (KHTML, like Gecko) "
  "Chrome/123.0.0.0 Safari/537.36"
)


def _project_root() -> Path:
  return Path(__file__).resolve().parents[1]


def get_page_content(cve_id: str, *, timeout_s: float = 30.0) -> str | None:
  url = f"{BASE_URL}{cve_id}"
  try:
    with httpx.Client(
      headers={"User-Agent": USER_AGENT},
      follow_redirects=True,
      timeout=float(timeout_s),
    ) as client:
      response = client.get(url)
      response.raise_for_status()
      return response.text
  except httpx.HTTPError as e:
    print(f"Exception fetching {cve_id}: {e}", flush=True)
    return None


def parse_nvd_page(html: str) -> dict:
  soup = BeautifulSoup(html, "html.parser")
  data: dict = {}

  desc_elem = soup.find("p", {"data-testid": "vuln-description"})
  data["description"] = desc_elem.text.strip() if desc_elem else None

  def extract_metric(source: str, score_id: str, vector_id: str, *, score_id_is_testid: bool = True) -> dict | None:
    entry: dict = {}
    if score_id_is_testid:
      score_elem = soup.find("a", {"data-testid": score_id})
    else:
      score_elem = soup.find("a", {"id": score_id})

    if not score_elem:
      return None
    entry["source"] = source
    entry["score"] = score_elem.text.strip()
    vector_elem = soup.find("span", {"data-testid": vector_id})
    entry["vector"] = vector_elem.text.strip() if vector_elem else None
    return entry

  cvss3_list: list[dict] = []
  for src, sid, vid, is_testid in [
    ("NIST", "vuln-cvss3-panel-score", "vuln-cvss3-nist-vector", True),
    ("CNA", "vuln-cvss3-cna-panel-score", "vuln-cvss3-cna-vector", True),
    ("ADP", "vuln-cvss3-adp-panel-score", "vuln-cvss3-adp-vector", True),
  ]:
    m = extract_metric(src, sid, vid, score_id_is_testid=is_testid)
    if m:
      cvss3_list.append(m)
  if cvss3_list:
    data["cvss3"] = cvss3_list
  elif soup.find("a", {"data-testid": "vuln-cvss3-panel-score-na"}):
    data["cvss3"] = "N/A"
  else:
    data["cvss3"] = None

  cvss2_list: list[dict] = []
  nist2 = extract_metric("NIST", "Cvss2CalculatorAnchor", "vuln-cvss2-panel-vector", score_id_is_testid=False)
  if nist2:
    cvss2_list.append(nist2)
  if cvss2_list:
    data["cvss2"] = cvss2_list
  elif soup.find("a", {"data-testid": "vuln-cvss2-panel-score-na"}):
    data["cvss2"] = "N/A"
  else:
    data["cvss2"] = None

  cvss4_list: list[dict] = []
  for src, sid, vid in [
    ("NIST", "vuln-cvss4-panel-score", "vuln-cvss4-nist-vector"),
    ("CNA", "vuln-cvss4-cna-panel-score", "vuln-cvss4-cna-vector"),
  ]:
    m = extract_metric(src, sid, vid, score_id_is_testid=True)
    if m:
      cvss4_list.append(m)
  if cvss4_list:
    data["cvss4"] = cvss4_list
  elif soup.find("a", {"data-testid": "vuln-cvss4-panel-score-na"}):
    data["cvss4"] = "N/A"
  else:
    data["cvss4"] = None

  return data


def _load_json(path: Path) -> dict:
  return json.loads(path.read_text(encoding="utf-8"))


def _resolve_path(root: Path, raw: str | None, default: Path) -> Path:
  if not raw:
    return default.resolve()
  p = Path(raw)
  if p.is_absolute():
    return p.resolve()
  return (root / p).resolve()


def main(argv: list[str] | None = None) -> int:
  ap = argparse.ArgumentParser()
  ap.add_argument("--dataset", default=None)
  ap.add_argument("--output", default=None)
  ap.add_argument("--cve-id", default=None)
  ap.add_argument("--sleep-s", type=float, default=2.0)
  ap.add_argument("--timeout-s", type=float, default=30.0)
  args = ap.parse_args(argv)

  root = _project_root()
  dataset_path = _resolve_path(root, args.dataset, root / "DataSet" / "BaseDataOrder.json")
  output_path = _resolve_path(root, args.output, root / "DataSet" / "BaseData_nvd.json")

  if args.cve_id:
    cve_ids = [args.cve_id.strip()]
  else:
    if not dataset_path.exists():
      raise SystemExit(f"Dataset not found at {dataset_path}")
    dataset = _load_json(dataset_path)
    if not isinstance(dataset, dict):
      raise SystemExit(f"Invalid dataset JSON: {dataset_path}")
    cve_ids = list(dataset.keys())

  results: dict = {}
  if output_path.exists():
    try:
      results = _load_json(output_path)
      if not isinstance(results, dict):
        results = {}
    except Exception:
      results = {}

  print(f"Processing {len(cve_ids)} CVEs (output={output_path})", flush=True)
  for i, cve_id in enumerate(cve_ids, start=1):
    if cve_id in results and isinstance(results.get(cve_id), dict) and results[cve_id].get("description"):
      continue

    print(f"[{i}/{len(cve_ids)}] Fetching {cve_id}...", flush=True)
    html = get_page_content(cve_id, timeout_s=float(args.timeout_s))
    if not html:
      print(f"Failed to retrieve content for {cve_id}", flush=True)
      continue
    if "Attention Required! | Cloudflare" in html:
      print("Blocked by Cloudflare. Stopping.", flush=True)
      break

    info = parse_nvd_page(html)
    info["source_url"] = f"{BASE_URL}{cve_id}"
    results[cve_id] = info
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(results, ensure_ascii=False, indent=4), encoding="utf-8")
    time.sleep(float(args.sleep_s))

  print(f"Done. Saved to {output_path}", flush=True)
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
