import argparse
import json
import os
from copy import deepcopy

from semgrep_evaluate import build_rule_cwe_index_from_semgrep_rules


def split_sarif_by_cwe(input_path: str, output_dir: str, prefix: str = "semgrep-owasp-benchmark") -> None:
    """
    Tách 1 file SARIF Semgrep tổng thành nhiều file SARIF nhỏ theo từng CWE.

    - Đọc rules từ runs[0].tool.driver.rules, map ruleId -> set(CWE_numbers)
      (dùng chung hàm với semgrep_evaluate để đảm bảo nhất quán).
    - Mỗi result được gán vào tất cả CWE mà ruleId đó có trong tags.
    - Với mỗi CWE tạo 1 file SARIF mới giữ nguyên cấu trúc, chỉ thay runs[0].results.

    File output sẽ có dạng:
      {prefix}-CWE-{cwe}.sarif
    ví dụ:
      semgrep-owasp-benchmark-CWE-643.sarif
    """
    input_path = os.path.abspath(input_path)
    output_dir = os.path.abspath(output_dir)

    with open(input_path, "r", encoding="utf-8") as f:
        sarif_data = json.load(f)

    runs = sarif_data.get("runs", [])
    if not runs:
        print("No runs found in SARIF file, nothing to split.")
        return

    run = runs[0]
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    rule_cwe_map = build_rule_cwe_index_from_semgrep_rules(rules)

    if not rule_cwe_map:
        print("No CWE mapping found in Semgrep rules (check tags/properties).")
        return

    # Gom result theo CWE (cwe_number -> list of results)
    cwe_to_results = {}
    for result in run.get("results", []) or []:
        rule_id = result.get("ruleId")
        if not rule_id:
            continue
        cwes = rule_cwe_map.get(rule_id) or set()
        if not cwes:
            continue
        for cwe in cwes:
            cwe_to_results.setdefault(cwe, []).append(result)

    if not cwe_to_results:
        print("No results mapped to any CWE, nothing to write.")
        return

    os.makedirs(output_dir, exist_ok=True)

    print(f"Input SARIF: {input_path}")
    print(f"Output dir : {output_dir}")
    print(f"Prefix     : {prefix}")
    print(f"Found {len(cwe_to_results)} CWEs with at least one result.")

    for cwe, results in sorted(cwe_to_results.items(), key=lambda kv: int(kv[0])):
        new_sarif = deepcopy(sarif_data)
        new_sarif["runs"][0]["results"] = results

        filename = f"{prefix}-CWE-{cwe}.sarif"
        out_path = os.path.join(output_dir, filename)

        with open(out_path, "w", encoding="utf-8") as out_f:
            json.dump(new_sarif, out_f, indent=2)

        print(f"  - CWE-{cwe}: {len(results)} results -> {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Split Semgrep SARIF into per-CWE SARIF files.")
    parser.add_argument(
        "--input",
        required=True,
        help="Path to Semgrep SARIF file (tổng).",
    )
    parser.add_argument(
        "--output_dir",
        required=True,
        help="Directory to write per-CWE SARIF files.",
    )
    parser.add_argument(
        "--prefix",
        default="semgrep-owasp-benchmark",
        help="Filename prefix for output SARIF files (default: semgrep-owasp-benchmark).",
    )

    args = parser.parse_args()
    split_sarif_by_cwe(args.input, args.output_dir, args.prefix)


if __name__ == "__main__":
    main()


