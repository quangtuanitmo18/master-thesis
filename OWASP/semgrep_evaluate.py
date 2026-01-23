import csv
import json
import os
import re

# ==== Paths & basic config ====

CSV_PATH = "input_files/ground_truth/expectedresults-1.2.csv"
SARIF_PATH = "input_files/sarif_results/owasp-benchmark/Benchmark_1.2-Semgrep-v1.149.0-codeflows-transform.sarif"

# Đặt CWE cần đánh giá (chỉ số, không có 'CWE-')
# Ví dụ: "90" (LDAP Injection), "89" (SQLi), "79" (XSS), ...
TARGET_CWE = "328"


def iter_test_names_from_result(result):
    """
    Lấy các BenchmarkTestXXXXX từ locations (và relatedLocations nếu có).

    Semgrep SARIF dùng chuẩn SARIF nên cấu trúc tương tự các tool khác:
      - result.locations[*].physicalLocation.artifactLocation.uri
      - message.text đôi khi cũng chứa tên BenchmarkTest.
    """
    out = set()

    def handle_locations(locs):
        if not locs:
            return
        for loc in locs:
            phys = (loc or {}).get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            uri = art.get("uri") or ""

            # Ví dụ: src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java
            base = os.path.basename(uri)
            if base.startswith("BenchmarkTest") and base.endswith(".java"):
                out.add(base[:-5])  # bỏ .java

    handle_locations(result.get("locations"))
    handle_locations(result.get("relatedLocations"))

    # Backup: cố gắng tìm BenchmarkTest trong message
    message = result.get("message", {})
    if isinstance(message, dict):
        text = message.get("text", "")
    else:
        text = str(message)
    matches = re.findall(r"BenchmarkTest\d{5}", text)
    out.update(matches)

    return out


def build_rule_cwe_index_from_semgrep_rules(rules):
    """
    Tạo mapping: ruleId -> set(CWE_numbers)

    Semgrep ghi CWE trong rules[*].properties.tags, ví dụ:
      "tags": [
        "CWE-90: Improper Neutralization of Special Elements used in an LDAP Query ...",
        "LOW CONFIDENCE",
        ...
      ]

    Ta parse tất cả 'CWE-<digits>' trong tags và trả về phần số (không 'CWE-').
    """
    idx = {}
    cwe_regex = re.compile(r"CWE-(\d+)", re.IGNORECASE)

    for rule in rules or []:
        rid = rule.get("id")
        if not rid:
            continue

        tags = (rule.get("properties") or {}).get("tags") or []
        cwes = set()

        for tag in tags:
            if not isinstance(tag, str):
                continue
            for m in cwe_regex.finditer(tag):
                cwes.add(m.group(1))  # ví dụ "90"

        if cwes:
            idx[rid] = cwes

    return idx


def main():
    # 1) Đọc ground truth
    gt = {}  # test_name -> {"is_vuln": bool, "cwe": str}
    with open(CSV_PATH, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        for row in reader:
            if not row or row[0].startswith("#"):
                continue
            test_name, _category, real_vuln, cwe = row[0], row[1], row[2], row[3]
            gt[test_name] = {
                "is_vuln": real_vuln.strip().lower() == "true",
                "cwe": str(cwe).strip(),
            }

    pos_tests = {t for t, info in gt.items() if info["cwe"] == TARGET_CWE and info["is_vuln"]}
    neg_tests = {t for t, info in gt.items() if info["cwe"] == TARGET_CWE and not info["is_vuln"]}

    print(f"Target CWE: {TARGET_CWE}")
    print(f"Ground truth positives (CWE-{TARGET_CWE}) = {len(pos_tests)}, negatives = {len(neg_tests)}")

    # 2) Đọc SARIF Semgrep
    with open(SARIF_PATH, encoding="utf-8") as f:
        sarif = json.load(f)

    detected_tests_all_rules = set()
    detected_tests_cwe_rule = set()

    for run in sarif.get("runs", []):
        rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
        rule_cwe_map = build_rule_cwe_index_from_semgrep_rules(rules)

        for result in run.get("results", []) or []:
            rule_id = result.get("ruleId") or ""
            test_names = iter_test_names_from_result(result)
            detected_tests_all_rules |= test_names

            # Kiểm tra rule này có map tới TARGET_CWE không
            rule_cwes = rule_cwe_map.get(rule_id) or set()
            if TARGET_CWE in rule_cwes:
                detected_tests_cwe_rule |= test_names

    print(f"\nTotal tests detected in SARIF (all Semgrep rules): {len(detected_tests_all_rules)}")
    print(f"Total tests detected for CWE-{TARGET_CWE} rules: {len(detected_tests_cwe_rule)}")

    # 3) Chỉ giữ detection mà ground truth cũng gán CWE target
    detected_cwe_tests = {t for t in detected_tests_cwe_rule if t in gt and gt[t]["cwe"] == TARGET_CWE}

    TP = detected_cwe_tests & pos_tests
    FP = detected_cwe_tests & neg_tests
    FN = pos_tests - detected_cwe_tests
    TN = neg_tests - detected_cwe_tests

    # 4) Tính metrics
    precision = len(TP) / (len(TP) + len(FP)) if (len(TP) + len(FP)) > 0 else 0.0
    recall = len(TP) / (len(TP) + len(FN)) if (len(TP) + len(FN)) > 0 else 0.0
    accuracy = (
        (len(TP) + len(TN)) / (len(TP) + len(FP) + len(FN) + len(TN))
        if (len(TP) + len(FP) + len(FN) + len(TN)) > 0
        else 0.0
    )
    f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = len(FP) / (len(FP) + len(TN)) if (len(FP) + len(TN)) > 0 else 0.0

    print(f"\nCWE-{TARGET_CWE} metrics (Semgrep):")
    print(f"TP = {len(TP)}")
    print(f"FP = {len(FP)}")
    print(f"FN = {len(FN)}")
    print(f"TN = {len(TN)}")
    print(f"\nPrecision = {precision:.4f}")
    print(f"Recall    = {recall:.4f}")
    print(f"Accuracy  = {accuracy:.4f}")
    print(f"F1-Score  = {f1_score:.4f}")
    print(f"FPR       = {fpr:.4f}")

    # Nếu cần debug chi tiết:
    # print("\nTP tests:", sorted(TP))
    # print("FP tests:", sorted(FP))
    # print("FN tests:", sorted(FN))
    # print("TN tests:", sorted(TN))


if __name__ == "__main__":
    main()


