import csv
import json
import os

CSV_PATH = "input_files/ground_truth/expectedresults-1.2.csv"
SARIF_PATH = "input_files/sarif_results/owasp-benchmark/codeql-owasp-benchmark-java-security-extended-1.4.0.sarif"

# Config for CWE-22 (Path Traversal) analysis
TARGET_CWE = "643"
# Per the SARIF produced by CodeQL CWE-022 run, the ruleId present in results is:
#   java/path-injection
TARGET_RULE_ID = "java/xml/xpath-injection"


def iter_test_names_from_result(result):
    """Lấy các BenchmarkTestXXXXX từ locations + relatedLocations."""
    out = set()

    def handle_locations(locs):
        if not locs:
            return
        for loc in locs:
            phys = (loc or {}).get("physicalLocation", {})
            art = phys.get("artifactLocation", {})
            uri = art.get("uri") or ""
            base = os.path.basename(uri)
            if base.startswith("BenchmarkTest") and base.endswith(".java"):
                out.add(base[:-5])

    handle_locations(result.get("locations"))
    handle_locations(result.get("relatedLocations"))
    return out


def build_rule_tag_index(rules):
    """ruleId -> set(tags)"""
    idx = {}
    for rule in rules or []:
        rid = rule.get("id")
        if not rid:
            continue
        tags = (rule.get("properties") or {}).get("tags") or []
        idx[rid] = set(tags)
    return idx


# 1) Đọc ground truth
gt = {}  # test_name -> {"is_vuln": bool, "cwe": str}
with open(CSV_PATH, newline="") as f:
    reader = csv.reader(f)
    for row in reader:
        if not row or row[0].startswith("#"):
            continue
        test_name, _category, real_vuln, cwe = row[0], row[1], row[2], row[3]
        gt[test_name] = {
            "is_vuln": real_vuln.strip().lower() == "true",
            "cwe": str(cwe).strip(),
        }

# 2) Ground truth cho CWE-643
pos_tests = {t for t, info in gt.items() if info["cwe"] == TARGET_CWE and info["is_vuln"]}
neg_tests = {t for t, info in gt.items() if info["cwe"] == TARGET_CWE and not info["is_vuln"]}

print(f"CWE-{TARGET_CWE}: positives in ground truth = {len(pos_tests)}, negatives = {len(neg_tests)}")

# 3) Đọc SARIF, chỉ lấy result thuộc rule CWE-643
with open(SARIF_PATH) as f:
    sarif = json.load(f)

detected_tests_all_rules = set()
detected_tests_cwe_rule = set()

for run in sarif.get("runs", []):
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    rule_tags = build_rule_tag_index(rules)

    for result in run.get("results", []) or []:
        rule_id = result.get("ruleId") or ""
        test_names = iter_test_names_from_result(result)
        detected_tests_all_rules |= test_names

        # Ưu tiên match ruleId, nếu khác thì fallback theo tag external/cwe/cwe-643
        if rule_id == TARGET_RULE_ID:
            detected_tests_cwe_rule |= test_names
        else:
            tags = rule_tags.get(rule_id, set())
            if f"external/cwe/cwe-{TARGET_CWE}" in tags:
                detected_tests_cwe_rule |= test_names

print(f"Total tests detected in SARIF (all rules): {len(detected_tests_all_rules)}")
print(f"Total tests detected for CWE-{TARGET_CWE} rule: {len(detected_tests_cwe_rule)} (ruleId={TARGET_RULE_ID})")

# 4) Chỉ giữ các detection mà ground truth cũng gán CWE-643
detected_cwe_tests = {t for t in detected_tests_cwe_rule if t in gt and gt[t]["cwe"] == TARGET_CWE}

TP = detected_cwe_tests & pos_tests
FP = detected_cwe_tests & neg_tests
FN = pos_tests - detected_cwe_tests
TN = neg_tests - detected_cwe_tests

print(f"\nCWE-{TARGET_CWE} metrics (suite SARIF, filtered by rule):")
print(f"TP = {len(TP)}")
print(f"FP = {len(FP)}")
print(f"FN = {len(FN)}")
print(f"TN = {len(TN)}")

# Nếu cần debug:
# print("TP tests:", sorted(TP))
# print("FP tests:", sorted(FP))
# print("FN tests:", sorted(FN))
# print("TN tests:", sorted(TN))