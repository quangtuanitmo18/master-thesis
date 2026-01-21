# SpotBugs/FindSecBugs dùng ruleId khác CodeQL:
import csv
import json
import os
import re

CSV_PATH = "input_files/ground_truth/expectedresults-1.2.csv"
SARIF_PATH = "input_files/sarif_results/owasp-benchmark/spotbugs-findsecbugs-owasp-benchmark-java.sarif"

# Config for CWE analysis (có thể thay đổi)
TARGET_CWE = "22"  # SQL Injection

# SpotBugs version check
SPOTBUGS_VERSION = "4.9.8"
FINDSECBUGS_VERSION = "1.14.0"

# Mapping SpotBugs/FindSecBugs rule IDs to CWE
# Based on SpotBugs 4.9.8 + FindSecBugs 1.14.0
# Reference: https://find-sec-bugs.github.io/bugs.htm
# Reference: https://spotbugs.readthedocs.io/en/latest/bugDescriptions.html
RULE_TO_CWE_MAP = {
    # ========== SQL Injection (CWE-89) ==========
    "SQL_INJECTION_JDBC": "89",
    "SQL_INJECTION_SPRING_JDBC": "89",
    "SQL_INJECTION_SPRING": "89",
    "SQL_INJECTION_JPA": "89",
    "SQL_INJECTION_HIBERNATE": "89",
    "SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING": "89",
    
    # ========== Cross-Site Scripting (CWE-79) ==========
    "XSS_SERVLET": "79",
    "XSS_JSP_PRINT": "79",
    "XSS_JSP_WRITER": "79",
    "XSS_REQUEST_PARAMETER_TO_SEND_ERROR": "79",
    "XSS_REQUEST_PARAMETER_TO_JSP_WRITER": "79",
    "XSS_REQUEST_PARAMETER_TO_HTML_ESCAPE": "79",
    "XSS_REQUEST_WRAPPER": "79",
    
    # ========== Path Traversal (CWE-22) ==========
    "PATH_TRAVERSAL_IN": "22",
    "PATH_TRAVERSAL_OUT": "22",
    "PT_ABSOLUTE_PATH_TRAVERSAL": "36",  # CWE-36: Absolute Path Traversal
    "PT_RELATIVE_PATH_TRAVERSAL": "23",  # CWE-23: Relative Path Traversal
    
    # ========== LDAP Injection (CWE-90) ==========
    "LDAP_INJECTION": "90",
    "LDAP_ANONYMOUS": "90",
    
    # ========== OS Command Injection (CWE-78) ==========
    "COMMAND_INJECTION": "78",
    "COMMAND_INJECTION_OS_COMMAND": "78",
    "OS_COMMAND_INJECTION": "78",
    
    # ========== HTTP Response Splitting (CWE-113) ==========
    "HTTP_RESPONSE_SPLITTING": "113",
    "HRS_REQUEST_PARAMETER_TO_COOKIE": "113",
    "HRS_REQUEST_PARAMETER_TO_HTTP_HEADER": "113",
    
    # ========== Weak Cryptography (CWE-327, 328, 329) ==========
    "WEAK_MESSAGE_DIGEST_MD5": "328",
    "WEAK_MESSAGE_DIGEST_MD4": "328",
    "WEAK_MESSAGE_DIGEST_MD2": "328",
    "WEAK_MESSAGE_DIGEST_SHA1": "327",
    "WEAK_MESSAGE_DIGEST": "327",
    "STATIC_IV": "329",
    "STATIC_INITIALIZATION_VECTOR": "329",
    "DES_USAGE": "327",
    "TDES_USAGE": "327",
    "RSA_NO_PADDING": "327",
    "RSA_MISSING_PADDING": "327",
    "ECB_MODE": "327",
    "PADDING_ORACLE": "329",
    
    # ========== Hard-coded Credentials (CWE-798, 259) ==========
    "HARD_CODE_PASSWORD": "798",
    "HARD_CODE_KEY": "798",
    "HARD_CODE_SECRET": "798",
    "DMI_CONSTANT_DB_PASSWORD": "259",
    "DMI_EMPTY_DB_PASSWORD": "259",
    "HARDCODED_PASSWORD": "798",
    
    # ========== Trust Boundary Violation (CWE-501) ==========
    "TRUST_BOUNDARY_VIOLATION": "501",
    "TRUST_BOUNDARY": "501",
    
    # ========== Code Injection (CWE-94, 95) ==========
    "SPEL_INJECTION": "94",  # Spring Expression Language Injection
    "EL_INJECTION": "94",    # Expression Language Injection
    "CODE_INJECTION": "94",
    "JSP_INCLUDE": "94",
    
    # ========== Open Redirect (CWE-601) ==========
    "UNVALIDATED_REDIRECT": "601",
    "UNVALIDATED_REDIRECTS": "601",
    "HTTPONLY_COOKIE": "1004",  # CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag
    
    # ========== Insecure Random (CWE-330) ==========
    "INSECURE_RANDOM": "330",
    "PREDICTABLE_RANDOM": "330",
    "WEAK_PRNG": "330",
    
    # ========== Information Disclosure (CWE-209, 215, 532) ==========
    "HTTPONLY_COOKIE": "1004",
    "COOKIE_USAGE": "209",
    "SERVLET_HEADER_REFERER": "209",
    "SERVLET_QUERY_STRING": "209",
    "SERVLET_SESSION_ID_IN_URL": "209",
    "SERVLET_PARAMETER": "209",
    "SERVLET_COOKIE": "209",
    "SERVLET_CONTENT_TYPE": "209",
    "SERVLET_SERVER_NAME": "209",
    "SERVLET_PATH_TRAVERSAL": "22",
    
    # ========== XML External Entity (CWE-611) ==========
    "XXE_XMLSTREAMREADER": "611",
    "XXE_DOCUMENT": "611",
    "XXE_XMLREADER": "611",
    "XXE_XPATH": "611",
    
    # ========== XPath Injection (CWE-643) ==========
    "XPATH_INJECTION": "643",
    "XPATH_INJECTION_XML": "643",
    
    # ========== Insecure Deserialization (CWE-502) ==========
    "DESERIALIZATION_GADGET": "502",
    "OBJECT_DESERIALIZATION": "502",
    "JACKSON_UNSAFE_DESERIALIZATION": "502",
    
    # ========== Weak Session Management (CWE-613) ==========
    "WEAK_SESSION_ID": "613",
    "INSECURE_SESSION": "613",
    
    # ========== Security Misconfiguration (CWE-16) ==========
    "INSECURE_COOKIE": "614",
    "COOKIE_FLAGS_NOT_SET": "614",
    
    # ========== Improper Input Validation (CWE-20) ==========
    "CONTROLLED_BY_EXTERNAL_INPUT": "20",
    "UNVALIDATED_INPUT": "20",
    
    # ========== Other Security Issues ==========
    "CRLF_INJECTION_LOGS": "117",  # CWE-117: Log Injection
    "CRLF_INJECTION": "113",
    "FILE_UPLOAD_FILENAME": "434",  # CWE-434: Unrestricted Upload
    "FILE_UPLOAD_SIZE": "434",
    "ZERO_RANDOM": "330",
    "NULL_CIPHER": "327",
    "BROKEN_CRYPTO": "327",
    "CIPHER_WITH_NO_INTEGRITY": "353",  # CWE-353: Missing Support for Integrity Check
    "STATIC_KEY": "321",  # CWE-321: Use of Hard-coded Cryptographic Key
    "HARD_CODE_KEYSTORE": "798",
    "INSECURE_SSL": "295",  # CWE-295: Improper Certificate Validation
    "BAD_HEXA_CONVERSION": "704",  # CWE-704: Incorrect Type Conversion
    "SERVLET_SESSION": "613",
    "JSP_JSTL_OUT": "79",
    "SPRING_ENDPOINT": "20",
    "SPRING_CSRF_PROTECTION_DISABLED": "352",  # CWE-352: Cross-Site Request Forgery
    "SPRING_UNVALIDATED_REDIRECT": "601",
    "SPRING_CSRF_UNRESTRICTED": "352",
    "JAXRS_ENDPOINT": "20",
    "JAXWS_ENDPOINT": "20",
    "SPRING_FILE_UPLOAD": "434",
    "JSP_INCLUDE": "94",
    "JSP_XSS": "79",
    "JSP_JSTL_OUT": "79",
    "JSP_XSS_2": "79",
    "JSP_XSS_3": "79",
    "JSP_XSS_4": "79",
    "JSP_XSS_5": "79",
    "JSP_XSS_6": "79",
    "JSP_XSS_7": "79",
    "JSP_XSS_8": "79",
    "JSP_XSS_9": "79",
    "JSP_XSS_10": "79",
    "JSP_XSS_11": "79",
    "JSP_XSS_12": "79",
    "JSP_XSS_13": "79",
    "JSP_XSS_14": "79",
    "JSP_XSS_15": "79",
    "JSP_XSS_16": "79",
    "JSP_XSS_17": "79",
    "JSP_XSS_18": "79",
    "JSP_XSS_19": "79",
    "JSP_XSS_20": "79",
}

# Helper function to get all rule IDs for a specific CWE
def get_rules_for_cwe(cwe):
    """Trả về danh sách tất cả rule IDs cho một CWE cụ thể"""
    return [rule_id for rule_id, cwe_id in RULE_TO_CWE_MAP.items() if cwe_id == cwe]

# Auto-generate TARGET_RULE_IDS from TARGET_CWE
TARGET_RULE_IDS = get_rules_for_cwe(TARGET_CWE)

print(f"SpotBugs version: {SPOTBUGS_VERSION}")
print(f"FindSecBugs version: {FINDSECBUGS_VERSION}")
print(f"Target CWE: {TARGET_CWE}")
print(f"Auto-detected rule IDs for CWE-{TARGET_CWE}: {TARGET_RULE_IDS}")


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
            
            # Extract test name from URI
            # Format: src/main/java/org/owasp/benchmark/testcode/BenchmarkTest00001.java
            # or: BenchmarkTest00001.java
            base = os.path.basename(uri)
            if base.startswith("BenchmarkTest") and base.endswith(".java"):
                # Remove .java extension
                test_name = base[:-5]
                out.add(test_name)
            
            # Also check in message text
            message = result.get("message", {})
            if isinstance(message, dict):
                text = message.get("text", "")
            else:
                text = str(message)
            
            # Try to extract BenchmarkTestXXXXX from message
            matches = re.findall(r'BenchmarkTest\d{5}', text)
            out.update(matches)

    handle_locations(result.get("locations"))
    handle_locations(result.get("relatedLocations"))
    return out


def build_rule_cwe_index(rules):
    """ruleId -> CWE number (from rule properties, tags, or mapping table)"""
    idx = {}
    for rule in rules or []:
        rid = rule.get("id")
        if not rid:
            continue
        
        # Check properties for CWE tag
        props = rule.get("properties") or {}
        tags = props.get("tags") or []
        
        # Look for CWE in tags (format: external/cwe/cwe-89 or cwe-89)
        cwe = None
        for tag in tags:
            if isinstance(tag, str) and "cwe" in tag.lower():
                match = re.search(r'cwe[-\s]?(\d+)', tag.lower())
                if match:
                    cwe = match.group(1)
                    break
        
        # Fallback: check rule name/description for CWE
        if not cwe:
            name = rule.get("name", "")
            desc = rule.get("fullDescription", {})
            if isinstance(desc, dict):
                desc_text = desc.get("text", "")
            else:
                desc_text = str(desc)
            
            # Try to find CWE in name or description
            for text in [name, desc_text]:
                match = re.search(r'CWE[-\s]?(\d+)', text, re.IGNORECASE)
                if match:
                    cwe = match.group(1)
                    break
        
        # Fallback: use mapping table
        if not cwe:
            cwe = RULE_TO_CWE_MAP.get(rid)
        
        if cwe:
            idx[rid] = cwe
    
    return idx


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

# 2) Ground truth cho TARGET_CWE
pos_tests = {t for t, info in gt.items() if info["cwe"] == TARGET_CWE and info["is_vuln"]}
neg_tests = {t for t, info in gt.items() if info["cwe"] == TARGET_CWE and not info["is_vuln"]}

print(f"\nCWE-{TARGET_CWE}: positives in ground truth = {len(pos_tests)}, negatives = {len(neg_tests)}")

# 3) Đọc SARIF, chỉ lấy result thuộc rule CWE target
with open(SARIF_PATH, encoding="utf-8") as f:
    sarif = json.load(f)

detected_tests_all_rules = set()
detected_tests_cwe_rule = set()

for run in sarif.get("runs", []):
    rules = ((run.get("tool") or {}).get("driver") or {}).get("rules") or []
    rule_cwe_map = build_rule_cwe_index(rules)

    for result in run.get("results", []) or []:
        rule_id = result.get("ruleId") or ""
        test_names = iter_test_names_from_result(result)
        detected_tests_all_rules |= test_names

        # Check if this rule matches target CWE
        rule_cwe = rule_cwe_map.get(rule_id)
        
        # Match by ruleId (if in TARGET_RULE_IDS) or by CWE mapping
        if rule_id in TARGET_RULE_IDS:
            detected_tests_cwe_rule |= test_names
        elif rule_cwe == TARGET_CWE:
            detected_tests_cwe_rule |= test_names

print(f"Total tests detected in SARIF (all rules): {len(detected_tests_all_rules)}")
print(f"Total tests detected for CWE-{TARGET_CWE} rule: {len(detected_tests_cwe_rule)}")
print(f"Target rule IDs: {TARGET_RULE_IDS}")

# 4) Chỉ giữ các detection mà ground truth cũng gán CWE target
detected_cwe_tests = {t for t in detected_tests_cwe_rule if t in gt and gt[t]["cwe"] == TARGET_CWE}

TP = detected_cwe_tests & pos_tests
FP = detected_cwe_tests & neg_tests
FN = pos_tests - detected_cwe_tests
TN = neg_tests - detected_cwe_tests

# 5) Tính các metrics
precision = len(TP) / (len(TP) + len(FP)) if (len(TP) + len(FP)) > 0 else 0.0
recall = len(TP) / (len(TP) + len(FN)) if (len(TP) + len(FN)) > 0 else 0.0
accuracy = (len(TP) + len(TN)) / (len(TP) + len(FP) + len(FN) + len(TN)) if (len(TP) + len(FP) + len(FN) + len(TN)) > 0 else 0.0
f1_score = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
fpr = len(FP) / (len(FP) + len(TN)) if (len(FP) + len(TN)) > 0 else 0.0

print(f"\nCWE-{TARGET_CWE} metrics (SpotBugs {SPOTBUGS_VERSION} + FindSecBugs {FINDSECBUGS_VERSION}):")
print(f"TP = {len(TP)}")
print(f"FP = {len(FP)}")
print(f"FN = {len(FN)}")
print(f"TN = {len(TN)}")
print(f"\nPrecision = {precision:.4f}")
print(f"Recall = {recall:.4f}")
print(f"Accuracy = {accuracy:.4f}")
print(f"F1-Score = {f1_score:.4f}")
print(f"FPR (False Positive Rate) = {fpr:.4f}")

# Debug: uncomment để xem chi tiết
# print("\nTP tests:", sorted(TP))
# print("FP tests:", sorted(FP))
# print("FN tests:", sorted(FN))
# print("TN tests:", sorted(TN))