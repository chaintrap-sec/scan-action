from chaintrap_static_scan.classify import classify_ids


def test_duplicate_ids_deduped():
    mal, vuln = classify_ids(["MAL-1", "MAL-1", "CVE-1"])
    assert mal == ["MAL-1"]
    assert vuln == ["CVE-1"]
