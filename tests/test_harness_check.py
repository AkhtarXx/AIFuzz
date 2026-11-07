import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import harness_check as hc


MINIMAL = {
    "name": "t",
    "description": "d",
    "language": "c",
    "sources": ["fuzz_target.c"],
    "engines": ["libfuzzer"],
    "sanitizers": ["address"],
}


def test_manifest_minimal_valid():
    assert hc.validate_manifest(dict(MINIMAL)) == []


def test_manifest_unknown_top_key():
    m = dict(MINIMAL)
    m["expected_crash"] = True
    errs = hc.validate_manifest(m)
    assert any("unknown manifest key" in e for e in errs)


def test_manifest_typo_crash_key():
    m = dict(MINIMAL)
    m["fuzz"] = {"expected_crashh": True}
    errs = hc.validate_manifest(m)
    assert any("unknown fuzz key" in e for e in errs)


def test_manifest_bad_bool_type():
    m = dict(MINIMAL)
    m["fuzz"] = {"expected_crash": "truu"}
    errs = hc.validate_manifest(m)
    assert any("expected_crash" in e for e in errs)


def test_manifest_bad_engine_name():
    m = dict(MINIMAL)
    m["engines"] = ["libfuzzr"]
    errs = hc.validate_manifest(m)
    assert any("unknown engine" in e for e in errs)


def test_manifest_timeout_bounds():
    m = dict(MINIMAL)
    m["fuzz"] = {"timeout_sec": 99999}
    errs = hc.validate_manifest(m)
    assert any("timeout_sec" in e for e in errs)


def test_manifest_bool_not_int():
    m = dict(MINIMAL)
    m["fuzz"] = {"max_len": True}
    errs = hc.validate_manifest(m)
    assert any("max_len" in e for e in errs)


def test_manifest_missing_name():
    m = dict(MINIMAL)
    del m["name"]
    errs = hc.validate_manifest(m)
    assert any("name" in e for e in errs)


def test_parse_stats_normal_and_fork():
    out = "#2 INITED cov: 2 ft: 3\n#157 NEW cov: 4 ft: 5\n#248790: cov: 12 ft: 12\n"
    cov, ft, _ = hc.parse_libfuzzer_stats(out)
    assert cov == 12
    assert ft == 12


def test_achieved_runs():
    assert hc.achieved_runs("#1 INITED cov: 1 ft: 1\n#2000 DONE\n") == 2000


def test_classify_run_kinds():
    assert hc.classify_run(0, "INFO: all fine") is None
    assert hc.classify_run(71, "ERROR: libFuzzer: out-of-memory") == "oom"
    assert hc.classify_run(70, "ERROR: libFuzzer: timeout") == "timeout"
    assert hc.classify_run(0, "x.c:3:5: runtime error: signed integer overflow") == "ubsan"
    assert hc.classify_run(1, "ERROR: AddressSanitizer: heap-buffer-overflow") == "asan-crash"
    assert hc.classify_run(-124, "AIFUZZ-TIMEOUT: exceeded") == "wall-timeout"


ASAN_OUT = """==123==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffe
WRITE of size 18
    #0 0x55d1 in process_special fuzz_target.c:42
    #1 0x55d2 in process_chunk fuzz_target.c:60
    #2 0x55d3 in LLVMFuzzerTestOneInput fuzz_target.c:88
"""


def test_classify_crash_output_asan():
    cls, frames = hc.classify_crash_output(ASAN_OUT)
    assert cls == "asan-stack-buffer-overflow"
    assert len(frames) == 3
    assert "process_special" in frames[0]


def test_classify_crash_output_ubsan():
    out = "x.c:9:5: runtime error: signed integer overflow\nSUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow at x.c:9\n"
    cls, frames = hc.classify_crash_output(out)
    assert cls == "ubsan"
    assert frames[0].startswith("signed-integer-overflow")


def test_stack_hash_stable():
    a = hc.stack_hash("asan-x", ["f1", "f2", "f3", "f4"])
    b = hc.stack_hash("asan-x", ["f1", "f2", "f3"])
    c = hc.stack_hash("asan-y", ["f1", "f2", "f3"])
    assert a == b
    assert a != c


def test_strip_c_comments():
    src = "int x; // exit( in comment\n/* block with rand() */ int y;\n"
    stripped = hc.strip_c_comments(src)
    assert "exit(" not in stripped
    assert "rand()" not in stripped
    assert stripped.count("\n") == src.count("\n")
    assert "int x;" in stripped
    assert "int y;" in stripped


def test_strip_c_comments_blanks_string_contents():
    src = 'const char *s = "never call exit( or system( here";\n'
    stripped = hc.strip_c_comments(src)
    assert "exit(" not in stripped
    assert "system(" not in stripped
    assert stripped.count('"') == 2
    assert "const char *s =" in stripped


def test_strip_c_comments_line_continuation():
    src = "// comment continues \\\nexit(1); still a comment\nint x;\n"
    stripped = hc.strip_c_comments(src)
    assert "exit" not in stripped
    assert "int x;" in stripped


def test_manifest_expected_crash_requires_address():
    m = dict(MINIMAL)
    m["sanitizers"] = ["undefined"]
    m["fuzz"] = {"expected_crash": True}
    errs = hc.validate_manifest(m)
    assert any("address" in e for e in errs)


def test_manifest_expected_crash_with_address_ok():
    m = dict(MINIMAL)
    m["fuzz"] = {"expected_crash": True}
    assert hc.validate_manifest(m) == []


def test_classify_crash_output_wall_timeout():
    cls, frames = hc.classify_crash_output("AIFUZZ-TIMEOUT: exceeded wall guard\n")
    assert cls == "wall-timeout"


def test_lint_catches_exit_not_comment(tmp_path):
    src = tmp_path / "fuzz_target.c"
    src.write_text("extern int LLVMFuzzerTestOneInput;\nint f(void){ return 0; }\nint LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){ if(d) exit(1); /* exit( ok in comment */ return f(); }\n", encoding="utf-8")
    manifest = {"name": "t", "sources": ["fuzz_target.c"]}
    findings = hc.lint_target(tmp_path, manifest)
    exits = [f for f in findings if "exit()" in f["message"]]
    assert len(exits) == 1
    lines = [f["line"] for f in exits]
    assert lines == [3]


def test_lint_catches_longjmp_and_exit_underscore(tmp_path):
    src = tmp_path / "fuzz_target.c"
    src.write_text("int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){ _exit(0); longjmp(0,0); return 0; }\n", encoding="utf-8")
    manifest = {"name": "t", "sources": ["fuzz_target.c"]}
    findings = hc.lint_target(tmp_path, manifest)
    msgs = " ".join(f["message"] for f in findings)
    assert "_exit()" in msgs
    assert "longjmp" in msgs


def test_load_manifest_missing_seeds_dir(tmp_path):
    (tmp_path / "manifest.yaml").write_text(
        "name: t\ndescription: d\nlanguage: c\nsources: [fuzz_target.c]\n"
        "engines: [libfuzzer]\nsanitizers: [address]\n"
        "fuzz:\n  seeds: nonexistent_seeds\n",
        encoding="utf-8")
    (tmp_path / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n",
        encoding="utf-8")
    with pytest.raises(hc.ManifestError) as exc:
        hc.load_manifest(tmp_path)
    assert "seeds dir missing" in str(exc.value)


def test_load_manifest_rejects_unknown_yaml(tmp_path):
    (tmp_path / "manifest.yaml").write_text(
        "name: t\ndescription: d\nlanguage: c\nsources: [fuzz_target.c]\n"
        "engines: [libfuzzer]\nsanitizers: [address]\nfuzz:\n  expected_crashh: true\n",
        encoding="utf-8")
    (tmp_path / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n",
        encoding="utf-8")
    with pytest.raises(hc.ManifestError) as exc:
        hc.load_manifest(tmp_path)
    assert "expected_crashh" in str(exc.value)


def test_load_manifest_missing_dict_file(tmp_path):
    (tmp_path / "manifest.yaml").write_text(
        "name: t\ndescription: d\nlanguage: c\nsources: [fuzz_target.c]\n"
        "engines: [libfuzzer]\nsanitizers: [address]\n"
        "fuzz:\n  dict: nope.txt\n",
        encoding="utf-8")
    (tmp_path / "fuzz_target.c").write_text(
        "int LLVMFuzzerTestOneInput(const unsigned char*d,unsigned long s){return 0;}\n",
        encoding="utf-8")
    with pytest.raises(hc.ManifestError) as exc:
        hc.load_manifest(tmp_path)
    assert "dictionary file missing" in str(exc.value)
