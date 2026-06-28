#!/usr/bin/env python3
"""Lightweight regression tests for the offline P7S signing service.

This script intentionally avoids pytest so it can be run in a clean enterprise
desktop environment with only the application's runtime dependencies installed.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
LOCAL_PACKAGES = APP_DIR / ".python-packages"
if LOCAL_PACKAGES.is_dir():
    sys.path.insert(0, str(LOCAL_PACKAGES))

from signing_service import AuditLogger, InputFileError, OutputFileError, P7SSigningService


KEY_FILE = APP_DIR / "private_key.pem"
CERT_FILE = APP_DIR / "user.crt"
SAMPLE_FILE = APP_DIR / "test.txt"


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def test_normal_signing_and_verification(tmpdir: Path) -> None:
    service = P7SSigningService(KEY_FILE, CERT_FILE)
    output = tmpdir / "sample.p7s"
    progress_events: list[tuple[int, int]] = []

    result = service.sign_file(SAMPLE_FILE, output, lambda done, total: progress_events.append((done, total)), overwrite=False)

    assert_true(result.path == output, "签名结果路径不正确")
    assert_true(output.is_file(), "未生成 p7s 文件")
    assert_true(output.stat().st_size > 0, "p7s 文件为空")
    assert_true(result.verified is True, "自动验签结果不是 True")
    assert_true(len(result.source_sha256) == 64, "原文件 SHA256 长度不正确")
    assert_true(len(result.signature_sha256) == 64, "签名文件 SHA256 长度不正确")
    assert_true(bool(progress_events), "未收到读取进度回调")

    service.verify_detached_signature(SAMPLE_FILE, output)


def test_certificate_info() -> None:
    info = P7SSigningService(KEY_FILE, CERT_FILE).get_signing_certificate_info()

    assert_true(bool(info.subject), "证书 subject 为空")
    assert_true(bool(info.issuer), "证书 issuer 为空")
    assert_true(info.status in {"有效", "未生效", "已过期"}, "证书状态非法")
    assert_true(len(info.sha256_fingerprint) == 64, "证书 SHA256 指纹长度不正确")


def test_audit_log(tmpdir: Path) -> None:
    service = P7SSigningService(KEY_FILE, CERT_FILE)
    output = tmpdir / "audit.p7s"
    result = service.sign_file(SAMPLE_FILE, output, overwrite=False)
    log_path = tmpdir / "audit.jsonl"

    AuditLogger(log_path).record_success(SAMPLE_FILE, result)
    payload = json.loads(log_path.read_text(encoding="utf-8").splitlines()[-1])

    assert_true(payload["event"] == "sign_success", "审计日志事件类型错误")
    assert_true(payload["verified"] is True, "审计日志未记录验签结果")
    assert_true(payload["source_sha256"] == result.source_sha256, "审计日志原文件摘要不一致")


def test_missing_input_file(tmpdir: Path) -> None:
    try:
        P7SSigningService(KEY_FILE, CERT_FILE).sign_file(tmpdir / "missing.txt", tmpdir / "missing.p7s")
    except InputFileError:
        return
    raise AssertionError("输入文件不存在时未抛出 InputFileError")


def test_missing_output_directory(tmpdir: Path) -> None:
    try:
        P7SSigningService(KEY_FILE, CERT_FILE).sign_file(SAMPLE_FILE, tmpdir / "not-exists" / "x.p7s")
    except OutputFileError:
        return
    raise AssertionError("输出目录不存在时未抛出 OutputFileError")


def main() -> int:
    if not KEY_FILE.is_file() or not CERT_FILE.is_file() or not SAMPLE_FILE.is_file():
        print("测试前置文件缺失：需要 private_key.pem、user.crt、test.txt", file=sys.stderr)
        return 2

    tests = [
        test_normal_signing_and_verification,
        test_certificate_info,
        test_audit_log,
        test_missing_input_file,
        test_missing_output_directory,
    ]

    with tempfile.TemporaryDirectory(prefix="p7s-tests-") as directory:
        tmpdir = Path(directory)
        for test in tests:
            if test is test_certificate_info:
                test()
            else:
                test(tmpdir)
            print(f"PASS {test.__name__}")
    print("全部签名服务回归测试通过。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
