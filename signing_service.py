"""Independent CMS/PKCS#7 signing service backed by cryptography/OpenSSL bindings."""

from __future__ import annotations

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

_LOCAL_PACKAGES = Path(__file__).resolve().parent / ".python-packages"
if _LOCAL_PACKAGES.is_dir():
    sys.path.insert(0, str(_LOCAL_PACKAGES))

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7


ProgressCallback = Callable[[int, int], None]


class SigningError(Exception):
    """Base exception intended for user-facing signing failures."""


class SigningMaterialError(SigningError):
    pass


class CertificateExpiredError(SigningMaterialError):
    pass


class KeyCertificateMismatchError(SigningMaterialError):
    pass


class InputFileError(SigningError):
    pass


class OutputFileError(SigningError):
    pass


class AlgorithmNotSupportedError(SigningError):
    pass


class P7SSigningService:
    """Creates detached DER PKCS#7 signatures without invoking an executable."""

    def __init__(self, private_key_path: Path, certificate_path: Path) -> None:
        self.private_key_path = Path(private_key_path)
        self.certificate_path = Path(certificate_path)

    def sign_file(
        self, source: Path, destination: Path, progress: ProgressCallback | None = None, *, overwrite: bool = False
    ) -> Path:
        """Sign *source* and atomically publish its detached .p7s file at *destination*.

        The source is deliberately read in chunks to provide byte-accurate read
        progress.  CMS construction itself currently requires a bytes payload in
        cryptography's public API, so the input must fit in memory.
        """
        source, destination = Path(source), Path(destination)
        self._validate_paths(source, destination, overwrite)
        key, certificate = self._load_signing_material()
        content = self._read_with_progress(source, progress)
        try:
            signed = (
                pkcs7.PKCS7SignatureBuilder()
                .set_data(content)
                .add_signer(certificate, key, hashes.SHA256())
                .sign(
                    serialization.Encoding.DER,
                    [
                        pkcs7.PKCS7Options.DetachedSignature,
                        pkcs7.PKCS7Options.Binary,
                        pkcs7.PKCS7Options.NoAttributes,
                    ],
                )
            )
        except UnsupportedAlgorithm as exc:
            raise AlgorithmNotSupportedError("当前 OpenSSL 后端不支持此证书的签名算法。") from exc
        except ValueError as exc:
            raise SigningError(f"无法生成 PKCS#7 签名：{exc}") from exc
        self._atomic_write(destination, signed)
        if progress:
            progress(len(content), len(content))
        return destination

    def _validate_paths(self, source: Path, destination: Path, overwrite: bool) -> None:
        if not source.is_file():
            raise InputFileError("待签名文件不存在，或不是普通文件。")
        if not os.access(source, os.R_OK):
            raise InputFileError("没有读取待签名文件的权限。")
        if not destination.parent.is_dir():
            raise OutputFileError("保存目录不存在。")
        if not os.access(destination.parent, os.W_OK):
            raise OutputFileError("没有写入目标目录的权限。")
        if destination.exists() and not overwrite:
            raise OutputFileError("目标文件已存在；请确认后再执行覆盖。")

    def _load_signing_material(self):
        if not self.private_key_path.is_file() or not self.certificate_path.is_file():
            raise SigningMaterialError("未找到 private_key.pem 或 user.crt。")
        try:
            key = serialization.load_pem_private_key(self.private_key_path.read_bytes(), password=None)
        except TypeError as exc:
            raise SigningMaterialError("私钥受口令保护；当前版本不支持无提示读取此私钥。") from exc
        except (ValueError, OSError) as exc:
            raise SigningMaterialError("私钥文件损坏、格式不正确或无法读取。") from exc
        try:
            certificate = x509.load_pem_x509_certificate(self.certificate_path.read_bytes())
        except (ValueError, OSError) as exc:
            raise SigningMaterialError("证书文件损坏、格式不正确或无法读取。") from exc
        now = datetime.now(timezone.utc)
        if not (certificate.not_valid_before_utc <= now <= certificate.not_valid_after_utc):
            raise CertificateExpiredError("签名证书尚未生效或已过期。")
        key_public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        cert_public = certificate.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        if key_public != cert_public:
            raise KeyCertificateMismatchError("私钥与签名证书不匹配。")
        return key, certificate

    @staticmethod
    def _read_with_progress(source: Path, progress: ProgressCallback | None) -> bytes:
        total, completed, chunks = source.stat().st_size, 0, []
        try:
            with source.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    chunks.append(chunk)
                    completed += len(chunk)
                    if progress:
                        progress(completed, total)
        except OSError as exc:
            raise InputFileError("读取待签名文件时发生错误。") from exc
        if progress and total == 0:
            progress(0, 0)
        return b"".join(chunks)

    @staticmethod
    def _atomic_write(destination: Path, content: bytes) -> None:
        temporary_path: str | None = None
        try:
            fd, temporary_path = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent)
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, destination)
            temporary_path = None
        except OSError as exc:
            raise OutputFileError("写入签名文件失败；请检查磁盘空间和文件夹权限。") from exc
        finally:
            if temporary_path:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
