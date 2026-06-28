#!/usr/bin/env python3
"""PySide6 UI layer for the offline P7S signing service.

This module deliberately contains no cryptographic operations.  All certificate,
private-key, CMS generation and atomic-output concerns remain in signing_service.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", APP_DIR))
if getattr(sys, "frozen", False) and sys.platform == "darwin":
    RUNTIME_DIR = Path.home() / "Library" / "Application Support" / "P7S离线文件数字签名工具"
elif getattr(sys, "frozen", False):
    RUNTIME_DIR = Path(sys.executable).resolve().parent
else:
    RUNTIME_DIR = APP_DIR
LOCAL_PACKAGES = APP_DIR / ".python-packages"
if LOCAL_PACKAGES.is_dir():
    sys.path.insert(0, str(LOCAL_PACKAGES))

from PySide6.QtCore import QStandardPaths, Qt, QThread, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QFrame,
    QGraphicsDropShadowEffect,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QProgressBar,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from signing_service import (
    AuditLogger,
    CertificateExpiredError,
    MAX_RECOMMENDED_FILE_SIZE,
    InputFileError,
    KeyCertificateMismatchError,
    OutputFileError,
    P7SSigningService,
    SigningResult,
    SigningError,
    SigningMaterialError,
    VerificationError,
)


KEY_FILE = RESOURCE_DIR / "private_key.pem"
CERT_FILE = RESOURCE_DIR / "user.crt"
AUDIT_LOG_FILE = RUNTIME_DIR / "logs" / "signing_audit.jsonl"
APP_VERSION = "1.0.0"


class SigningWorker(QThread):
    """Runs the synchronous signing service away from Qt's GUI thread."""

    progress_changed = Signal(int, str)
    succeeded = Signal(object)
    failed = Signal(object)

    def __init__(self, source: Path, destination: Path, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.source = source
        self.destination = destination

    def run(self) -> None:
        """Invoke the service and forward state only through thread-safe signals."""
        def report_read_progress(done: int, total: int) -> None:
            # Byte-level reading occupies 0–80%; service signing then completes it.
            percent = 80 if total == 0 else min(80, int(done * 80 / total))
            self.progress_changed.emit(percent, "正在读取文件…")

        try:
            self.progress_changed.emit(3, "正在校验证书与私钥…")
            service = P7SSigningService(KEY_FILE, CERT_FILE)
            result = service.sign_file(
                self.source, self.destination, report_read_progress, overwrite=True
            )
            self.progress_changed.emit(92, "正在自动验签…")
            self.progress_changed.emit(100, "签名与验签完成")
            AuditLogger(AUDIT_LOG_FILE).record_success(self.source, result)
            self.succeeded.emit(result)
        except SigningError as exc:
            AuditLogger(AUDIT_LOG_FILE).record_failure(self.source, self.destination, exc)
            self.failed.emit(exc)
        except Exception as exc:
            wrapped = SigningError("发生未预期的内部错误；未生成或覆盖目标文件。")
            AuditLogger(AUDIT_LOG_FILE).record_failure(self.source, self.destination, exc)
            self.failed.emit(wrapped)


class P7SSignerWindow(QMainWindow):
    """Interaction layer: file dialogs, UI state, and worker lifecycle only."""

    def __init__(self) -> None:
        super().__init__()
        self.input_file: Path | None = None
        self.last_output_file: Path | None = None
        self.signing_completed = False
        self.certificate_ready = False
        self.worker: SigningWorker | None = None
        self.setWindowTitle("P7S 离线文件数字签名工具")
        self.setMinimumSize(760, 540)
        self.resize(860, 590)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(56, 46, 56, 46)
        outer.addStretch(1)

        self.card = QFrame()
        self.card.setObjectName("signingCard")
        self.card.setMaximumWidth(680)
        self.card.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        shadow = QGraphicsDropShadowEffect(self.card)
        shadow.setBlurRadius(34)
        shadow.setOffset(0, 12)
        shadow.setColor(QColor(0, 0, 0, 86))
        self.card.setGraphicsEffect(shadow)
        outer.addWidget(self.card, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(1)

        layout = QVBoxLayout(self.card)
        layout.setContentsMargins(44, 38, 44, 34)
        layout.setSpacing(0)
        title = QLabel("P7S 离线文件数字签名工具")
        title.setObjectName("title")
        subtitle = QLabel("本地密钥离线签名，文件不上传网络")
        subtitle.setObjectName("subtitle")
        layout.addWidget(title)
        layout.addWidget(subtitle)
        layout.addSpacing(24)

        self.cert_label = QLabel("正在读取签名证书信息…")
        self.cert_label.setObjectName("certInfo")
        self.cert_label.setWordWrap(True)
        layout.addWidget(self.cert_label)
        layout.addSpacing(22)

        # The readonly line edit is deliberately used as a file-path field: it
        # shows only the file name to keep the card clean; the full absolute path
        # is available via tooltip and kept in self.input_file for signing.
        file_row = QHBoxLayout()
        file_row.setSpacing(10)
        self.path_edit = QLineEdit("尚未选择文件")
        self.path_edit.setObjectName("filePath")
        self.path_edit.setReadOnly(True)
        self.path_edit.setPlaceholderText("尚未选择文件")
        self.choose_button = QPushButton("选择文件")
        self.choose_button.setObjectName("secondaryButton")
        self.choose_button.clicked.connect(self.choose_file)
        self.clear_button = QPushButton("清空")
        self.clear_button.setObjectName("secondaryButton")
        self.clear_button.setEnabled(False)
        self.clear_button.clicked.connect(self.clear_file)
        file_row.addWidget(self.path_edit, 1)
        file_row.addWidget(self.choose_button)
        file_row.addWidget(self.clear_button)
        layout.addLayout(file_row)

        self.file_info = QLabel("支持任意文件格式")
        self.file_info.setObjectName("fileInfo")
        layout.addWidget(self.file_info)
        layout.addSpacing(28)

        status_row = QHBoxLayout()
        self.status_label = QLabel("准备就绪")
        self.status_label.setObjectName("status")
        self.percent_label = QLabel("")
        self.percent_label.setObjectName("percent")
        self.percent_label.setFixedWidth(48)
        self.percent_label.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        status_row.addWidget(self.status_label)
        status_row.addStretch(1)
        status_row.addWidget(self.percent_label)
        layout.addLayout(status_row)
        layout.addSpacing(8)
        self.progress = QProgressBar()
        self.progress.setObjectName("progress")
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        layout.addWidget(self.progress)
        layout.addSpacing(23)

        footer = QHBoxLayout()
        footer.setSpacing(10)
        self.security_note = QLabel(f"离线安全签名 · 密钥本地存储，数据不上传 · v{APP_VERSION}")
        self.security_note.setObjectName("securityNote")
        self.open_folder_button = QPushButton("打开所在文件夹")
        self.open_folder_button.setObjectName("secondaryButton")
        self.open_folder_button.setEnabled(False)
        self.open_folder_button.clicked.connect(self.open_output_folder)
        footer.addWidget(self.security_note)
        footer.addStretch(1)
        footer.addWidget(self.open_folder_button)
        self.sign_button = QPushButton("生成 P7S 签名")
        self.sign_button.setObjectName("primaryButton")
        self.sign_button.setEnabled(False)
        self.sign_button.clicked.connect(self.choose_destination_and_sign)
        footer.addWidget(self.sign_button)
        layout.addLayout(footer)
        self.load_certificate_summary()

    def load_certificate_summary(self) -> None:
        try:
            info = P7SSigningService(KEY_FILE, CERT_FILE).get_signing_certificate_info()
        except SigningError as exc:
            self.certificate_ready = False
            self.cert_label.setText(f"证书状态：不可用 · {exc}")
            self.cert_label.setStyleSheet("color: #B04A4A;")
            self.set_status("签名证书不可用", "error")
            self.sign_button.setEnabled(False)
            return
        self.certificate_ready = info.status == "有效"
        valid_to = info.not_valid_after.astimezone().strftime("%Y-%m-%d")
        fingerprint = self.compact_fingerprint(info.sha256_fingerprint)
        self.cert_label.setText(
            f"签名证书：{info.subject} · {info.status} · 有效期至 {valid_to} · SHA256 {fingerprint}"
        )
        if self.certificate_ready:
            self.cert_label.setStyleSheet("color: #8A929B;")
        else:
            self.cert_label.setStyleSheet("color: #B04A4A;")
            self.set_status("签名证书不可用", "error")

    def choose_file(self) -> None:
        choice, _ = QFileDialog.getOpenFileName(self, "选择需要签名的文件", str(Path.home()), "所有文件 (*)")
        if not choice:
            return
        candidate = Path(choice).expanduser()
        try:
            size = self.validate_input_file(candidate)
        except (OSError, ValueError) as exc:
            self.set_status("文件导入失败", "error")
            QMessageBox.critical(self, "文件导入失败", str(exc))
            return
        self.input_file = candidate.resolve()
        self.last_output_file = None
        self.signing_completed = False
        self.path_edit.setText(self.input_file.name)
        self.path_edit.setToolTip(str(self.input_file))
        warning = " · 大文件签名可能占用较多内存" if size > MAX_RECOMMENDED_FILE_SIZE else ""
        self.file_info.setText(f"{self.format_size(size)} · 文件已就绪{warning}")
        self.clear_button.setEnabled(True)
        self.open_folder_button.setEnabled(False)
        self.sign_button.setEnabled(self.certificate_ready)
        if self.certificate_ready:
            self.set_status("文件已就绪", "success")
        else:
            self.set_status("文件已选择，但证书不可用", "error")

    def clear_file(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.input_file = None
        self.last_output_file = None
        self.signing_completed = False
        self.path_edit.setText("尚未选择文件")
        self.path_edit.setToolTip("")
        self.file_info.setText("支持任意文件格式")
        self.progress.setValue(0)
        self.percent_label.setText("")
        self.clear_button.setEnabled(False)
        self.open_folder_button.setEnabled(False)
        self.sign_button.setEnabled(False)
        self.set_status("准备就绪", "idle")

    def choose_destination_and_sign(self) -> None:
        if not self.certificate_ready:
            QMessageBox.critical(self, "证书不可用", "当前签名证书或私钥不可用，请修复 private_key.pem / user.crt 后重新启动工具。")
            return
        if not self.input_file:
            QMessageBox.information(self, "尚未选择文件", "请先选择需要签名的文件。")
            return
        try:
            self.validate_input_file(self.input_file)
        except (OSError, ValueError) as exc:
            self.set_status("文件不可用", "error")
            QMessageBox.critical(self, "文件不可用", f"签名前检查失败：\n{exc}")
            return
        desktop = QStandardPaths.writableLocation(QStandardPaths.StandardLocation.DesktopLocation) or str(Path.home())
        proposed = f"{self.input_file.name}.p7s"
        target, _ = QFileDialog.getSaveFileName(self, "保存 P7S 签名文件", str(Path(desktop) / proposed), "P7S 签名文件 (*.p7s);;所有文件 (*)")
        if not target:
            return
        output = Path(target)
        if output.suffix.lower() != ".p7s":
            output = output.with_suffix(".p7s")
        if output.exists():
            answer = QMessageBox.question(self, "确认覆盖", f"以下文件已存在：\n{output.name}\n\n是否替换它？", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No, QMessageBox.StandardButton.No)
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.start_signing(output)

    def start_signing(self, output: Path) -> None:
        self.set_busy(True)
        self.set_status("正在读取文件…", "working", 0)
        self.worker = SigningWorker(self.input_file, output, self)
        self.worker.progress_changed.connect(self.set_status)
        self.worker.succeeded.connect(self.on_signing_succeeded)
        self.worker.failed.connect(self.on_signing_failed)
        self.worker.finished.connect(self.on_worker_finished)
        self.worker.start()

    def on_signing_succeeded(self, result: SigningResult) -> None:
        self.last_output_file = result.path
        self.signing_completed = True
        self.set_status("签名已安全保存，自动验签通过", "success", 100)
        self.open_folder_button.setEnabled(True)
        self.sign_button.setEnabled(False)
        QMessageBox.information(
            self,
            "签名完成",
            "P7S 签名文件已保存，并已完成自动验签。\n\n"
            f"保存位置：\n{result.path}\n\n"
            f"原文件 SHA256：\n{result.source_sha256}",
        )

    def on_signing_failed(self, error: SigningError) -> None:
        self.set_status("签名失败", "error", 0)
        QMessageBox.critical(self, "签名失败", self.friendly_error(error))

    def on_worker_finished(self) -> None:
        self.set_busy(False)
        if self.worker:
            self.worker.deleteLater()
            self.worker = None

    def set_busy(self, busy: bool) -> None:
        """Locks both user actions to prevent concurrent signing submissions."""
        self.choose_button.setEnabled(not busy)
        self.clear_button.setEnabled(not busy and self.input_file is not None)
        self.open_folder_button.setEnabled(not busy and self.last_output_file is not None)
        self.sign_button.setEnabled(not busy and self.input_file is not None and not self.signing_completed and self.certificate_ready)

    def set_status(self, message: str, state: str, percent: int | None = None) -> None:
        color = {"working": "#246BCE", "success": "#387A5A", "error": "#B04A4A"}.get(state, "#7C858F")
        self.status_label.setText(message)
        self.status_label.setStyleSheet(f"color: {color};")
        if percent is not None:
            self.progress.setValue(percent)
            self.percent_label.setText(f"{percent}%" if percent else "")

    def open_output_folder(self) -> None:
        if not self.last_output_file:
            return
        folder = self.last_output_file.parent
        if not folder.exists():
            QMessageBox.warning(self, "无法打开文件夹", "签名文件所在文件夹不存在或已被移动。")
            return
        QDesktopServices.openUrl(QUrl.fromLocalFile(str(folder)))

    @staticmethod
    def validate_input_file(candidate: Path) -> int:
        if not candidate.exists():
            raise ValueError("所选文件不存在，可能已被移动或删除。")
        if not candidate.is_file():
            raise ValueError("请选择普通文件，不能选择文件夹。")
        if not os.access(candidate, os.R_OK):
            raise ValueError("没有读取该文件的权限。")
        return candidate.stat().st_size

    @staticmethod
    def format_size(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
            size /= 1024
        return ""

    @staticmethod
    def friendly_error(error: SigningError) -> str:
        if isinstance(error, CertificateExpiredError):
            return "证书有效期异常。请更换有效的签名证书。"
        if isinstance(error, KeyCertificateMismatchError):
            return "私钥与证书不匹配。请检查签名材料。"
        if isinstance(error, VerificationError):
            return f"{error}\n\n建议：请重新生成签名；如果仍失败，请检查证书、私钥和原文件是否被替换。"
        if isinstance(error, (SigningMaterialError, InputFileError, OutputFileError)):
            return str(error)
        return str(error)

    @staticmethod
    def compact_fingerprint(fingerprint: str) -> str:
        return f"{fingerprint[:8]}…{fingerprint[-8:]}" if len(fingerprint) > 20 else fingerprint


QSS = """
QWidget#root { background: #24272C; }
QFrame#signingCard { background: rgba(248, 249, 250, 242); border-radius: 16px; }
QLabel#title { color: #20242A; font-size: 27px; font-weight: 800; letter-spacing: -0.2px; }
QLabel#subtitle { color: #8A929B; font-size: 13px; padding-top: 8px; }
QLabel#certInfo {
    background: #F0F3F6;
    border-radius: 10px;
    color: #8A929B;
    font-size: 11px;
    padding: 9px 12px;
}
QLineEdit#filePath {
    background: #FFFFFF;
    border: 1px solid #DDE1E6;
    border-radius: 10px;
    color: #20242A;
    padding: 10px 13px;
    font-size: 13px;
    selection-background-color: #DCE9FA;
}
QLineEdit#filePath:focus { border: 1px solid #CDD3DA; }
QLabel#fileInfo { color: #8A929B; font-size: 11px; padding-top: 8px; }
QLabel#status, QLabel#percent { color: #8A929B; font-size: 12px; }
QLabel#securityNote { color: #B3B9C0; font-size: 11px; }
QProgressBar#progress { background: #E5E8EB; border: none; border-radius: 5px; min-height: 8px; max-height: 8px; }
QProgressBar#progress::chunk { background: #246BCE; border-radius: 5px; }
QPushButton { border: none; border-radius: 10px; padding: 10px 18px; font-size: 13px; font-weight: 600; min-height: 18px; }
QPushButton#primaryButton { background: #246BCE; color: #FFFFFF; }
QPushButton#primaryButton:hover { background: #1D5FB8; }
QPushButton#primaryButton:pressed { background: #194F98; }
QPushButton#primaryButton:disabled { background: rgba(184, 190, 198, 150); color: #F7F8F9; }
QPushButton#secondaryButton { background: #EEF1F4; color: #20242A; }
QPushButton#secondaryButton:hover { background: #E2E6EA; }
QPushButton#secondaryButton:pressed { background: #D8DDE3; }
QPushButton#secondaryButton:disabled { background: rgba(238, 241, 244, 150); color: #A2A9B1; }
"""


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    window = P7SSignerWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
