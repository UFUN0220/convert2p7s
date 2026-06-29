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

from PySide6.QtCore import QEvent, QStandardPaths, Qt, QThread, QUrl, Signal
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
APP_VERSION = "1.2.2"


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
        self.setMinimumSize(820, 620)
        self.resize(920, 660)
        self.setAcceptDrops(True)
        self._build_ui()

    def configure_drop_target(self, widget: QWidget) -> None:
        widget.setAcceptDrops(True)
        widget.installEventFilter(self)

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.configure_drop_target(root)
        self.setCentralWidget(root)
        outer = QVBoxLayout(root)
        outer.setContentsMargins(64, 52, 64, 52)
        outer.addStretch(1)

        self.card = QFrame()
        self.card.setObjectName("signingCard")
        self.configure_drop_target(self.card)
        self.card.setMaximumWidth(740)
        self.card.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Fixed)
        shadow = QGraphicsDropShadowEffect(self.card)
        shadow.setBlurRadius(42)
        shadow.setOffset(0, 18)
        shadow.setColor(QColor(0, 0, 0, 96))
        self.card.setGraphicsEffect(shadow)
        outer.addWidget(self.card, 0, Qt.AlignmentFlag.AlignHCenter)
        outer.addStretch(1)

        layout = QVBoxLayout(self.card)
        layout.setContentsMargins(46, 42, 46, 36)
        layout.setSpacing(0)

        header_row = QHBoxLayout()
        header_row.setSpacing(16)
        accent = QFrame()
        accent.setObjectName("accentRail")
        accent.setFixedSize(4, 56)
        header_text = QVBoxLayout()
        header_text.setSpacing(0)
        title = QLabel("P7S 离线文件数字签名工具")
        title.setObjectName("title")
        subtitle = QLabel("本地密钥离线签名，文件不上传网络")
        subtitle.setObjectName("subtitle")
        header_text.addWidget(title)
        header_text.addWidget(subtitle)
        header_row.addWidget(accent)
        header_row.addLayout(header_text, 1)
        layout.addLayout(header_row)
        layout.addSpacing(26)

        self.cert_label = QLabel("正在读取签名证书信息…")
        self.cert_label.setObjectName("certInfo")
        self.cert_label.setWordWrap(True)
        layout.addWidget(self.cert_label)
        layout.addSpacing(18)

        self.file_zone = QFrame()
        self.file_zone.setObjectName("fileDropZone")
        self.configure_drop_target(self.file_zone)
        file_zone_layout = QVBoxLayout(self.file_zone)
        file_zone_layout.setContentsMargins(18, 16, 18, 15)
        file_zone_layout.setSpacing(0)
        file_heading = QLabel("选择待签名文件")
        file_heading.setObjectName("sectionTitle")
        file_zone_layout.addWidget(file_heading)
        file_zone_layout.addSpacing(11)

        # The readonly line edit is deliberately used as a file-path field: it
        # shows only the file name to keep the card clean; the full absolute path
        # is available via tooltip and kept in self.input_file for signing.
        file_row = QHBoxLayout()
        file_row.setSpacing(12)
        self.path_edit = QLineEdit("尚未选择文件")
        self.path_edit.setObjectName("filePath")
        self.path_edit.setReadOnly(True)
        self.path_edit.setAcceptDrops(False)
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
        file_zone_layout.addLayout(file_row)

        self.file_info = QLabel("支持任意文件格式 · 可将单个本地文件拖拽到此区域")
        self.file_info.setObjectName("fileInfo")
        file_zone_layout.addWidget(self.file_info)
        layout.addWidget(self.file_zone)
        layout.addSpacing(18)

        self.status_panel = QFrame()
        self.status_panel.setObjectName("statusPanel")
        status_panel_layout = QVBoxLayout(self.status_panel)
        status_panel_layout.setContentsMargins(18, 15, 18, 17)
        status_panel_layout.setSpacing(0)

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
        status_panel_layout.addLayout(status_row)
        status_panel_layout.addSpacing(10)
        self.progress = QProgressBar()
        self.progress.setObjectName("progress")
        self.progress.setRange(0, 100)
        self.progress.setTextVisible(False)
        status_panel_layout.addWidget(self.progress)
        layout.addWidget(self.status_panel)
        layout.addSpacing(22)

        footer = QHBoxLayout()
        footer.setSpacing(12)
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

    def eventFilter(self, watched: object, event: QEvent) -> bool:
        """Enable drag-and-drop on the card without creating a custom widget."""
        if event.type() in (QEvent.Type.DragEnter, QEvent.Type.DragMove):
            return self.handle_drag_enter_or_move(event)
        if event.type() == QEvent.Type.DragLeave:
            self.set_drag_highlight(False)
            self.restore_idle_status_after_drag()
            return False
        if event.type() == QEvent.Type.Drop:
            return self.handle_drop(event)
        return super().eventFilter(watched, event)

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
        self.select_input_file(Path(choice).expanduser(), show_dialog=True)

    def select_input_file(self, candidate: Path, *, show_dialog: bool) -> None:
        try:
            size = self.validate_input_file(candidate)
        except (OSError, ValueError) as exc:
            self.set_status("文件导入失败", "error")
            if show_dialog:
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

    def handle_drag_enter_or_move(self, event: QEvent) -> bool:
        if self.worker and self.worker.isRunning():
            event.ignore()
            self.set_drag_highlight(False)
            return True
        if self.extract_single_local_drop_path(event, update_status=False) is None:
            event.ignore()
            self.set_drag_highlight(False)
            return True
        event.acceptProposedAction()
        self.set_drag_highlight(True)
        self.file_info.setText("释放鼠标以上传文件")
        self.set_status("准备接收文件", "working")
        return True

    def handle_drop(self, event: QEvent) -> bool:
        self.set_drag_highlight(False)
        self.file_info.setText("支持任意文件格式 · 可将单个本地文件拖拽到此区域")
        candidate = self.extract_single_local_drop_path(event, update_status=True)
        if candidate is None:
            event.ignore()
            return True
        event.acceptProposedAction()
        self.select_input_file(candidate, show_dialog=False)
        return True

    def extract_single_local_drop_path(self, event: QEvent, *, update_status: bool) -> Path | None:
        mime = event.mimeData()
        if not mime.hasUrls():
            if update_status:
                self.set_status("请拖入本地文件", "error")
            return None
        urls = mime.urls()
        local_urls = [url for url in urls if url.isLocalFile()]
        if len(local_urls) != len(urls):
            if update_status:
                self.set_status("仅支持拖入本地文件", "error")
            return None
        if len(local_urls) != 1:
            if update_status:
                self.set_status("当前仅支持拖入单个文件", "error")
            return None
        return Path(local_urls[0].toLocalFile()).expanduser()

    def set_drag_highlight(self, active: bool) -> None:
        for widget in (self.card, self.file_zone, self.path_edit):
            widget.setProperty("dragActive", active)
            widget.style().unpolish(widget)
            widget.style().polish(widget)
            widget.update()
        self.file_info.setProperty("dragActive", active)
        self.file_info.style().unpolish(self.file_info)
        self.file_info.style().polish(self.file_info)
        self.file_info.update()

    def restore_idle_status_after_drag(self) -> None:
        if not self.input_file:
            self.file_info.setText("支持任意文件格式 · 可将单个本地文件拖拽到此区域")
        if self.worker and self.worker.isRunning():
            return
        if self.input_file and self.certificate_ready:
            self.set_status("文件已就绪", "success")
        elif self.input_file:
            self.set_status("文件已选择，但证书不可用", "error")
        elif self.certificate_ready:
            self.set_status("准备就绪", "idle")
        else:
            self.set_status("签名证书不可用", "error")

    def clear_file(self) -> None:
        if self.worker and self.worker.isRunning():
            return
        self.input_file = None
        self.last_output_file = None
        self.signing_completed = False
        self.path_edit.setText("尚未选择文件")
        self.path_edit.setToolTip("")
        self.file_info.setText("支持任意文件格式 · 可将单个本地文件拖拽到此区域")
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
        color = {"working": "#0A84FF", "success": "#248A3D", "error": "#D70015"}.get(state, "#7C858F")
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
QWidget#root { background: #17202B; font-family: "PingFang SC", "Microsoft YaHei", "Segoe UI", "Helvetica Neue", Arial; }
QFrame#signingCard {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #FBFCFF, stop:0.52 #F7F9FC, stop:1 #F3F8F7);
    border: 1px solid rgba(255, 255, 255, 180);
    border-radius: 22px;
}
QFrame#signingCard[dragActive="true"] { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #F7FBFF, stop:1 #F1FFF9); border: 1px solid #8EC5FF; }
QFrame#accentRail { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0A84FF, stop:0.56 #64D2FF, stop:1 #30D158); border-radius: 2px; }
QLabel#title { color: #161B22; font-size: 29px; font-weight: 800; letter-spacing: -0.4px; }
QLabel#subtitle { color: #7F8893; font-size: 13px; padding-top: 9px; letter-spacing: 0.1px; }
QLabel#certInfo {
    background: #F1F7FF;
    border: 1px solid #DCEBFF;
    border-radius: 13px;
    color: #627386;
    font-size: 11px;
    padding: 11px 14px;
}
QFrame#fileDropZone {
    background: #FFFFFF;
    border: 1px solid #DFE9F4;
    border-radius: 16px;
}
QFrame#fileDropZone[dragActive="true"] {
    background: #F2FAFF;
    border: 1px solid #0A84FF;
}
QLabel#sectionTitle {
    color: #2A313B;
    font-size: 12px;
    font-weight: 700;
    letter-spacing: 0.2px;
}
QLineEdit#filePath {
    background: #FAFCFF;
    border: 1px solid #DEE8F2;
    border-radius: 12px;
    color: #1F2732;
    padding: 12px 14px;
    font-size: 13px;
    selection-background-color: #DCEEFF;
}
QLineEdit#filePath:focus { border: 1px solid #C9D2DC; }
QLineEdit#filePath[dragActive="true"] { border: 1px solid #0A84FF; background: #FFFFFF; }
QLabel#fileInfo { color: #8B95A1; font-size: 11px; padding-top: 7px; }
QLabel#fileInfo[dragActive="true"] { color: #0A84FF; font-weight: 600; }
QFrame#statusPanel {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #F0F7FF, stop:0.55 #F5F3FF, stop:1 #F1FFF7);
    border: 1px solid #E1EAF3;
    border-radius: 15px;
}
QLabel#status { color: #7B8490; font-size: 12px; font-weight: 600; }
QLabel#percent { color: #7B8490; font-size: 12px; font-weight: 700; }
QLabel#securityNote { color: #9CA5AF; font-size: 11px; }
QProgressBar#progress { background: #DEE8F2; border: none; border-radius: 5px; min-height: 9px; max-height: 9px; }
QProgressBar#progress::chunk { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0A84FF, stop:0.65 #64D2FF, stop:1 #30D158); border-radius: 5px; }
QPushButton { border: none; border-radius: 12px; padding: 11px 19px; font-size: 13px; font-weight: 700; min-height: 20px; }
QPushButton#primaryButton { background: #0A84FF; color: #FFFFFF; }
QPushButton#primaryButton:hover { background: #0071E3; }
QPushButton#primaryButton:pressed { background: #005BBF; }
QPushButton#primaryButton:disabled { background: #C2CAD4; color: #F7F9FB; }
QPushButton#secondaryButton { background: #F2F6FB; color: #27313D; border: 1px solid #E1EAF4; }
QPushButton#secondaryButton:hover { background: #EAF4FF; }
QPushButton#secondaryButton:pressed { background: #DCEEFF; }
QPushButton#secondaryButton:disabled { background: #F1F4F8; color: #A4ADB8; border: 1px solid #E8ECF1; }
"""


def main() -> int:
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    window = P7SSignerWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
