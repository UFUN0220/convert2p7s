#!/usr/bin/env python3
"""Refined desktop interface for the P7S signing service."""

from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_DIR = Path(__file__).resolve().parent
LOCAL_PACKAGES = APP_DIR / ".python-packages"
if LOCAL_PACKAGES.is_dir():
    sys.path.insert(0, str(LOCAL_PACKAGES))

from signing_service import (  # noqa: E402
    CertificateExpiredError,
    InputFileError,
    KeyCertificateMismatchError,
    OutputFileError,
    P7SSigningService,
    SigningError,
    SigningMaterialError,
)

KEY_FILE, CERT_FILE = APP_DIR / "private_key.pem", APP_DIR / "user.crt"
DESKTOP = Path.home() / "Desktop"
BG, CARD, TEXT, MUTED = "#F5F5F7", "#FFFFFF", "#17171B", "#73737A"
BLUE, BLUE_ACTIVE, BORDER, GREEN, RED = "#0A84FF", "#0071E3", "#D9D9DE", "#218838", "#D92D20"


class SignerApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Sign — P7S 数字签名")
        self.geometry("770x590")
        self.minsize(700, 545)
        self.configure(bg=BG)
        self.input_file: Path | None = None
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.destination_reply: queue.Queue[Path | None] = queue.Queue(maxsize=1)
        self._build_ui()
        self.after(50, self._process_events)

    def _build_ui(self) -> None:
        root = tk.Frame(self, bg=BG, padx=54, pady=42)
        root.pack(fill="both", expand=True)
        header = tk.Frame(root, bg=BG)
        header.pack(fill="x")
        emblem = tk.Canvas(header, width=42, height=42, bg=BG, highlightthickness=0)
        emblem.create_oval(2, 2, 40, 40, fill=BLUE, outline="")
        emblem.create_text(21, 21, text="✓", fill="white", font=("Helvetica", 20, "bold"))
        emblem.pack(side="left", padx=(0, 14))
        title_box = tk.Frame(header, bg=BG)
        title_box.pack(side="left")
        tk.Label(title_box, text="数字签名", font=("Helvetica", 25, "bold"), fg=TEXT, bg=BG).pack(anchor="w")
        tk.Label(title_box, text="创建可验证的 PKCS#7 / P7S 文件签名", font=("Helvetica", 12), fg=MUTED, bg=BG).pack(anchor="w", pady=(2, 0))
        tk.Label(root, text="本地处理 · SHA-256 · 不上传任何文件", font=("Helvetica", 11, "bold"), fg=GREEN, bg=BG).pack(anchor="w", pady=(26, 11))

        self.card = tk.Frame(root, bg=CARD, highlightbackground=BORDER, highlightthickness=1, padx=26, pady=24)
        self.card.pack(fill="x")
        tk.Label(self.card, text="待签名文件", font=("Helvetica", 14, "bold"), fg=TEXT, bg=CARD).pack(anchor="w")
        self.file_name = tk.Label(self.card, text="选择一个文件开始", font=("Helvetica", 16, "bold"), fg=MUTED, bg=CARD, anchor="w")
        self.file_name.pack(fill="x", pady=(13, 3))
        self.file_meta = tk.Label(self.card, text="支持任意文件格式", font=("Helvetica", 12), fg=MUTED, bg=CARD, anchor="w")
        self.file_meta.pack(fill="x")
        self.pick_button = self._button(self.card, "选择文件", self._choose_file, secondary=True)
        self.pick_button.pack(anchor="w", pady=(19, 0))

        status_row = tk.Frame(root, bg=BG)
        status_row.pack(fill="x", pady=(28, 9))
        self.status_dot = tk.Label(status_row, text="●", font=("Helvetica", 12), fg=MUTED, bg=BG)
        self.status_dot.pack(side="left")
        self.status = tk.Label(status_row, text="准备就绪", font=("Helvetica", 13), fg=MUTED, bg=BG)
        self.status.pack(side="left", padx=(7, 0))
        self.percent = tk.Label(status_row, text="", font=("Helvetica", 12, "bold"), fg=MUTED, bg=BG)
        self.percent.pack(side="right")
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("Sign.Horizontal.TProgressbar", troughcolor="#E2E2E7", background=BLUE, lightcolor=BLUE, darkcolor=BLUE, bordercolor="#E2E2E7", thickness=8)
        self.progress = ttk.Progressbar(root, style="Sign.Horizontal.TProgressbar", maximum=100)
        self.progress.pack(fill="x")
        footer = tk.Frame(root, bg=BG)
        footer.pack(fill="x", pady=(29, 0))
        tk.Label(footer, text="保存时可指定任意位置，默认选择桌面。", font=("Helvetica", 11), fg=MUTED, bg=BG).pack(side="left", pady=10)
        self.sign_button = self._button(footer, "生成 P7S 签名", self._request_destination)
        self.sign_button.pack(side="right")

    def _button(self, parent, text, command, secondary=False):
        bg, fg, active = ("#F0F0F3", TEXT, "#E5E5EA") if secondary else (BLUE, "white", BLUE_ACTIVE)
        return tk.Button(parent, text=text, command=command, font=("Helvetica", 13, "bold"), bg=bg, fg=fg, activebackground=active, activeforeground=fg, relief="flat", bd=0, padx=19, pady=11, cursor="pointinghand")

    def _choose_file(self) -> None:
        choice = filedialog.askopenfilename(title="选择需要签名的文件", initialdir=str(Path.home()), parent=self)
        if choice:
            self.input_file = Path(choice)
            self.file_name.configure(text=self.input_file.name, fg=TEXT)
            self.file_meta.configure(text=f"{self._size_text(self.input_file.stat().st_size)}  ·  {self.input_file.parent}")
            self._set_status("文件已准备就绪", MUTED, 0)

    @staticmethod
    def _size_text(size: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if size < 1024 or unit == "TB":
                return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
            size /= 1024

    def _request_destination(self) -> None:
        if not self.input_file:
            messagebox.showinfo("尚未选择文件", "请先选择需要签名的文件。", parent=self)
            return
        default = DESKTOP if DESKTOP.is_dir() else Path.home()
        proposed = f"{self.input_file.name}.p7s"
        target = filedialog.asksaveasfilename(title="保存 P7S 签名文件", initialdir=str(default), initialfile=proposed, defaultextension=".p7s", filetypes=[("P7S 签名文件", "*.p7s"), ("所有文件", "*.*")], parent=self)
        if not target:
            return
        output = Path(target)
        if output.exists() and not messagebox.askyesno("确认覆盖", f"以下文件已存在：\n{output.name}\n\n是否替换它？", icon="warning", parent=self):
            return
        self._start_signing(output)

    def _start_signing(self, output: Path) -> None:
        self.sign_button.configure(state="disabled")
        self.pick_button.configure(state="disabled")
        self._set_status("正在读取文件…", BLUE, 0)
        threading.Thread(target=self._worker, args=(self.input_file, output), daemon=True).start()

    def _worker(self, source: Path, output: Path) -> None:
        def on_progress(done: int, total: int) -> None:
            value = 80 if total == 0 else min(80, int(done * 80 / total))
            self.events.put(("progress", (value, "正在读取文件…")))
        try:
            service = P7SSigningService(KEY_FILE, CERT_FILE)
            self.events.put(("progress", (82, "正在校验证书与私钥…")))
            path = service.sign_file(source, output, on_progress, overwrite=True)
            self.events.put(("progress", (100, "签名已生成")))
            self.events.put(("done", path))
        except SigningError as exc:
            self.events.put(("error", exc))
        except Exception:
            self.events.put(("error", SigningError("发生未预期的内部错误；未生成或覆盖目标文件。")))

    def _process_events(self) -> None:
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "progress":
                    amount, text = value
                    self._set_status(text, BLUE, amount)
                elif kind == "done":
                    self._set_idle()
                    self._set_status("签名已安全保存", GREEN, 100)
                    messagebox.showinfo("签名完成", f"P7S 签名文件已保存到：\n{value}", parent=self)
                elif kind == "error":
                    self._set_idle()
                    self._set_status("签名失败", RED, 0)
                    messagebox.showerror("签名失败", self._friendly_error(value), parent=self)
        except queue.Empty:
            pass
        self.after(50, self._process_events)

    @staticmethod
    def _friendly_error(error: SigningError) -> str:
        if isinstance(error, CertificateExpiredError): return "证书有效期异常。请更换有效的签名证书。"
        if isinstance(error, KeyCertificateMismatchError): return "私钥与证书不匹配。请检查签名材料。"
        if isinstance(error, SigningMaterialError): return str(error)
        if isinstance(error, InputFileError): return str(error)
        if isinstance(error, OutputFileError): return str(error)
        return str(error)

    def _set_status(self, text: str, color: str, value: int) -> None:
        self.status.configure(text=text, fg=color)
        self.status_dot.configure(fg=color)
        self.progress["value"] = value
        self.percent.configure(text=f"{value}%" if value else "")

    def _set_idle(self) -> None:
        self.sign_button.configure(state="normal")
        self.pick_button.configure(state="normal")


if __name__ == "__main__":
    SignerApp().mainloop()
