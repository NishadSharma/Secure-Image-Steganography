# src/gui_pro.py
"""
A modern, clean, and advanced Tkinter GUI for Secure Image Steganography
- ttkbootstrap theming (light/dark switch)
- Two-tab workflow (Embed / Extract)
- Image previews (cover & stego)
- Capacity vs payload meter with live updates
- Non-blocking operations with threading
- PSNR calculation & display
- Status console + toasts for feedback
- Sensible validation, error handling, and UX polish

Dependencies:
    pip install ttkbootstrap pillow pycryptodome numpy

Relies on your existing modules:
    from src import crypto, stego, utils

Run:
    python src/gui_pro.py
"""
from __future__ import annotations
import threading
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import filedialog
from PIL import Image, ImageTk

# Project modules
from src import crypto, stego, utils


@dataclass
class ImageInfo:
    path: Path
    width: int
    height: int
    capacity_bytes: int


class StegoGUI(tb.Window):
    def __init__(self):
        super().__init__(themename="flatly")
        self.title("🔒 Secure Image Steganography — Pro GUI")
        self.geometry("1080x680")
        self.minsize(980, 600)

        # state
        self.cover_info: Optional[ImageInfo] = None
        self.stego_preview_path: Optional[Path] = None
        self.extract_image_info: Optional[ImageInfo] = None

        # build UI
        self._build_topbar()
        self._build_tabs()
        self._build_statusbar()

    # -------------------- Top bar --------------------
    def _build_topbar(self):
        bar = tb.Frame(self, padding=(12, 8))
        bar.pack(fill=X)

        tb.Label(bar, text="Secure Image Steganography", font=("Inter", 14, "bold")).pack(side=LEFT)

        bar_right = tb.Frame(bar)
        bar_right.pack(side=RIGHT)

        tb.Label(bar_right, text="Theme:").pack(side=LEFT, padx=(0, 6))
        self.theme_var = tb.StringVar(value="flatly")
        theme_combo = tb.Combobox(bar_right, width=12, textvariable=self.theme_var,
                                  values=["flatly", "cosmo", "journal", "litera", "minty", "pulse", "sandstone", "solar", "superhero", "united", "yeti", "darkly", "cyborg", "vapor"])
        theme_combo.pack(side=LEFT)
        theme_combo.bind("<<ComboboxSelected>>", self._on_theme_change)

        tb.Button(bar_right, text="About", bootstyle="secondary-outline", command=self._show_about).pack(side=LEFT, padx=8)

    # -------------------- Tabs --------------------
    def _build_tabs(self):
        self.tabs = tb.Notebook(self)
        self.tabs.pack(fill=BOTH, expand=True, padx=12, pady=8)

        self.embed_tab = tb.Frame(self.tabs)
        self.extract_tab = tb.Frame(self.tabs)
        self.tabs.add(self.embed_tab, text="Embed / Encrypt")
        self.tabs.add(self.extract_tab, text="Extract / Decrypt")

        self._build_embed_tab(self.embed_tab)
        self._build_extract_tab(self.extract_tab)

    # -------------------- Statusbar --------------------
    def _build_statusbar(self):
        self.status = tb.Label(self, text="Ready", anchor=W, padding=(10, 6))
        self.status.pack(fill=X, side=BOTTOM)

    # -------------------- Embed tab --------------------
    def _build_embed_tab(self, root: tb.Frame):
        left = tb.Labelframe(root, text="Cover Image", padding=10)
        left.pack(side=LEFT, fill=Y, padx=(8, 6), pady=8)

        tb.Button(left, text="Choose Image", bootstyle="info-outline", command=self.choose_cover).pack(fill=X)
        self.cover_meta = tb.Label(left, text="No image selected", justify=LEFT, padding=(0, 6))
        self.cover_meta.pack(fill=X)

        self.cover_preview_widget = tb.Label(left, text="Preview", bootstyle="secondary")
        self.cover_preview_widget.pack(fill=BOTH, expand=False, ipadx=8, ipady=8)

        tb.Separator(left).pack(fill=X, pady=8)

        tb.Label(left, text="Stego Preview (after save)").pack(anchor=W)
        self.stego_preview_widget = tb.Label(left, text="—", bootstyle="secondary")
        self.stego_preview_widget.pack(fill=BOTH, ipadx=8, ipady=8)

        right = tb.Labelframe(root, text="Message & Security", padding=10)
        right.pack(side=LEFT, fill=BOTH, expand=True, padx=(6, 8), pady=8)

        # message source
        src_row = tb.Frame(right)
        src_row.pack(fill=X)
        tb.Label(src_row, text="Secret file (optional):").pack(side=LEFT)
        self.msg_file_entry = tb.Entry(src_row)
        self.msg_file_entry.pack(side=LEFT, fill=X, expand=True, padx=6)
        tb.Button(src_row, text="Browse", bootstyle="outline-info", command=self.choose_message_file).pack(side=LEFT)

        tb.Label(right, text="Or type/paste your message:").pack(anchor=W, pady=(10, 2))
        self.msg_text = tb.Text(right, height=8)
        self.msg_text.pack(fill=BOTH, expand=True)

        # passphrase
        tb.Label(right, text="AES-256 Passphrase:").pack(anchor=W, pady=(10, 2))
        pass_row = tb.Frame(right)
        pass_row.pack(fill=X)
        self.pass_entry = tb.Entry(pass_row, show="*")
        self.pass_entry.pack(side=LEFT, fill=X, expand=True)
        self.show_pass_var = tb.IntVar(value=0)
        tb.Checkbutton(pass_row, text="Show", variable=self.show_pass_var, command=self._toggle_show_pass).pack(side=LEFT, padx=8)

        # capacity vs payload meter
        meter_frame = tb.Frame(right)
        meter_frame.pack(fill=X, pady=(12, 4))
        tb.Label(meter_frame, text="Payload vs Capacity:").pack(anchor=W)
        self.capacity_meter = tb.Progressbar(meter_frame, mode="determinate", maximum=100)
        self.capacity_meter.pack(fill=X)
        self.capacity_label = tb.Label(meter_frame, text="—")
        self.capacity_label.pack(anchor=W)

        # buttons
        btn_row = tb.Frame(right)
        btn_row.pack(fill=X, pady=(10, 2))
        self.embed_btn = tb.Button(btn_row, text="Encrypt & Embed…", bootstyle="success", command=self._start_embed)
        self.embed_btn.pack(side=LEFT)
        tb.Button(btn_row, text="Clear", bootstyle="secondary-outline", command=self._clear_embed_inputs).pack(side=LEFT, padx=8)

        # progress + console
        self.embed_prog = tb.Progressbar(right, mode="indeterminate")
        self.embed_prog.pack(fill=X, pady=(12, 6))
        tb.Label(right, text="Console:").pack(anchor=W)
        self.console = tb.ScrolledText(right, height=8)
        self.console.pack(fill=BOTH, expand=False)

    # -------------------- Extract tab --------------------
    def _build_extract_tab(self, root: tb.Frame):
        left = tb.Labelframe(root, text="Stego Image", padding=10)
        left.pack(side=LEFT, fill=Y, padx=(8, 6), pady=8)

        tb.Button(left, text="Choose Stego Image", bootstyle="info-outline", command=self.choose_stego).pack(fill=X)
        self.extract_meta = tb.Label(left, text="No image selected", justify=LEFT, padding=(0, 6))
        self.extract_meta.pack(fill=X)
        self.extract_preview_widget = tb.Label(left, text="Preview", bootstyle="secondary")
        self.extract_preview_widget.pack(fill=BOTH, ipadx=8, ipady=8)

        right = tb.Labelframe(root, text="Decryption", padding=10)
        right.pack(side=LEFT, fill=BOTH, expand=True, padx=(6, 8), pady=8)

        tb.Label(right, text="AES-256 Passphrase:").pack(anchor=W)
        self.extract_pass = tb.Entry(right, show="*")
        self.extract_pass.pack(fill=X, pady=(2, 8))

        btn_row = tb.Frame(right)
        btn_row.pack(fill=X, pady=(4, 8))
        self.extract_btn = tb.Button(btn_row, text="Extract & Decrypt", bootstyle="warning", command=self._start_extract)
        self.extract_btn.pack(side=LEFT)
        tb.Button(btn_row, text="Save to File…", bootstyle="secondary-outline", command=self._save_extracted).pack(side=LEFT, padx=8)
        tb.Button(btn_row, text="Copy Text", bootstyle="secondary-outline", command=self._copy_extracted).pack(side=LEFT)

        tb.Label(right, text="Extracted Message:").pack(anchor=W)
        self.extracted_text = tb.ScrolledText(right, height=12)
        self.extracted_text.pack(fill=BOTH, expand=True)

    # -------------------- Helpers --------------------
    def _on_theme_change(self, _):
        try:
            self.style.theme_use(self.theme_var.get())
        except Exception as e:
            Messagebox.show_error(f"Failed to apply theme: {e}")

    def _show_about(self):
        Messagebox.show_info(
            "About",
            "Secure Image Steganography — Pro GUI\n\n"
            "AES-256 (GCM) + LSB steganography with modern Tkinter UI.\n"
            "Built for final-year cybersecurity projects."
        )

    def _toggle_show_pass(self):
        self.pass_entry.configure(show="" if self.show_pass_var.get() else "*")

    def _open_image_info(self, path: Path) -> ImageInfo:
        img = Image.open(path).convert("RGB")
        w, h = img.size
        cap_bits = stego.capacity_in_bits(img, channels=3)
        cap_bytes = (cap_bits // 8) - stego.HEADER_LEN_BYTES
        return ImageInfo(path=path, width=w, height=h, capacity_bytes=max(cap_bytes, 0))

    def _set_status(self, text: str):
        self.status.configure(text=text)
        self.console.insert(END, text + "\n")
        self.console.see(END)

    def _set_preview(self, widget: tb.Label, path: Path):
        img = Image.open(path)
        thumb = img.copy(); thumb.thumbnail((360, 260))
        tkimg = ImageTk.PhotoImage(thumb)
        widget.configure(image=tkimg, text="")
        widget.image = tkimg

    def _update_capacity_meter(self):
        if not self.cover_info:
            self.capacity_meter.configure(value=0)
            self.capacity_label.configure(text="—")
            return
        # compute payload size
        payload = self._gather_payload_bytes(allow_empty=True)
        size = len(payload) if payload else 0
        header = stego.HEADER_LEN_BYTES
        used = size + header
        cap = self.cover_info.capacity_bytes
        pct = int(min(max((used / cap) * 100 if cap else 0, 0), 100))
        self.capacity_meter.configure(value=pct)
        self.capacity_label.configure(text=f"Payload {size} B  + header {header} B  /  Capacity {cap} B  → {pct}%")

    def _gather_payload_bytes(self, allow_empty=False) -> Optional[bytes]:
        msg_path_str = self.msg_file_entry.get().strip()
        if msg_path_str:
            try:
                return Path(msg_path_str).read_bytes()
            except Exception as e:
                Messagebox.show_error(f"Failed to read message file: {e}")
                return None
        text = self.msg_text.get("1.0", END).encode("utf-8")
        text = text.rstrip(b"\n")
        if not text and not allow_empty:
            Messagebox.show_warning("Please provide a message (file or text).")
            return None
        return text

    # -------------------- File pickers --------------------
    def choose_cover(self):
        p = filedialog.askopenfilename(title="Choose cover image", filetypes=[("Images", "*.png;*.jpg;*.jpeg;*.bmp")])
        if not p:
            return
        path = Path(p)
        try:
            self.cover_info = self._open_image_info(path)
            self.cover_meta.configure(text=f"{path.name}\n{self.cover_info.width}×{self.cover_info.height} px\nCapacity: {self.cover_info.capacity_bytes} bytes")
            self._set_preview(self.cover_preview_widget, path)
            self._update_capacity_meter()
            self._set_status(f"Loaded cover image: {path}")
        except Exception as e:
            Messagebox.show_error(f"Failed to open image: {e}")

    def choose_message_file(self):
        p = filedialog.askopenfilename(title="Choose secret file")
        if not p:
            return
        self.msg_file_entry.delete(0, END)
        self.msg_file_entry.insert(0, p)
        self._update_capacity_meter()

    def choose_stego(self):
        p = filedialog.askopenfilename(title="Choose stego image", filetypes=[("Images", "*.png;*.jpg;*.jpeg")])
        if not p:
            return
        path = Path(p)
        try:
            info = self._open_image_info(path)
            self.extract_image_info = info
            self.extract_meta.configure(text=f"{path.name}\n{info.width}×{info.height} px")
            self._set_preview(self.extract_preview_widget, path)
            self._set_status(f"Loaded stego image: {path}")
        except Exception as e:
            Messagebox.show_error(f"Failed to open image: {e}")

    # -------------------- Embed flow --------------------
    def _start_embed(self):
        if not self.cover_info:
            Messagebox.show_warning("Please select a cover image.")
            return
        payload = self._gather_payload_bytes()
        if payload is None:
            return
        if len(payload) + stego.HEADER_LEN_BYTES > self.cover_info.capacity_bytes:
            Messagebox.show_error("Payload too large for this cover image. Choose a larger image or a smaller payload.")
            return
        passphrase = self.pass_entry.get()
        if not passphrase:
            Messagebox.show_warning("Please enter a passphrase.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")], initialfile="stego_output.png")
        if not out:
            return

        self.embed_btn.configure(state=DISABLED)
        self.embed_prog.start(8)
        self._set_status("Encrypting and embedding…")

        t = threading.Thread(target=self._embed_worker, args=(payload, passphrase, Path(out)), daemon=True)
        t.start()

    def _embed_worker(self, payload: bytes, passphrase: str, out_path: Path):
        try:
            blob = crypto.encrypt(payload, passphrase)
            stego.embed_bytes_into_image(str(self.cover_info.path), blob, str(out_path))
            # PSNR
            c = Image.open(self.cover_info.path).convert("RGB")
            s = Image.open(out_path).convert("RGB")
            psnr_val = utils.psnr(c, s)
            self.stego_preview_path = out_path
            self.after(0, lambda: self._on_embed_success(out_path, psnr_val))
        except Exception as e:
            trace = traceback.format_exc()
            print(trace)
            self.after(0, lambda: self._on_embed_error(e))
        finally:
            self.after(0, self._embed_cleanup)

    def _on_embed_success(self, path: Path, psnr_val: float):
        self._set_status(f"Saved stego image: {path} (PSNR {psnr_val:.2f} dB)")
        Messagebox.show_info("Success", f"Embedded successfully!\nSaved: {path}\nPSNR: {psnr_val:.2f} dB")
        try:
            self._set_preview(self.stego_preview_widget, path)
        except Exception:
            pass

    def _on_embed_error(self, exc: Exception):
        Messagebox.show_error(f"Embedding failed:\n{exc}")
        self._set_status(f"Error: {exc}")

    def _embed_cleanup(self):
        self.embed_prog.stop()
        self.embed_btn.configure(state=NORMAL)

    def _clear_embed_inputs(self):
        self.msg_file_entry.delete(0, END)
        self.msg_text.delete("1.0", END)
        self.pass_entry.delete(0, END)
        self.capacity_meter.configure(value=0)
        self.capacity_label.configure(text="—")

    # -------------------- Extract flow --------------------
    def _start_extract(self):
        if not self.extract_image_info:
            Messagebox.show_warning("Please choose a stego image.")
            return
        passphrase = self.extract_pass.get()
        if not passphrase:
            Messagebox.show_warning("Please enter the passphrase.")
            return
        self.extract_btn.configure(state=DISABLED)
        self.embed_prog.start(6)
        self._set_status("Extracting and decrypting…")
        t = threading.Thread(target=self._extract_worker, args=(passphrase,), daemon=True)
        t.start()

    def _extract_worker(self, passphrase: str):
        try:
            blob = stego.extract_bytes_from_image(str(self.extract_image_info.path))
            plaintext = crypto.decrypt(blob, passphrase)
            self.after(0, lambda: self._on_extract_success(plaintext))
        except Exception as e:
            trace = traceback.format_exc(); print(trace)
            self.after(0, lambda: self._on_extract_error(e))
        finally:
            self.after(0, self._extract_cleanup)

    def _on_extract_success(self, plaintext: bytes):
        try:
            text = plaintext.decode("utf-8")
            self.extracted_text.delete("1.0", END)
            self.extracted_text.insert("1.0", text)
            Messagebox.show_info("Done", "Message extracted and decrypted.")
        except Exception:
            # binary content
            self.extracted_text.delete("1.0", END)
            self.extracted_text.insert("1.0", f"<binary data> {len(plaintext)} bytes\n\n" + plaintext[:256].hex())
            Messagebox.show_info("Done", "Binary data extracted. Use 'Save to File…' to store it.")

    def _on_extract_error(self, exc: Exception):
        Messagebox.show_error(f"Extraction failed:\n{exc}")
        self._set_status(f"Error: {exc}")

    def _extract_cleanup(self):
        self.embed_prog.stop()
        self.extract_btn.configure(state=NORMAL)

    def _save_extracted(self):
        data = self.extracted_text.get("1.0", END)
        if not data.strip():
            Messagebox.show_warning("There is no extracted text to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text file", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        try:
            Path(path).write_text(data, encoding="utf-8")
            Messagebox.show_info("Saved", f"Saved to {path}")
        except Exception as e:
            Messagebox.show_error(f"Failed to save: {e}")

    def _copy_extracted(self):
        data = self.extracted_text.get("1.0", END)
        if not data.strip():
            return
        self.clipboard_clear()
        self.clipboard_append(data)
        self._set_status("Extracted text copied to clipboard.")


if __name__ == "__main__":
    app = StegoGUI()
    app.mainloop()
