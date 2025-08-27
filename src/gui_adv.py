# src/gui_adv.py
import threading
import traceback
from pathlib import Path
import io

import ttkbootstrap as tb
from ttkbootstrap.constants import *
from ttkbootstrap.dialogs import Messagebox
from tkinter import filedialog
from PIL import Image, ImageTk

# import your project modules
from src import crypto, stego, utils


class AdvancedStegoApp(tb.Window):
    def __init__(self):
        super().__init__(themename="flatly")
        self.title("🔐 Secure Image Steganography — Advanced GUI")
        self.geometry("980x640")
        self.minsize(900, 560)

        # internal state
        self.cover_path = None
        self.stego_path = None
        self.default_out_name = "stego_output.png"

        # UI layout
        self._build_ui()

    def _build_ui(self):
        notebook = tb.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=12, pady=12)

        # Embed tab
        embed_frame = tb.Frame(notebook)
        notebook.add(embed_frame, text="Embed / Encrypt")

        # Extract tab
        extract_frame = tb.Frame(notebook)
        notebook.add(extract_frame, text="Extract / Decrypt")

        # ---------------- Embed UI ----------------
        left = tb.Frame(embed_frame)
        left.pack(side="left", fill="y", padx=(10, 6), pady=10)

        tb.Label(left, text="Cover Image", font=("Inter", 12, "bold")).pack(anchor="w")
        tb.Button(left, text="Browse Image", bootstyle="info-outline", command=self.browse_cover).pack(fill="x", pady=(6, 8))

        self.cover_preview = tb.Label(left, text="No image selected", anchor="center")
        self.cover_preview.pack(ipadx=6, ipady=6, expand=False)

        tb.Label(left, text="Image Info", font=("Inter", 10)).pack(anchor="w", pady=(10, 0))
        self.cover_info = tb.Label(left, text="Width: -  Height: -  Capacity: - KB", wraplength=260, justify="left")
        self.cover_info.pack(anchor="w", pady=(4, 8))

        tb.Separator(left).pack(fill="x", pady=8)

        tb.Label(left, text="Preview (after embedding)", font=("Inter", 10)).pack(anchor="w")
        self.stego_preview = tb.Label(left, text="No stego yet", anchor="center")
        self.stego_preview.pack(ipadx=6, ipady=6, pady=(6,4))

        # right panel for controls
        right = tb.Frame(embed_frame)
        right.pack(side="left", fill="both", expand=True, padx=(6, 10), pady=10)

        # message input
        tb.Label(right, text="Secret message (choose file or type below):", font=("Inter", 11)).pack(anchor="w")
        file_row = tb.Frame(right)
        file_row.pack(fill="x", pady=(6,4))
        self.msg_file_entry = tb.Entry(file_row)
        self.msg_file_entry.pack(side="left", fill="x", expand=True, padx=(0,8))
        tb.Button(file_row, text="Browse", bootstyle="outline-info", command=self.browse_message_file).pack(side="left")

        tb.Label(right, text="Or type message:", font=("Inter", 10)).pack(anchor="w", pady=(6,0))
        self.text_msg = tb.Text(right, height=6)
        self.text_msg.pack(fill="both", expand=False, pady=(4,6))

        tb.Label(right, text="AES Passphrase:", font=("Inter", 11)).pack(anchor="w", pady=(6,0))
        self.pass_entry = tb.Entry(right, show="*")
        self.pass_entry.pack(fill="x", pady=(4,6))

        # options
        opts = tb.Frame(right)
        opts.pack(fill="x", pady=(6,8))
        tb.Label(opts, text="Options:", font=("Inter", 10)).pack(side="left", padx=(0,8))
        self.lsb_var = tb.IntVar(value=1)
        tb.Checkbutton(opts, text="Use 1 LSB per channel (safer)", variable=self.lsb_var).pack(side="left", padx=(0,8))

        # embed controls
        btns = tb.Frame(right)
        btns.pack(fill="x", pady=(10,6))
        self.embed_btn = tb.Button(btns, text="Embed & Save", bootstyle="success-outline", command=self.start_embed)
        self.embed_btn.pack(side="left", padx=(0,8))
        tb.Button(btns, text="Clear Message", bootstyle="secondary-outline", command=self.clear_message).pack(side="left")

        # progress & status
        self.embed_progress = tb.Progressbar(right, mode="indeterminate")
        self.embed_progress.pack(fill="x", pady=(12,6))
        self.status_label = tb.Label(right, text="Status: Idle")
        self.status_label.pack(anchor="w")

        # PSNR display
        self.psnr_label = tb.Label(right, text="PSNR: -")
        self.psnr_label.pack(anchor="w", pady=(8,0))

        # ---------------- Extract UI ----------------
        ex_left = tb.Frame(extract_frame)
        ex_left.pack(side="left", fill="y", padx=(10, 6), pady=10)

        tb.Label(ex_left, text="Stego Image", font=("Inter", 12, "bold")).pack(anchor="w")
        tb.Button(ex_left, text="Browse Stego Image", bootstyle="info-outline", command=self.browse_stego).pack(fill="x", pady=(6, 8))
        self.extract_preview = tb.Label(ex_left, text="No stego selected", anchor="center")
        self.extract_preview.pack(ipadx=6, ipady=6)

        tb.Label(ex_left, text="Image info", font=("Inter", 10)).pack(anchor="w", pady=(10, 0))
        self.extract_info = tb.Label(ex_left, text="Width: -  Height: -", wraplength=260, justify="left")
        self.extract_info.pack(anchor="w", pady=(4, 8))

        ex_right = tb.Frame(extract_frame)
        ex_right.pack(side="left", fill="both", expand=True, padx=(6, 10), pady=10)

        tb.Label(ex_right, text="AES Passphrase:", font=("Inter", 11)).pack(anchor="w", pady=(6,0))
        self.extract_pass = tb.Entry(ex_right, show="*")
        self.extract_pass.pack(fill="x", pady=(4,8))

        tb.Label(ex_right, text="Extracted message:", font=("Inter", 11)).pack(anchor="w")
        self.extracted_text = tb.Text(ex_right, height=10)
        self.extracted_text.pack(fill="both", expand=True, pady=(6,8))

        ex_btns = tb.Frame(ex_right)
        ex_btns.pack(fill="x")
        self.extract_btn = tb.Button(ex_btns, text="Extract", bootstyle="warning-outline", command=self.start_extract)
        self.extract_btn.pack(side="left", padx=(0,8))
        tb.Button(ex_btns, text="Save to file", bootstyle="secondary-outline", command=self.save_extracted).pack(side="left")

    # ---------- helpers ----------
    def browse_cover(self):
        p = filedialog.askopenfilename(title="Choose cover image",
                                       filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp")])
        if not p:
            return
        self.cover_path = p
        self._update_cover_preview(p)

    def _update_cover_preview(self, path):
        try:
            img = Image.open(path)
            w, h = img.size
            cap_bits = stego.capacity_in_bits(img, channels=3)
            cap_bytes = (cap_bits // 8) - stego.HEADER_LEN_BYTES
            info = f"Width: {w} px  Height: {h} px\nCapacity: {cap_bytes} bytes (approx.)"
            self.cover_info.configure(text=info)
            thumb = img.copy()
            thumb.thumbnail((300, 220))
            tkimg = ImageTk.PhotoImage(thumb)
            self.cover_preview.configure(image=tkimg, text="")
            self.cover_preview.image = tkimg
        except Exception as e:
            Messagebox.show_error(f"Failed to open image:\n{e}")

    def browse_message_file(self):
        p = filedialog.askopenfilename(title="Choose secret file")
        if not p: return
        self.msg_file_entry.delete(0, "end")
        self.msg_file_entry.insert(0, p)

    def clear_message(self):
        self.msg_file_entry.delete(0, "end")
        self.text_msg.delete("1.0", "end")

    def browse_stego(self):
        p = filedialog.askopenfilename(title="Choose stego image",
                                       filetypes=[("Images", "*.png *.jpg *.jpeg")])
        if not p: return
        self.stego_path = p
        try:
            img = Image.open(p)
            w, h = img.size
            self.extract_info.configure(text=f"Width: {w} px  Height: {h} px")
            thumb = img.copy()
            thumb.thumbnail((300, 220))
            tkimg = ImageTk.PhotoImage(thumb)
            self.extract_preview.configure(image=tkimg, text="")
            self.extract_preview.image = tkimg
        except Exception as e:
            Messagebox.show_error(f"Failed to open image:\n{e}")

    # ---------- embed/extract workers ----------
    def start_embed(self):
        # validate inputs
        if not self.cover_path:
            Messagebox.show_warning("Please select a cover image first.")
            return
        msg_file = self.msg_file_entry.get().strip()
        typed_msg = self.text_msg.get("1.0", "end").encode("utf-8").rstrip(b"\n")

        if msg_file:
            payload = None
            try:
                with open(msg_file, "rb") as f:
                    payload = f.read()
            except Exception as e:
                Messagebox.show_error(f"Failed to read message file:\n{e}")
                return
        elif typed_msg and len(typed_msg) > 0:
            payload = typed_msg
        else:
            Messagebox.show_warning("Please provide a message (file or typed).")
            return

        passphrase = self.pass_entry.get()
        if not passphrase:
            Messagebox.show_warning("Please enter an AES passphrase.")
            return

        # output location
        out_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                filetypes=[("PNG Image", "*.png")],
                                                initialfile=self.default_out_name,
                                                title="Save stego image as")
        if not out_path:
            return

        # start thread
        self.embed_progress.start(8)
        self.status_label.configure(text="Status: Encrypting & embedding...")
        self.embed_btn.configure(state=DISABLED)
        t = threading.Thread(target=self._embed_worker, args=(payload, passphrase, out_path), daemon=True)
        t.start()

    def _embed_worker(self, payload: bytes, passphrase: str, out_path: str):
        try:
            # encrypt
            blob = crypto.encrypt(payload, passphrase)

            # choose channels usage based on LSB option
            # our stego implementation uses channels param, but we used default RGB; using 1 LSB per channel here
            stego.embed_bytes_into_image(self.cover_path, blob, out_path)

            # compute PSNR
            img_cover = Image.open(self.cover_path).convert("RGB")
            img_stego = Image.open(out_path).convert("RGB")
            psnr_val = utils.psnr(img_cover, img_stego)

            # update UI on main thread
            self.after(0, lambda: self._on_embed_success(out_path, psnr_val))
        except Exception as e:
            tb = traceback.format_exc()
            print(tb)
            self.after(0, lambda: self._on_embed_error(e))
        finally:
            self.after(0, self._embed_cleanup)

    def _on_embed_success(self, out_path: str, psnr_val: float):
        Messagebox.show_info("Success", f"Embedded successfully!\nSaved: {out_path}\nPSNR: {psnr_val:.2f} dB")
        # update stego preview
        try:
            img = Image.open(out_path)
            thumb = img.copy(); thumb.thumbnail((300,220))
            tkimg = ImageTk.PhotoImage(thumb)
            self.stego_preview.configure(image=tkimg, text="")
            self.stego_preview.image = tkimg
        except Exception:
            pass
        self.psnr_label.configure(text=f"PSNR: {psnr_val:.2f} dB")
        self.default_out_name = Path(out_path).name

    def _on_embed_error(self, exc):
        Messagebox.show_error(f"Embedding failed:\n{exc}")

    def _embed_cleanup(self):
        self.embed_progress.stop()
        self.status_label.configure(text="Status: Idle")
        self.embed_btn.configure(state=NORMAL)

    # ---------- extract ----------
    def start_extract(self):
        if not self.stego_path:
            Messagebox.show_warning("Please select a stego image first.")
            return
        passphrase = self.extract_pass.get()
        if not passphrase:
            Messagebox.show_warning("Please enter the AES passphrase used for embedding.")
            return

        self.extract_btn.configure(state=DISABLED)
        self.status_label.configure(text="Status: Extracting & decrypting...")
        self.embed_progress.start(6)
        t = threading.Thread(target=self._extract_worker, args=(passphrase,), daemon=True)
        t.start()

    def _extract_worker(self, passphrase: str):
        try:
            blob = stego.extract_bytes_from_image(self.stego_path)
            plaintext = crypto.decrypt(blob, passphrase)
            # show result in text widget (main thread)
            self.after(0, lambda: self._on_extract_success(plaintext))
        except Exception as e:
            tb = traceback.format_exc()
            print(tb)
            self.after(0, lambda: self._on_extract_error(e))
        finally:
            self.after(0, self._extract_cleanup)

    def _on_extract_success(self, plaintext: bytes):
        try:
            text = plaintext.decode("utf-8")
        except Exception:
            # binary file - display as repr and allow save
            text = f"<binary data> {len(plaintext)} bytes\n\n" + plaintext[:200].hex()
        self.extracted_text.delete("1.0", "end")
        self.extracted_text.insert("1.0", text)
        Messagebox.show_info("Extracted", "Message extracted successfully.")

    def _on_extract_error(self, exc):
        Messagebox.show_error(f"Extraction failed:\n{exc}")

    def _extract_cleanup(self):
        self.embed_progress.stop()
        self.status_label.configure(text="Status: Idle")
        self.extract_btn.configure(state=NORMAL)

    def save_extracted(self):
        content = self.extracted_text.get("1.0", "end")
        if not content.strip():
            Messagebox.show_warning("No extracted content to save.")
            return
        p = filedialog.asksaveasfilename(title="Save extracted message", defaultextension=".txt",
                                         filetypes=[("Text file", "*.txt"), ("All files", "*.*")])
        if not p:
            return
        try:
            with open(p, "wb") as f:
                try:
                    # try to save utf-8 text
                    f.write(content.encode("utf-8"))
                except Exception:
                    f.write(content.encode("utf-8", errors="ignore"))
            Messagebox.show_info("Saved", f"Saved extracted message to {p}")
        except Exception as e:
            Messagebox.show_error(f"Failed to save:\n{e}")


if __name__ == "__main__":
    app = AdvancedStegoApp()
    app.mainloop()