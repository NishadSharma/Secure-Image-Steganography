import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter import ttk
import ttkbootstrap as tb
from PIL import Image, ImageTk
import os


class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Secure Image Steganography with AES-256")
        self.root.geometry("800x600")

        # Use modern theme
        style = tb.Style("cosmo")

        # Notebook (Tabs)
        self.notebook = tb.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        # Tabs
        self.embed_tab = tb.Frame(self.notebook)
        self.extract_tab = tb.Frame(self.notebook)

        self.notebook.add(self.embed_tab, text="Embed Message")
        self.notebook.add(self.extract_tab, text="Extract Message")

        # Embed UI
        self.build_embed_ui()

        # Extract UI
        self.build_extract_ui()

    def build_embed_ui(self):
        lbl1 = tb.Label(self.embed_tab, text="Select Cover Image", font=("Arial", 12))
        lbl1.pack(pady=5)
        btn1 = tb.Button(self.embed_tab, text="Browse", bootstyle="info", command=self.load_image)
        btn1.pack(pady=5)

        self.img_label = tb.Label(self.embed_tab)
        self.img_label.pack(pady=10)

        tb.Label(self.embed_tab, text="Enter Secret Message:", font=("Arial", 12)).pack(pady=5)
        self.secret_entry = tk.Text(self.embed_tab, height=5, width=60)
        self.secret_entry.pack(pady=5)

        tb.Label(self.embed_tab, text="Enter AES Password:", font=("Arial", 12)).pack(pady=5)
        self.pass_entry = tb.Entry(self.embed_tab, show="*")
        self.pass_entry.pack(pady=5)

        self.progress = ttk.Progressbar(self.embed_tab, mode="indeterminate")
        self.progress.pack(pady=10, fill="x")

        btn2 = tb.Button(self.embed_tab, text="Embed & Save", bootstyle="success", command=self.embed_message)
        btn2.pack(pady=10)

    def build_extract_ui(self):
        lbl1 = tb.Label(self.extract_tab, text="Select Stego Image", font=("Arial", 12))
        lbl1.pack(pady=5)
        btn1 = tb.Button(self.extract_tab, text="Browse", bootstyle="info", command=self.load_stego_image)
        btn1.pack(pady=5)

        self.stego_label = tb.Label(self.extract_tab)
        self.stego_label.pack(pady=10)

        tb.Label(self.extract_tab, text="Enter AES Password:", font=("Arial", 12)).pack(pady=5)
        self.extract_pass = tb.Entry(self.extract_tab, show="*")
        self.extract_pass.pack(pady=5)

        btn2 = tb.Button(self.extract_tab, text="Extract Message", bootstyle="warning", command=self.extract_message)
        btn2.pack(pady=10)

        self.result_text = tk.Text(self.extract_tab, height=10, width=60)
        self.result_text.pack(pady=10)

    def load_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg")])
        if file_path:
            img = Image.open(file_path).resize((300, 200))
            img_tk = ImageTk.PhotoImage(img)
            self.img_label.configure(image=img_tk)
            self.img_label.image = img_tk
            self.cover_image = file_path

    def load_stego_image(self):
        file_path = filedialog.askopenfilename(filetypes=[("Images", "*.png *.jpg")])
        if file_path:
            img = Image.open(file_path).resize((300, 200))
            img_tk = ImageTk.PhotoImage(img)
            self.stego_label.configure(image=img_tk)
            self.stego_label.image = img_tk
            self.stego_image = file_path

    def embed_message(self):
        # Dummy simulation
        self.progress.start(10)
        self.root.after(2000, self.finish_embed)

    def finish_embed(self):
        self.progress.stop()
        messagebox.showinfo("Success", "Message successfully embedded with AES-256 encryption!")

    def extract_message(self):
        # Dummy simulation
        message = "This is the hidden secret message."
        self.result_text.insert(tk.END, message)


if __name__ == "__main__":
    root = tb.Window(themename="cosmo")
    app = StegoApp(root)
    root.mainloop()
