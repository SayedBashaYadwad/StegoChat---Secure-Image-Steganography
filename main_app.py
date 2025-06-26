import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog, Menu, scrolledtext
from PIL import Image, ImageTk
import numpy as np
import threading
from queue import Queue
from encryption import encrypt_message, decrypt_message
import os

def message_to_bits(msg):
    return [int(b) for char in msg for b in bin(ord(char))[2:].rjust(8, '0')]

def bits_to_message(bits):
    chars = []
    for i in range(0, len(bits), 8):
        byte = bits[i:i+8]
        if len(byte) < 8: break
        c = chr(int(''.join(map(str, byte)), 2))
        if c == '\x00': break
        chars.append(c)
    return ''.join(chars)

def extract_message_from_image(path):
    try:
        img = Image.open(path).convert('RGB')
        data = np.array(img).flatten()
        bits = [v & 1 for v in data]
        return bits_to_message(bits)
    except Exception as e:
        raise ValueError(f"Failed to extract message: {str(e)}")

def hide_message_in_image(in_path, out_path, msg):
    img = Image.open(in_path).convert('RGB')
    data = np.array(img)
    shape = data.shape
    data = data.flatten()
    bits = message_to_bits(msg) + [0]*8
    if len(bits) > len(data):
        raise ValueError("Message too long")
    for i, bit in enumerate(bits): data[i] = (data[i] & ~1) | bit
    Image.fromarray(data.reshape(shape).astype('uint8'), 'RGB').save(out_path)

class StegoApp:
    def __init__(self, root):
        self.root = root
        self.root.title("StegoChat - Secure Image Steganography")
        self.root.geometry("800x700")
        self.queue = Queue()
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.notebook = ttk.Notebook(root)
        self.hide_tab = ttk.Frame(self.notebook)
        self.extract_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.hide_tab, text='Hide Message')
        self.notebook.add(self.extract_tab, text='Extract Message')
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W).pack(side=tk.BOTTOM, fill=tk.X)
        self.image_cache = {}

        self.setup_hide_tab()
        self.setup_extract_tab()
        self.process_queue()

    def process_queue(self):
        try:
            while True:
                func, args = self.queue.get_nowait()
                func(*args)
        except:
            pass
        self.root.after(100, self.process_queue)

    def show_image_preview(self, path, label):
        if path in self.image_cache:
            label.config(image=self.image_cache[path])
            return
        def loader():
            try:
                img = Image.open(path)
                img.thumbnail((300, 300))
                photo = ImageTk.PhotoImage(img)
                self.image_cache[path] = photo
                self.queue.put((label.config, {'image': photo}))
            except Exception as e:
                self.queue.put((self.status_var.set, (f"Error loading image: {e}",)))
                self.queue.put((messagebox.showerror, ("Error", f"Failed to load image: {e}")))
        threading.Thread(target=loader, daemon=True).start()

    def update_message_length(self, event=None):
        try:
            msg = self.message_text.get("1.0", "end-1c").strip()
            length = len(msg)
            if self.image_path_var.get():
                img = Image.open(self.image_path_var.get())
                max_chars = (img.width * img.height * 3) // 8 - 32
                self.capacity_label.config(text=(
                    f"📝 Image Capacity Information:\n"
                    f"• Maximum message length: {max_chars} chars\n"
                    f"• Current length: {length} chars\n"
                    f"• Remaining: {max_chars - length} chars"))
                color = 'red' if length > max_chars else 'black'
                self.capacity_label.config(foreground=color)
                self.status_var.set(f"Capacity used: {length}/{max_chars} chars")
            else:
                self.capacity_label.config(text="Select an image to see capacity info")
        except Exception as e:
            self.status_var.set(f"Error updating message length: {str(e)}")

    def select_image(self):
        path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if path:
            try:
                self.image_path_var.set(path)
                self.show_image_preview(path, self.image_preview_label)
                self.update_message_length()
                self.status_var.set(f"Selected image: {os.path.basename(path)}")
            except Exception as e:
                self.status_var.set(f"Error loading image: {str(e)}")
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def select_extract_image(self):
        path = filedialog.askopenfilename(filetypes=[("PNG Images", "*.png")])
        if path:
            try:
                self.extract_image_path_var.set(path)
                self.show_image_preview(path, self.extract_image_preview_label)
                img = Image.open(path)
                max_bytes = (img.width * img.height * 3) // 8
                self.message_preview.config(text=f"Up to {max_bytes} bytes hidden message possible.")
                self.status_var.set(f"Selected stego image: {os.path.basename(path)}")
            except Exception as e:
                self.status_var.set(f"Error loading image: {str(e)}")
                messagebox.showerror("Error", f"Failed to load image: {str(e)}")

    def disable_ui(self):
        for tab in [self.hide_tab, self.extract_tab]:
            for w in tab.winfo_children():
                if isinstance(w, (ttk.Button, ttk.Entry, scrolledtext.ScrolledText)):
                    w.configure(state='disabled')

    def enable_ui(self):
        for tab in [self.hide_tab, self.extract_tab]:
            for w in tab.winfo_children():
                if isinstance(w, (ttk.Button, ttk.Entry)):
                    w.configure(state='normal')
                elif isinstance(w, scrolledtext.ScrolledText):
                    w.configure(state='normal')
        self.extracted_message.configure(state='disabled')

    def hide_message(self):
        img_path = self.image_path_var.get()
        message = self.message_text.get("1.0", "end-1c").strip()
        pw = self.hide_password_entry.get()
        confirm_pw = self.confirm_password_entry.get()

        if not img_path or not message or not pw:
            messagebox.showerror("Error", "Fill all fields.")
            return
        if pw != confirm_pw:
            messagebox.showerror("Error", "Passwords do not match.")
            return
        if len(pw) < 8:
            messagebox.showerror("Error", "Password too short.")
            return
        try:
            img = Image.open(img_path)
            max_chars = (img.width * img.height * 3) // 8 - 32
            if len(message) > max_chars:
                messagebox.showerror("Error", f"Message too long (max {max_chars} chars).")
                return
        except Exception as e:
            messagebox.showerror("Error", f"Image error: {e}")
            return
        filename = simpledialog.askstring("Save As", "Enter filename:", initialvalue="stego_image.png")
        if not filename:
            return
        if not filename.endswith('.png'):
            filename += '.png'

        self.disable_ui()
        self.progress.start()
        self.status_var.set("Hiding message...")

        def task():
            try:
                encrypted = encrypt_message(message, pw)
                hide_message_in_image(img_path, filename, encrypted.decode())
                self.queue.put((messagebox.showinfo, ("Success", f"Message hidden in {filename}.\nShare password securely.")))
            except Exception as e:
                self.queue.put((messagebox.showerror, ("Error", f"Failed: {e}")))
            finally:
                self.queue.put((self.enable_ui, ()))
                self.queue.put((self.progress.stop, ()))

        threading.Thread(target=task, daemon=True).start()

    def extract_message(self):
        img_path = self.extract_image_path_var.get()
        pw = self.extract_password_entry.get()
        if not img_path or not pw:
            messagebox.showerror("Error", "Fill all fields.")
            return
        if len(pw) < 8:
            messagebox.showerror("Error", "Invalid password length.")
            return

        self.disable_ui()
        self.extract_progress.start()
        self.status_var.set("Extracting message...")

        def task():
            try:
                hidden = extract_message_from_image(img_path)
                decrypted = decrypt_message(hidden.encode(), pw)
                self.queue.put((self.update_extracted_message, (decrypted,)))
                self.queue.put((self.status_var.set, ("Message extracted successfully!",)))
            except Exception as e:
                self.queue.put((messagebox.showerror, ("Error", f"Failed: {e}")))
            finally:
                self.queue.put((self.enable_ui, ()))
                self.queue.put((self.extract_progress.stop, ()))

        threading.Thread(target=task, daemon=True).start()

    def update_extracted_message(self, msg):
        self.extracted_message.configure(state='normal')
        self.extracted_message.delete("1.0", tk.END)
        self.extracted_message.insert("1.0", msg)
        self.extracted_message.configure(state='disabled')

    def setup_hide_tab(self):
        left = ttk.Frame(self.hide_tab)
        left.pack(side=tk.LEFT, fill='both', expand=True, padx=10, pady=20)
        right = ttk.Frame(self.hide_tab)
        right.pack(side=tk.RIGHT, fill='both', expand=True, padx=10, pady=20)

        ttk.Label(left, text="Select Image (.png):", font='Arial 12 bold').pack(pady=5)
        self.image_path_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.image_path_var, width=40).pack(pady=5)
        ttk.Button(left, text="Browse", command=self.select_image).pack(pady=5)
        self.image_preview_label = ttk.Label(left)
        self.image_preview_label.pack(pady=10)

        ttk.Label(right, text="Enter Password:", font='Arial 12 bold').pack(pady=5)
        self.hide_password_entry = ttk.Entry(right, show="*", width=40)
        self.hide_password_entry.pack(pady=5)
        ttk.Label(right, text="Confirm Password:", font='Arial 12 bold').pack(pady=5)
        self.confirm_password_entry = ttk.Entry(right, show="*", width=40)
        self.confirm_password_entry.pack(pady=5)
        ttk.Label(right, text="(Minimum 8 characters)", font='Arial 8').pack()

        ttk.Label(right, text="Enter Secret Message:", font='Arial 12 bold').pack(pady=5)
        self.message_text = scrolledtext.ScrolledText(right, height=12, width=40, wrap=tk.WORD)
        self.message_text.pack(pady=5)
        
        # Bind all text change events
        for event in ('<KeyPress>', '<KeyRelease>', '<<Paste>>', '<<Cut>>', '<<Modified>>'):
            self.message_text.bind(event, lambda e: self.root.after(10, self.update_message_length))

        self.capacity_label = ttk.Label(self.hide_tab, font='Arial 10', wraplength=300, justify='left')
        self.capacity_label.pack(pady=5)
        self.progress = ttk.Progressbar(right, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=5)
        ttk.Button(right, text="Hide Message", command=self.hide_message).pack(pady=20)

    def setup_extract_tab(self):
        left = ttk.Frame(self.extract_tab)
        left.pack(side=tk.LEFT, fill='both', expand=True, padx=10, pady=20)
        right = ttk.Frame(self.extract_tab)
        right.pack(side=tk.RIGHT, fill='both', expand=True, padx=10, pady=20)

        ttk.Label(left, text="Select Stego Image:", font='Arial 12 bold').pack(pady=5)
        self.extract_image_path_var = tk.StringVar()
        ttk.Entry(left, textvariable=self.extract_image_path_var, width=40).pack(pady=5)
        ttk.Button(left, text="Browse", command=self.select_extract_image).pack(pady=5)
        self.extract_image_preview_label = ttk.Label(left)
        self.extract_image_preview_label.pack(pady=10)
        self.message_preview = ttk.Label(left, wraplength=300)
        self.message_preview.pack(pady=5)

        ttk.Label(right, text="Enter Password:", font='Arial 12 bold').pack(pady=5)
        self.extract_password_entry = ttk.Entry(right, show="*", width=40)
        self.extract_password_entry.pack(pady=5)
        ttk.Label(right, text="(Password used to hide message)", font='Arial 8').pack()

        self.extract_progress = ttk.Progressbar(right, mode='indeterminate')
        self.extract_progress.pack(fill=tk.X, pady=5)
        ttk.Button(right, text="Extract Message", command=self.extract_message).pack(pady=20)
        ttk.Label(right, text="Extracted Message:", font='Arial 12 bold').pack(pady=5)
        self.extracted_message = scrolledtext.ScrolledText(right, height=12, width=40, wrap=tk.WORD, state='disabled')
        self.extracted_message.pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    StegoApp(root)
    root.mainloop()
