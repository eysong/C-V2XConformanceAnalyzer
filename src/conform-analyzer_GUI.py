import os
import sys
import queue
import shutil
import tempfile
import threading
import tkinter as tk
from tkinter import (filedialog, messagebox, scrolledtext, StringVar, BooleanVar)
from PIL import ImageTk, Image

import cv2x-conform-analyzer


class AnalyzerGUI:
    def __init__(self, root):
        self.root = root
        root.title("V2X Conformance Analyzer")
        root.geometry("850x850")
        root.config(background="#e3e9f8")

        self.pdml_path = StringVar(value="Select a PDML file")
        self.finalonly = BooleanVar(value=False)
        self.showskipped = BooleanVar(value=False)
        self.filename_var = StringVar(value="")
        self.progress_var = StringVar(value=" ")
        self.msg_queue = queue.Queue()
        self.temp_report_path = None
        self.current_base = "report"
        self._detail_buffer = []   

        root.columnconfigure(1, weight=1)
        root.rowconfigure(6, weight=3)  
        root.rowconfigure(9, weight=2)  

        # Title
        try:
            self.logo = Image.open("nist_ctl_logo.png").resize((160, 29))
            self.logo = ImageTk.PhotoImage(self.logo)
            tk.Label(root, image=self.logo, bg="#e3e9f8").place(x=0, y=5)
        except Exception:
            pass
        tk.Label(root, text="V2X Conformance Analyzer", font=("Calibri", 25, "bold"), bg="#e3e9f8").grid(row=0, column=0, columnspan=3, pady=8)

        tk.Label(root, text="PDML File", font=("Calibri", 12), bg="#e3e9f8").grid(row=1, column=0, padx=8, sticky="w")
        tk.Entry(root, textvariable=self.pdml_path, width=60).grid(row=1, column=1, padx=4, sticky="ew")
        b = tk.Button(root, text="Browse...", command=self.browse_pdml)
        b.grid(row=1, column=2, padx=8, sticky="w")
        self.add_hover(b, "#f0f0f0", "#E2E2E2")

        # Options
        opt = tk.Frame(root, bg="#e3e9f8")
        opt.grid(row=2, column=0, columnspan=3, sticky="w", padx=8, pady=4)
        tk.Checkbutton(opt, text="Export final verdict only (no per-packet detail in report txt file)", variable=self.finalonly, bg="#e3e9f8", font=("Calibri", 11)).pack(anchor="w")
        tk.Checkbutton(opt, text="Show skipped / unmapped fields", variable=self.showskipped, bg="#e3e9f8", font=("Calibri", 11)).pack(anchor="w")

        # Run button
        self.run_btn = tk.Button(root, text="Analyze", font=("Calibri", 16, "bold"), command=self.start_analysis, bg="#005EA2", fg="white", width=15)
        self.run_btn.grid(row=3, column=0, columnspan=3, pady=8)
        self.add_hover(self.run_btn, "#005EA2", "#1A4480")

        # Filename + progress
        tk.Label(root, textvariable=self.filename_var, font=("Calibri", 11, "bold"), bg="#e3e9f8").grid(row=4, column=0, columnspan=3)
        tk.Label(root, textvariable=self.progress_var, font=("Calibri", 11), bg="#e3e9f8").grid(row=5, column=0, columnspan=3)

        # Detail box (real-time full pass/fail)
        tk.Label(root, text="Real-time Detail:", font=("Calibri", 12), bg="#e3e9f8").grid(row=6, column=0, sticky="nw", padx=8)
        self.detail_box = scrolledtext.ScrolledText(root, wrap=tk.NONE, width=100, height=18)
        self.detail_box.grid(row=6, column=0, columnspan=3, rowspan=2, padx=8, pady=4, sticky="nsew")
        self.detail_box.config(background="#f3f5fa")

        # Summary box
        tk.Label(root, text="Summary Report:", font=("Calibri", 12), bg="#e3e9f8").grid(row=8, column=0, sticky="nw", padx=8)
        self.summary_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=12)
        self.summary_box.grid(row=9, column=0, columnspan=3, padx=8, pady=4, sticky="nsew")
        self.summary_box.config(background="#eef1fb")

        # Download button
        self.dl_btn = tk.Button(root, text="Download Full Report (.txt)", command=self.download_report, font=("Calibri", 12))
        self.dl_btn.grid(row=10, column=0, columnspan=3, pady=8)
        self.add_hover(self.dl_btn, "#f0f0f0", "#F9F9F9")

        self.poll_queue()

    # File picker 
    def browse_pdml(self):
        path = filedialog.askopenfilename(
            filetypes=[("PDML files", "*.pdml"), ("All files", "*.*")])
        if path:
            self.pdml_path.set(path)

    # Start analysis
    def start_analysis(self):
        pdml = self.pdml_path.get().strip()
        if pdml == "Select a PDML file" or not os.path.isfile(pdml):
            messagebox.showwarning("Missing file", "Please select a valid PDML file.")
            return

        base = os.path.basename(pdml)
        self.current_base = os.path.splitext(base)[0]
        self.filename_var.set(f"Analyzing: {base}")
        self.progress_var.set("0 packets checked...")  
        self.detail_box.delete("1.0", tk.END)
        self.summary_box.delete("1.0", tk.END)
        self.run_btn.config(state="disabled")
        self.dl_btn.config(state="disabled")
        self._detail_buffer = []

        thread = threading.Thread(target=self.worker, args=(pdml,), daemon=True)
        thread.start()

    # Worker thread
    def worker(self, pdml):
        try:
            # Write the complete report to a temp file
            # The Download button copies this to the user's chosen location
            tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False, encoding="utf-8")
            self.temp_report_path = tmp.name

            self.msg_queue.put(("detail", f"Parsing {pdml} ...\n"))

            detail_target = None if self.finalonly.get() else tmp

            def progress_cb(n, total):
                self.msg_queue.put(("progress", f"{n} / {total} packets checked"))

            def detail_cb(text):
                self._detail_buffer.append(text)
                if len(self._detail_buffer) >= 50:  
                    self.msg_queue.put(("detail", "\n".join(self._detail_buffer) + "\n"))
                    self._detail_buffer = []

            file_ok, faillog, skiplog, stats = analyzer.analyze_file(pdml, detail_file=detail_target, progress_cb=progress_cb, detail_cb=detail_cb)

            if self._detail_buffer:
                self.msg_queue.put(("detail", "\n".join(self._detail_buffer) + "\n"))
                self._detail_buffer = []

            summary = analyzer.build_report(pdml, file_ok, faillog, skiplog, stats, verbose=self.showskipped.get())

            # Append summary to the temp file after the detail
            if not self.finalonly.get():
                tmp.write("\n\n")
            tmp.write(summary + "\n")
            tmp.close()

            # Send summary to summary box
            self.msg_queue.put(("summary", summary))
            self.msg_queue.put(("done", None))

        except Exception as e:
            self.msg_queue.put(("summary", f"ERROR: {e}"))
            self.msg_queue.put(("done", None))

    def poll_queue(self):
        while not self.msg_queue.empty():
            kind, payload = self.msg_queue.get()
            if kind == "detail":
                self.append_detail(payload)
            elif kind == "progress":
                self.progress_var.set(payload)
            elif kind == "summary":
                self.summary_box.insert(tk.END, payload + "\n")
                self.summary_box.see(tk.END)
            elif kind == "done":
                self.progress_var.set("Done.")
                self.run_btn.config(state="normal")
                self.dl_btn.config(state="normal")
        self.root.after(100, self.poll_queue)

    def append_detail(self, text):
        self.detail_box.insert(tk.END, text)
        line_count = int(self.detail_box.index('end-1c').split('.')[0])
        if line_count > 5000:
            self.detail_box.delete("1.0", f"{line_count - 5000}.0")
        self.detail_box.see(tk.END)

    # Download the report
    def download_report(self):
        if not self.temp_report_path or not os.path.isfile(self.temp_report_path):
            messagebox.showinfo("Nothing to save", "Run an analysis first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")], initialfile=f"{self.current_base}_report.txt")
        if path:
            try:
                shutil.copy(self.temp_report_path, path)
                messagebox.showinfo("Saved", f"Saved to:\n{path}")
            except OSError as e:
                messagebox.showerror("Error", f"Could not save: {e}")

    def add_hover(self, button, normal, hover):
        button.bind("<Enter>", lambda e: button.config(bg=hover))
        button.bind("<Leave>", lambda e: button.config(bg=normal))


if __name__ == "__main__":
    root = tk.Tk()
    app = AnalyzerGUI(root)
    root.mainloop()
