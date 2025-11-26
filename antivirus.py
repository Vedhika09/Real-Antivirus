#!/usr/bin/env python3

import os
import sys
import hashlib
import shutil
import json
import logging
import threading
import queue
import math
from datetime import datetime
from pathlib import Path
from tkinter import (
    Tk, Frame, Label, Entry, Button, filedialog, messagebox, StringVar, ttk, Text, Scrollbar, VERTICAL, RIGHT, Y, LEFT, BOTH, END
)

# ---------------------------
# Configuration / Signatures
# ---------------------------

# Simple example "bad" signatures (MD5) -- for demo only.
# Replace / expand with real signatures if you have them.
SIGNATURES = {
    # md5: name
    "44d88612fea8a8f36de82e1278abb02f": "EICAR_TEST_FILE",  # EICAR MD5 (example)
    # Add more known MD5 hashes here
}

SUSPICIOUS_EXTS = {".exe", ".dll", ".scr", ".pif", ".bat", ".cmd", ".js", ".vbs", ".jar", ".ps1"}
QUARANTINE_DIR = Path.home() / ".simple_av_quarantine"
METADATA_FILE = QUARANTINE_DIR / "quarantine_index.json"
LOG_FILE = Path.home() / "simple_av.log"

# Ensure quarantine dir exists
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
if not METADATA_FILE.exists():
    METADATA_FILE.write_text(json.dumps({}))

# Setup logging
logging.basicConfig(
    filename=str(LOG_FILE),
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# ---------------------------
# Utility functions
# ---------------------------

def md5_of_file(path, chunk_size=8192):
    """Compute MD5 of a file in streaming fashion."""
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(chunk_size), b""):
                h.update(chunk)
    except Exception as e:
        logging.warning(f"Could not read file {path}: {e}")
        return None
    return h.hexdigest()


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def file_entropy(path, sample_size=4096):
    """Estimate entropy by sampling beginning of file (fast)."""
    try:
        with open(path, "rb") as f:
            data = f.read(sample_size)
    except Exception as e:
        logging.warning(f"Could not read for entropy {path}: {e}")
        return 0.0
    return shannon_entropy(data)


# ---------------------------
# Quarantine management
# ---------------------------

def load_quarantine_index():
    try:
        return json.loads(METADATA_FILE.read_text())
    except Exception:
        return {}


def save_quarantine_index(idx):
    METADATA_FILE.write_text(json.dumps(idx, indent=2))


def quarantine_file(original_path: str) -> str:
    """Move file into quarantine and record metadata. Returns quarantine path."""
    orig = Path(original_path)
    if not orig.exists() or not orig.is_file():
        raise FileNotFoundError(str(original_path))

    qidx = load_quarantine_index()
    timestamp = datetime.utcnow().strftime("%Y%m%d%H%M%S")
    qname = f"{timestamp}_{orig.name}"
    qpath = QUARANTINE_DIR / qname

    # Ensure unique
    i = 1
    while qpath.exists():
        qpath = QUARANTINE_DIR / f"{timestamp}_{i}_{orig.name}"
        i += 1

    shutil.move(str(orig), str(qpath))

    qidx[str(qpath)] = {
        "original_path": str(orig),
        "quarantined_at": datetime.utcnow().isoformat(),
        "md5": md5_of_file(str(qpath)),
        "reason": "user_quarantine"
    }
    save_quarantine_index(qidx)
    logging.info(f"Quarantined {original_path} -> {qpath}")
    return str(qpath)


def restore_quarantined(qpath_str: str) -> bool:
    qpath = Path(qpath_str)
    qidx = load_quarantine_index()
    if str(qpath) not in qidx:
        raise KeyError("Quarantine entry not found")
    meta = qidx[str(qpath)]
    orig_parent = Path(meta["original_path"]).parent
    orig_parent.mkdir(parents=True, exist_ok=True)
    try:
        shutil.move(str(qpath), meta["original_path"])
        logging.info(f"Restored {qpath} -> {meta['original_path']}")
        del qidx[str(qpath)]
        save_quarantine_index(qidx)
        return True
    except Exception as e:
        logging.error(f"Failed to restore {qpath}: {e}")
        raise


# ---------------------------
# Scanning logic
# ---------------------------

def scan_file(path: str):
    """Analyze a single file and return (verdict, reasons)."""
    reasons = []
    try:
        md5 = md5_of_file(path)
        if md5 and md5 in SIGNATURES:
            reasons.append(f"Signature match: {SIGNATURES[md5]} ({md5})")
            return "malicious", reasons

        ext = Path(path).suffix.lower()
        if ext in SUSPICIOUS_EXTS:
            reasons.append(f"Suspicious extension: {ext}")

        ent = file_entropy(path)
        # entropy threshold is heuristic: many packed/encoded binaries have high entropy ~7.5-8
        if ent >= 7.5:
            reasons.append(f"High entropy: {ent:.2f}")

        # file size based heuristic (tiny script-like files could be suspicious too)
        try:
            size = Path(path).stat().st_size
            if size == 0:
                reasons.append("Zero-byte file")
            elif size < 512 and ext in {".js", ".vbs", ".ps1"}:
                reasons.append(f"Small script file: {size} bytes")
        except Exception:
            size = None

        if reasons:
            # simple scoring: if signature matched it was already returned
            return "suspicious", reasons
        else:
            return "clean", ["No indicators matched"]
    except Exception as e:
        logging.warning(f"Error scanning {path}: {e}")
        return "error", [str(e)]


# ---------------------------
# GUI / App
# ---------------------------

class SimpleAVApp:
    def __init__(self, root: Tk):
        self.root = root
        self.root.title("SimpleAV — Prototype Antivirus")
        self.root.geometry("900x600")
        self.scan_thread = None
        self.scan_queue = queue.Queue()
        self.should_stop = threading.Event()

        # Path selection
        top_frame = Frame(root, padx=8, pady=6)
        top_frame.pack(fill="x")
        Label(top_frame, text="Folder to scan:").pack(side="left")
        self.folder_var = StringVar(value=str(Path.home()))
        Entry(top_frame, textvariable=self.folder_var, width=60).pack(side="left", padx=6)
        Button(top_frame, text="Browse", command=self.browse).pack(side="left", padx=4)
        Button(top_frame, text="Quick Scan", command=self.quick_scan).pack(side="left", padx=4)
        Button(top_frame, text="Full Scan", command=self.full_scan).pack(side="left", padx=4)
        Button(top_frame, text="Stop Scan", command=self.stop_scan).pack(side="left", padx=4)

        # Results (Treeview)
        mid_frame = Frame(root, padx=8, pady=6)
        mid_frame.pack(fill="both", expand=True)
        cols = ("path", "verdict", "reason")
        self.tree = ttk.Treeview(mid_frame, columns=cols, show="headings", selectmode="extended")
        self.tree.heading("path", text="Path")
        self.tree.heading("verdict", text="Verdict")
        self.tree.heading("reason", text="Reason (summary)")
        self.tree.column("path", width=520)
        self.tree.column("verdict", width=100)
        self.tree.column("reason", width=240)
        vsb = ttk.Scrollbar(mid_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side=LEFT, fill=BOTH, expand=True)
        vsb.pack(side=RIGHT, fill=Y)

        # Action buttons
        act_frame = Frame(root, padx=8, pady=6)
        act_frame.pack(fill="x")
        Button(act_frame, text="Quarantine Selected", command=self.quarantine_selected).pack(side="left", padx=6)
        Button(act_frame, text="Delete Selected", command=self.delete_selected).pack(side="left", padx=6)
        Button(act_frame, text="Restore from Quarantine", command=self.restore_dialog).pack(side="left", padx=6)
        Button(act_frame, text="Open Log", command=self.open_log_viewer).pack(side="left", padx=6)
        Button(act_frame, text="Refresh Quarantine Index", command=self.refresh_quarantine).pack(side="left", padx=6)

        # Progress
        bottom_frame = Frame(root, padx=8, pady=6)
        bottom_frame.pack(fill="x")
        self.progress_label = Label(bottom_frame, text="Idle")
        self.progress_label.pack(side="left")
        self.progress = ttk.Progressbar(bottom_frame, orient="horizontal", length=400, mode="determinate")
        self.progress.pack(side="left", padx=8)

        # Poll queue
        self.root.after(200, self.process_queue)

    def browse(self):
        folder = filedialog.askdirectory(initialdir=self.folder_var.get())
        if folder:
            self.folder_var.set(folder)

    def quick_scan(self):
        folder = self.folder_var.get().strip()
        # Quick scan heuristics: scan root and immediate children, or if folder is user's home, scan Desktop/Documents/Downloads
        targets = []
        p = Path(folder)
        if not p.exists():
            messagebox.showerror("Error", f"Folder does not exist: {folder}")
            return
        # If user selected home, pick common directories
        if str(p) == str(Path.home()):
            for name in ("Desktop", "Documents", "Downloads"):
                f = Path.home() / name
                if f.exists():
                    targets.append(str(f))
        else:
            # root + immediate children files
            targets.append(str(p))
        self.start_scan(targets, quick=True)

    def full_scan(self):
        folder = self.folder_var.get().strip()
        p = Path(folder)
        if not p.exists():
            messagebox.showerror("Error", f"Folder does not exist: {folder}")
            return
        self.start_scan([str(p)], quick=False)

    def start_scan(self, target_paths, quick=False):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Scan running", "A scan is already running. Please stop it first.")
            return
        self.should_stop.clear()
        # clear previous results
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.progress["value"] = 0
        self.progress_label.config(text="Scanning...")
        self.scan_thread = threading.Thread(target=self.scan_worker, args=(target_paths, quick), daemon=True)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.should_stop.set()
            self.progress_label.config(text="Stopping...")

    def scan_worker(self, target_paths, quick):
        """Walk target paths and scan files; put results into queue for UI."""
        files = []
        # Build file list conservatively for quick scan
        for tp in target_paths:
            tp_path = Path(tp)
            if quick:
                # add files in top level and common executable dirs
                if tp_path.is_dir():
                    try:
                        for child in tp_path.iterdir():
                            if child.is_file():
                                files.append(str(child))
                            elif child.is_dir():
                                # sample a few subfolders
                                try:
                                    for sub in list(child.glob("*"))[:20]:
                                        if sub.is_file():
                                            files.append(str(sub))
                                except Exception:
                                    pass
                    except Exception:
                        pass
                else:
                    files.append(str(tp_path))
            else:
                # full walk
                for root, _, fnames in os.walk(tp):
                    if self.should_stop.is_set():
                        break
                    for f in fnames:
                        files.append(os.path.join(root, f))
        total = max(1, len(files))
        scanned = 0
        for path in files:
            if self.should_stop.is_set():
                self.scan_queue.put(("status", "Stopped by user"))
                break
            try:
                verdict, reasons = scan_file(path)
                short_reason = reasons[0] if reasons else ""
                self.scan_queue.put(("result", {"path": path, "verdict": verdict, "reason": short_reason, "reasons": reasons}))
            except Exception as e:
                self.scan_queue.put(("result", {"path": path, "verdict": "error", "reason": str(e), "reasons": [str(e)]}))
            scanned += 1
            pct = int((scanned / total) * 100)
            self.scan_queue.put(("progress", pct))
        else:
            # finished normally
            self.scan_queue.put(("status", "Scan complete"))
        self.scan_queue.put(("done", None))

    def process_queue(self):
        """Process messages from scan thread."""
        try:
            while True:
                msg = self.scan_queue.get_nowait()
                typ = msg[0]
                data = msg[1]
                if typ == "result":
                    path = data["path"]
                    verdict = data["verdict"]
                    reason = data["reason"]
                    # insert into tree
                    self.tree.insert("", END, values=(path, verdict, reason))
                    logging.info(f"Scanned: {path} -> {verdict} ({reason})")
                elif typ == "progress":
                    self.progress["value"] = data
                elif typ == "status":
                    self.progress_label.config(text=data)
                elif typ == "done":
                    self.progress_label.config(text="Idle")
                    self.progress["value"] = 0
                else:
                    pass
        except queue.Empty:
            pass
        finally:
            self.root.after(200, self.process_queue)

    # ---------------------------
    # Actions on files
    # ---------------------------

    def _get_selected_paths(self):
        items = self.tree.selection()
        paths = []
        for it in items:
            v = self.tree.item(it, "values")
            if v:
                paths.append(v[0])
        return paths

    def quarantine_selected(self):
        paths = self._get_selected_paths()
        if not paths:
            messagebox.showinfo("No selection", "Select files in the results to quarantine.")
            return
        failed = []
        for p in paths:
            try:
                qpath = quarantine_file(p)
                # update tree: remove the entry since file moved
                # find item and update
                for it in self.tree.get_children():
                    if self.tree.item(it, "values")[0] == p:
                        self.tree.delete(it)
                        break
                self.scan_queue.put(("status", f"Quarantined: {qpath}"))
            except Exception as e:
                failed.append((p, str(e)))
        if failed:
            messagebox.showwarning("Quarantine errors", f"Some files failed to quarantine:\n{failed}")
        else:
            messagebox.showinfo("Quarantine", "Selected files moved to quarantine.")

    def delete_selected(self):
        paths = self._get_selected_paths()
        if not paths:
            messagebox.showinfo("No selection", "Select files in the results to delete.")
            return
        if not messagebox.askyesno("Confirm Delete", f"Delete {len(paths)} file(s) permanently? This cannot be undone."):
            return
        failed = []
        for p in paths:
            try:
                os.remove(p)
                logging.info(f"Deleted {p}")
                # remove from tree
                for it in self.tree.get_children():
                    if self.tree.item(it, "values")[0] == p:
                        self.tree.delete(it)
                        break
            except Exception as e:
                failed.append((p, str(e)))
        if failed:
            messagebox.showwarning("Delete errors", f"Some deletes failed:\n{failed}")
        else:
            messagebox.showinfo("Delete", "Selected files deleted.")

    def restore_dialog(self):
        qidx = load_quarantine_index()
        if not qidx:
            messagebox.showinfo("Quarantine empty", "No files in quarantine.")
            return
        # show a simple selection dialog listing quarantined paths
        choices = list(qidx.keys())
        dlg = ToplevelSelection(self.root, choices)
        self.root.wait_window(dlg.top)
        selected = dlg.selected
        if selected:
            try:
                restore_quarantined(selected)
                messagebox.showinfo("Restore", f"Restored {selected}")
            except Exception as e:
                messagebox.showerror("Restore failed", str(e))

    def open_log_viewer(self):
        try:
            txt = LOG_FILE.read_text()
        except Exception as e:
            txt = f"Could not read log: {e}"
        LogViewer(self.root, txt)

    def refresh_quarantine(self):
        # just reload index and info
        qidx = load_quarantine_index()
        messagebox.showinfo("Quarantine index", f"{len(qidx)} item(s) in quarantine.")


# ---------------------------
# Small helper dialogs
# ---------------------------

class ToplevelSelection:
    def __init__(self, parent, choices):
        self.top = ttk.Frame(parent)
        self.selected = None
        self.win = ttk.Toplevel(parent)
        self.win.title("Select quarantined file to restore")
        self.win.geometry("700x300")
        self.listbox = ttk.Treeview(self.win, columns=("qpath", "orig"), show="headings")
        self.listbox.heading("qpath", text="Quarantined Path")
        self.listbox.heading("orig", text="Original Path")
        self.listbox.column("qpath", width=420)
        self.listbox.column("orig", width=240)
        self.listbox.pack(fill=BOTH, expand=True)
        vsb = ttk.Scrollbar(self.win, orient=VERTICAL, command=self.listbox.yview)
        self.listbox.configure(yscrollcommand=vsb.set)
        vsb.pack(side=RIGHT, fill=Y)
        idx = load_quarantine_index()
        for k, v in idx.items():
            self.listbox.insert("", END, values=(k, v.get("original_path", "")))
        btnf = Frame(self.win)
        btnf.pack(fill="x")
        Button(btnf, text="Restore Selected", command=self._restore).pack(side="left", padx=4, pady=4)
        Button(btnf, text="Cancel", command=self.win.destroy).pack(side="left", padx=4, pady=4)

    def _restore(self):
        sel = self.listbox.selection()
        if not sel:
            messagebox.showinfo("Select", "Select an item to restore.")
            return
        v = self.listbox.item(sel[0], "values")
        self.selected = v[0]
        self.win.destroy()


class LogViewer:
    def __init__(self, parent, text):
        self.win = ttk.Toplevel(parent)
        self.win.title("Log Viewer")
        self.win.geometry("800x500")
        txt = Text(self.win, wrap="none")
        txt.insert(END, text)
        txt.configure(state="disabled")
        txt.pack(fill=BOTH, expand=True)
        # scrollbars
        vsb = Scrollbar(self.win, orient=VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=vsb.set)
        vsb.pack(side=RIGHT, fill=Y)


# ---------------------------
# Main
# ---------------------------

def main():
    root = Tk()
    app = SimpleAVApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
