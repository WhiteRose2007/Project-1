from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.properties import StringProperty, ListProperty
from kivy.lang import Builder
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.clock import mainthread

import os
import subprocess
import json
import threading
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

API_URL = "https://api.onlinehashcrack.com/v2"
CONFIG_FILE = "config.json"

LIGHT_THEME = {
    "bg": [1, 1, 1, 1],
    "fg": [0, 0, 0, 1],
    "entry_bg": [1, 1, 1, 1],
    "entry_fg": [0, 0, 0, 1],
    "button_bg": [0.88, 0.88, 0.88, 1],
    "button_fg": [0, 0, 0, 1],
    "text_bg": [0.96, 0.96, 0.96, 1],
    "text_fg": [0, 0, 0, 1]
}

DARK_THEME = {
    "bg": [0.17, 0.17, 0.17, 1],
    "fg": [0.94, 0.94, 0.94, 1],
    "entry_bg": [0.24, 0.25, 0.25, 1],
    "entry_fg": [1, 1, 1, 1],
    "button_bg": [0.31, 0.31, 0.32, 1],
    "button_fg": [1, 1, 1, 1],
    "text_bg": [0.24, 0.25, 0.25, 1],
    "text_fg": [1, 1, 1, 1]
}

current_theme = LIGHT_THEME

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_config(cfg):
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)

def create_session():
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

def send_hashes(api_key, hash_list):
    payload = {
        "api_key": api_key,
        "agree_terms": "yes",
        "algo_mode": 22000,
        "hashes": hash_list
    }
    headers = {"Content-Type": "application/json"}
    session = create_session()
    r = session.post(API_URL, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def list_tasks(api_key):
    payload = { "api_key": api_key, "agree_terms": "yes", "action": "list_tasks" }
    headers = {"Content-Type": "application/json"}
    session = create_session()
    r = session.post(API_URL, headers=headers, json=payload, timeout=30)
    r.raise_for_status()
    return r.json()

def convert_to_hc22000(cap_path):
    if not os.path.exists(cap_path):
        raise FileNotFoundError("File not found: " + cap_path)
    out_path = cap_path + ".hc22000"
    cmd = ["hcxpcapngtool", "-o", out_path, cap_path]
    proc = subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if not os.path.exists(out_path) or os.path.getsize(out_path) == 0:
        raise RuntimeError("Conversion produced no output.")
    return out_path

def read_first_line(path):
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                return line
    return None

class FileChooserPopup(Popup):
    pass

class RootWidget(BoxLayout):
    api_key = StringProperty("")
    file_path = StringProperty("")
    log_text = StringProperty("")
    tasks_text = StringProperty("")
    theme = DictProperty(current_theme)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        cfg = load_config()
        self.api_key = cfg.get("api_key", "")
        self.theme = current_theme

    def toggle_theme(self):
        global current_theme
        current_theme = DARK_THEME if current_theme == LIGHT_THEME else LIGHT_THEME
        self.theme = current_theme

    def save_api_key(self):
        save_config({"api_key": self.api_key})
        self.append_log("[*] API key saved.")

    def open_file_chooser(self):
        popup = FileChooserPopup(select=self.select_file)
        popup.open()

    def select_file(self, path):
        self.file_path = path

    @mainthread
    def append_log(self, text):
        self.log_text += text + "\n"

    @mainthread
    def set_tasks_text(self, text):
        self.tasks_text = text

    def upload(self):
        self.log_text = ""
        if not self.api_key.strip():
            self.append_log("[-] API key required!")
            return

        hash_list = []
        try:
            if self.file_path:
                ext = self.file_path.lower().split('.')[-1]
                if ext in ("cap", "pcap", "pcapng"):
                    self.append_log("[*] Converting capture file to hc22000 format...")
                    hc_file = convert_to_hc22000(self.file_path)
                    h = read_first_line(hc_file)
                    if not h:
                        self.append_log("[-] No hash extracted from converted file.")
                        return
                    hash_list = [h]
                elif ext == "hc22000":
                    h = read_first_line(self.file_path)
                    if not h:
                        self.append_log("[-] No hash found in file.")
                        return
                    hash_list = [h]
                else:
                    self.append_log("[-] Unsupported file extension.")
                    return
            else:
                self.append_log("[-] Provide a handshake file.")
                return
        except Exception as e:
            self.append_log(f"[-] Error preparing hashes: {e}")
            return

        def thread_upload():
            try:
                resp = send_hashes(self.api_key, hash_list)
                if resp.get("success"):
                    self.append_log("[+] Hashes uploaded successfully.")
                else:
                    self.append_log("[-] Upload error: " + resp.get("message", "Unknown error"))
            except Exception as e:
                self.append_log("[-] Upload failed: " + str(e))

        threading.Thread(target=thread_upload).start()

    def fetch_tasks(self):
        self.tasks_text = ""
        if not self.api_key.strip():
            self.append_log("[-] API key required!")
            return

        def thread_fetch():
            try:
                resp = list_tasks(self.api_key)
                if not resp.get("success"):
                    self.append_log("[-] Error fetching tasks: " + resp.get("message", "Unknown error"))
                    return
                tasks = resp.get("tasks", [])
                if not tasks:
                    self.set_tasks_text("No tasks found.")
                    return
                out = ""
                for t in tasks:
                    status = t.get("status", "unknown")
                    cracked = t.get("cracked", False)
                    pwd = t.get("password", "")
                    tid = t.get("task_id", "")
                    out += (
                        f"Task ID: {tid}\n"
                        f"Status: {status}\n"
                        f"Cracked: {cracked}\n"
                        f"Password: {pwd}\n"
                        + "-"*40 + "\n"
                    )
                self.set_tasks_text(out)
            except Exception as e:
                self.append_log("[-] Fetch tasks failed: " + str(e))

        threading.Thread(target=thread_fetch).start()
