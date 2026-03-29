import customtkinter as ctk
import tkinter.messagebox as messagebox
import threading
import time
from engine.analyzer import URLAnalyzer
from engine.detector import URLDetector
from engine.typosquatting import TyposquattingDetector
from utils.history_manager import HistoryManager
from utils.qr_scanner import QRScanner
from PIL import Image
import os

# Custom Vibrant Theme
COLORS = {
    "bg_dark": "#0F172A",
    "bg_frame": "#1E293B",
    "primary": "#6366F1",  # Vibrant Indigo
    "secondary": "#06B6D4", # Cyan
    "text_main": "#F8FAFC",
    "text_dim": "#94A3B8",
    "success": "#10B981",
    "warning": "#F59E0B",
    "danger": "#F43F5E"
}


# Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PhishingDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Phishing URL Detector & Risk Analysis Tool")
        self.geometry("1150x750")
        self.configure(fg_color=COLORS["bg_dark"])

        # Logic Components
        self.history_manager = HistoryManager()
        self.qr_scanner = QRScanner()
        self.debounce_timer = None

        # Load Icons
        self._load_icons()

        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)


        # Sidebar (History)
        self.sidebar_frame = ctk.CTkFrame(self, width=280, corner_radius=0, fg_color=COLORS["bg_frame"])
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")

        self._setup_sidebar()

        # Main Content
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=30, pady=30)

        self.main_frame.grid_columnconfigure(0, weight=1)
        self._setup_main_content()

        # Initial history load
        self._refresh_history()

    def _load_icons(self):
        asset_path = os.path.join(os.path.dirname(__file__), "assets")
        self.icons = {
            "logo": ctk.CTkImage(Image.open(os.path.join(asset_path, "logo.png")), size=(60, 60)),
            "search": ctk.CTkImage(Image.open(os.path.join(asset_path, "search.png")), size=(20, 20)),
            "qr": ctk.CTkImage(Image.open(os.path.join(asset_path, "qr.png")), size=(24, 24)),
            "history": ctk.CTkImage(Image.open(os.path.join(asset_path, "history.png")), size=(24, 24)),
            "safe": ctk.CTkImage(Image.open(os.path.join(asset_path, "shield_safe.png")), size=(100, 100)),
            "warning": ctk.CTkImage(Image.open(os.path.join(asset_path, "shield_warning.png")), size=(100, 100)),
            # Use warning as fallback for danger if missing, but we'll use color to differentiate
            "danger": ctk.CTkImage(Image.open(os.path.join(asset_path, "shield_warning.png")), size=(100, 100))
        }

    def _setup_sidebar(self):
        self.sidebar_header = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        self.sidebar_header.pack(pady=(30, 20), padx=20, fill="x")

        self.sidebar_icon = ctk.CTkLabel(self.sidebar_header, text="", image=self.icons["history"])
        self.sidebar_icon.pack(side="left", padx=(0, 10))

        self.sidebar_label = ctk.CTkLabel(self.sidebar_header, text="Recent Scans", 
                                        font=ctk.CTkFont(size=22, weight="bold"),
                                        text_color=COLORS["text_main"])
        self.sidebar_label.pack(side="left")

        self.history_scroll = ctk.CTkScrollableFrame(self.sidebar_frame, width=250, 
                                                    fg_color="transparent",
                                                    scrollbar_button_color=COLORS["bg_frame"],
                                                    scrollbar_button_hover_color=COLORS["primary"])
        self.history_scroll.pack(fill="both", expand=True, padx=15, pady=10)


    def _setup_main_content(self):
        # Header / Branding
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, pady=(0, 30), sticky="ew")
        
        self.logo_label = ctk.CTkLabel(self.header_frame, text="", image=self.icons["logo"])
        self.logo_label.pack(side="left", padx=(0, 20))
        
        self.title_text_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.title_text_frame.pack(side="left")
        
        self.header_label = ctk.CTkLabel(self.title_text_frame, text="URL Guard", 
                                       font=ctk.CTkFont(family="Inter", size=36, weight="bold"),
                                       text_color=COLORS["primary"])
        self.header_label.pack(anchor="w")
        
        self.subtitle_label = ctk.CTkLabel(self.title_text_frame, text="Advanced Phishing Detection & Risk Analysis", 
                                         font=ctk.CTkFont(size=14),
                                         text_color=COLORS["text_dim"])
        self.subtitle_label.pack(anchor="w")

        # Input System
        self.input_container = ctk.CTkFrame(self.main_frame, fg_color=COLORS["bg_frame"], corner_radius=20, height=80)
        self.input_container.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 20))
        self.input_container.grid_propagate(False)
        self.input_container.grid_columnconfigure(1, weight=1)
        self.input_container.grid_rowconfigure(0, weight=1)

        self.search_icon_label = ctk.CTkLabel(self.input_container, text="", image=self.icons["search"])
        self.search_icon_label.grid(row=0, column=0, padx=(20, 10))

        self.url_entry = ctk.CTkEntry(self.input_container, 
                                     placeholder_text="Paste your URL here...", 
                                     height=50,
                                     border_width=0,
                                     fg_color="transparent",
                                     font=ctk.CTkFont(size=16),
                                     text_color=COLORS["text_main"])
        self.url_entry.grid(row=0, column=1, sticky="ew")
        self.url_entry.bind("<KeyRelease>", self._on_url_key_release)

        self.scan_btn = ctk.CTkButton(self.input_container, 
                                     text="SCAN QR", 
                                     image=self.icons["qr"],
                                     compound="left",
                                     width=140, 
                                     height=50, 
                                     corner_radius=12,
                                     fg_color=COLORS["primary"], 
                                     hover_color="#4F46E5", 
                                     font=ctk.CTkFont(weight="bold"),
                                     command=self._on_qr_scan)
        self.scan_btn.grid(row=0, column=2, padx=15)

        # Result Dashboard
        self.result_frame = ctk.CTkFrame(self.main_frame, corner_radius=25, 
                                        fg_color=COLORS["bg_frame"],
                                        border_width=2, border_color="#1E293B")
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=10, pady=10)
        self.result_frame.grid_columnconfigure(0, weight=1)

        # Status Visual
        self.status_icon_label = ctk.CTkLabel(self.result_frame, text="", image=self.icons["safe"])
        self.status_icon_label.grid(row=0, column=0, pady=(30, 10))

        self.score_label = ctk.CTkLabel(self.result_frame, text="Ready to scan", 
                                      font=ctk.CTkFont(size=28, weight="bold"),
                                      text_color=COLORS["text_main"])
        self.score_label.grid(row=1, column=0, pady=(0, 5))

        self.progress_bar = ctk.CTkProgressBar(self.result_frame, width=500, height=12, 
                                              corner_radius=6,
                                              fg_color="#0F172A",
                                              progress_color=COLORS["primary"])
        self.progress_bar.grid(row=2, column=0, pady=15)
        self.progress_bar.set(0)

        self.score_value_label = ctk.CTkLabel(self.result_frame, text="0 / 100", 
                                            font=ctk.CTkFont(size=14),
                                            text_color=COLORS["text_dim"])
        self.score_value_label.grid(row=3, column=0, pady=(0, 25))

        # Details Section
        self.details_label = ctk.CTkLabel(self.result_frame, text="DETECTION DETAILS", 
                                         font=ctk.CTkFont(size=12, weight="bold"),
                                         text_color=COLORS["text_dim"])
        self.details_label.grid(row=4, column=0, sticky="w", padx=40)

        self.details_scroll = ctk.CTkScrollableFrame(self.result_frame, height=180, 
                                                    fg_color="#0F172A",
                                                    corner_radius=15)
        self.details_scroll.grid(row=5, column=0, sticky="nsew", padx=40, pady=(5, 30))

        
        # Typosquatting Suggestion
        self.typo_label = ctk.CTkLabel(self.main_frame, text="", text_color="#E67E22", font=ctk.CTkFont(slant="italic"))
        self.typo_label.grid(row=3, column=0, pady=5)

    def _on_url_key_release(self, event):
        """Real-time debouncing for analysis."""
        if self.debounce_timer:
            self.after_cancel(self.debounce_timer)
        self.debounce_timer = self.after(500, self._perform_analysis)

    def _perform_analysis(self):
        url = self.url_entry.get().strip()
        if not url:
            self._reset_dashboard()
            return

        def task():
            try:
                # Analyzer
                analyzer = URLAnalyzer(url)
                features = analyzer.get_features()
                
                # Detector
                detector = URLDetector(features, url)
                result = detector.detect()

                # Typosquatting
                typo_detector = TyposquattingDetector(analyzer.domain)
                suggestion = typo_detector.check()

                # Update UI in main thread
                self.after(0, lambda: self._update_results_ui(result, suggestion))
                
                # Update history if score is meaningful
                self.history_manager.add_to_history(url, result["score"], result["level"], result["reasons"])
                self.after(0, self._refresh_history)

            except Exception as e:
                print(f"Error analyzing URL: {e}")

        threading.Thread(target=task, daemon=True).start()

    def _update_results_ui(self, result, suggestion):
        # Update colors based on risk
        color = result["color"]
        if result["level"] == "Safe":
            icon = self.icons["safe"]
            color = COLORS["success"]
        elif result["level"] == "Suspicious":
            icon = self.icons["warning"]
            color = COLORS["warning"]
        else:
            icon = self.icons["danger"]
            color = COLORS["danger"]

        # Update labels & icon
        self.status_icon_label.configure(image=icon)
        self.score_label.configure(text=f"{result['level']} Site", text_color=color)
        self.progress_bar.set(result["score"] / 100.0)
        self.progress_bar.configure(progress_color=color)
        self.score_value_label.configure(text=f"Health Score: {100 - result['score']} / 100")
        self.result_frame.configure(border_color=color)

        # Update details
        for widget in self.details_scroll.winfo_children():
            widget.destroy()

        if not result["reasons"]:
            ctk.CTkLabel(self.details_scroll, text="✓ This URL passes all security checks.", 
                        text_color=COLORS["success"], font=ctk.CTkFont(weight="bold")).pack(pady=20)
        else:
            for reason in result["reasons"]:
                item = ctk.CTkFrame(self.details_scroll, fg_color="transparent")
                item.pack(fill="x", padx=10, pady=5)
                ctk.CTkLabel(item, text="!", text_color=color, font=ctk.CTkFont(size=16, weight="bold")).pack(side="left", padx=(0, 10))
                ctk.CTkLabel(item, text=reason, anchor="w", justify="left", wraplength=400,
                            text_color=COLORS["text_main"]).pack(side="left", fill="x")


        # Update suggestion
        if suggestion:
            self.typo_label.configure(text=f"Typo detected? Did you mean: {suggestion}")
        else:
            self.typo_label.configure(text="")

    def _reset_dashboard(self):
        self.status_icon_label.configure(image=self.icons["safe"])
        self.score_label.configure(text="Ready to scan", text_color=COLORS["text_main"])
        self.progress_bar.set(0)
        self.score_value_label.configure(text="0 / 100")
        self.result_frame.configure(border_color="#1E293B")
        for widget in self.details_scroll.winfo_children():
            widget.destroy()
        self.typo_label.configure(text="")


    def _on_qr_scan(self):
        # Open a selection menu or camera directly
        def initiate_scan():
            val, err = self.qr_scanner.scan_from_camera()
            if val:
                self.after(0, lambda: self._set_url_and_scan(val))
            elif err:
                self.after(0, lambda: messagebox.showwarning("QR Scan Info", f"Status: {err}"))

        threading.Thread(target=initiate_scan, daemon=True).start()

    def _set_url_and_scan(self, url):
        self.url_entry.delete(0, 'end')
        self.url_entry.insert(0, url)
        self._perform_analysis()

    def _refresh_history(self):
        for widget in self.history_scroll.winfo_children():
            widget.destroy()
        
        history = self.history_manager.get_history()
        for h in history:
            color = COLORS["success"] if h['level'] == "Safe" else COLORS["warning"] if h['level'] == "Suspicious" else COLORS["danger"]
            
            card = ctk.CTkFrame(self.history_scroll, fg_color=COLORS["bg_dark"], corner_radius=10)
            card.pack(fill="x", pady=5, padx=5)
            
            btn = ctk.CTkButton(card, text=f"{h['url'][:22]}...", 
                                fg_color="transparent", anchor="w",
                                hover_color=COLORS["bg_frame"],
                                text_color=COLORS["text_main"],
                                command=lambda u=h['url']: self._set_url_and_scan(u))
            btn.pack(side="left", fill="x", expand=True, padx=5, pady=5)
            
            indicator = ctk.CTkLabel(card, text="●", text_color=color, font=ctk.CTkFont(size=14))
            indicator.pack(side="right", padx=10)


if __name__ == "__main__":
    app = PhishingDetectorApp()
    app.mainloop()
