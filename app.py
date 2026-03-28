import customtkinter as ctk
import tkinter.messagebox as messagebox
import threading
import time
from engine.analyzer import URLAnalyzer
from engine.detector import URLDetector
from engine.typosquatting import TyposquattingDetector
from utils.history_manager import HistoryManager
from utils.qr_scanner import QRScanner

# Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

class PhishingDetectorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Phishing URL Detector & Risk Analysis Tool")
        self.geometry("1100x700")

        # Logic Components
        self.history_manager = HistoryManager()
        self.qr_scanner = QRScanner()
        self.debounce_timer = None

        # Grid Layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # Sidebar (History)
        self.sidebar_frame = ctk.CTkFrame(self, width=250, corner_radius=0)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self._setup_sidebar()

        # Main Content
        self.main_frame = ctk.CTkFrame(self)
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        self.main_frame.grid_columnconfigure(0, weight=1)
        self._setup_main_content()

        # Initial history load
        self._refresh_history()

    def _setup_sidebar(self):
        self.sidebar_label = ctk.CTkLabel(self.sidebar_frame, text="Recent Scans", font=ctk.CTkFont(size=20, weight="bold"))
        self.sidebar_label.pack(pady=20, padx=10)

        self.history_scroll = ctk.CTkScrollableFrame(self.sidebar_frame, width=230, height=500)
        self.history_scroll.pack(fill="both", expand=True, padx=10, pady=10)

    def _setup_main_content(self):
        # Header
        self.header_label = ctk.CTkLabel(self.main_frame, text="URL Phishing Analyzer", font=ctk.CTkFont(size=28, weight="bold"))
        self.header_label.grid(row=0, column=0, pady=(10, 20))

        # Input System
        self.input_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.input_frame.grid(row=1, column=0, sticky="ew", padx=20)
        self.input_frame.grid_columnconfigure(0, weight=1)

        self.url_entry = ctk.CTkEntry(self.input_frame, placeholder_text="Enter URL to check (e.g., https://example.com)", height=45)
        self.url_entry.grid(row=0, column=0, sticky="ew", padx=(0, 10))
        self.url_entry.bind("<KeyRelease>", self._on_url_key_release)

        self.scan_btn = ctk.CTkButton(self.input_frame, text="Scan QR", width=120, height=45, fg_color="#3498DB", hover_color="#2980B9", command=self._on_qr_scan)
        self.scan_btn.grid(row=0, column=1)

        # Result Dashboard
        self.result_frame = ctk.CTkFrame(self.main_frame, corner_radius=15, border_width=2, border_color="#333333")
        self.result_frame.grid(row=2, column=0, sticky="nsew", padx=40, pady=30)
        self.result_frame.grid_columnconfigure(0, weight=1)

        # Risk Score Indicator
        self.score_label = ctk.CTkLabel(self.result_frame, text="Risk Level: N/A", font=ctk.CTkFont(size=22, weight="bold"))
        self.score_label.grid(row=0, column=0, pady=(20, 5))

        self.progress_bar = ctk.CTkProgressBar(self.result_frame, width=400, height=15)
        self.progress_bar.grid(row=1, column=0, pady=10)
        self.progress_bar.set(0)

        self.score_value_label = ctk.CTkLabel(self.result_frame, text="Score: 0 / 100", font=ctk.CTkFont(size=14))
        self.score_value_label.grid(row=2, column=0, pady=(0, 20))

        # Details Section
        self.details_scroll = ctk.CTkScrollableFrame(self.result_frame, height=200, fg_color="transparent")
        self.details_scroll.grid(row=3, column=0, sticky="nsew", padx=20, pady=10)
        
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
        # Update labels
        self.score_label.configure(text=f"Risk Level: {result['level']}", text_color=result["color"])
        self.progress_bar.set(result["score"] / 100.0)
        self.progress_bar.configure(progress_color=result["color"])
        self.score_value_label.configure(text=f"Score: {result['score']} / 100")
        self.result_frame.configure(border_color=result["color"])

        # Update details
        for widget in self.details_scroll.winfo_children():
            widget.destroy()

        if not result["reasons"]:
            ctk.CTkLabel(self.details_scroll, text="No immediate phishing indicators found.").pack(pady=5)
        else:
            for reason in result["reasons"]:
                ctk.CTkLabel(self.details_scroll, text=f"• {reason}", anchor="w", justify="left").pack(fill="x", padx=10, pady=2)

        # Update suggestion
        if suggestion:
            self.typo_label.configure(text=f"Typo detected? Did you mean: {suggestion}")
        else:
            self.typo_label.configure(text="")

    def _reset_dashboard(self):
        self.score_label.configure(text="Risk Level: N/A", text_color="white")
        self.progress_bar.set(0)
        self.score_value_label.configure(text="Score: 0 / 100")
        self.result_frame.configure(border_color="#333333")
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
            btn = ctk.CTkButton(self.history_scroll, text=f"{h['url'][:25]}...", 
                                fg_color="transparent", anchor="w", 
                                command=lambda u=h['url']: self._set_url_and_scan(u))
            btn.pack(fill="x", pady=2)

if __name__ == "__main__":
    app = PhishingDetectorApp()
    app.mainloop()
