#!/usr/bin/env python3
"""
P12 Password Cracker & Changer GUI - UI for the P12 Password Cracker tool made by nabzclan.vip
Powered by Nabzclan Developer API
"""

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import requests
import json
from colorama import init, Fore
from PIL import Image, ImageTk, ImageDraw, ImageFont
import io
import base64
import subprocess

from main import (
    API_KEY, CRACK_ENDPOINT, CHANGE_ENDPOINT, VERIFY_ENDPOINT,
    verify_p12_password, validate_p12_file, validate_url, is_local_file,
    crack_p12_password, change_p12_password, download_file, check_api_key,
    is_vip_user, show_usage_info, get_user_profile
)

init(autoreset=True)

class RedirectText:
    """Class to redirect stdout to a tkinter Text widget"""
    def __init__(self, text_widget):
        self.text_widget = text_widget
        self.buffer = ""
        
    def write(self, string):
        string = self._strip_ansi_codes(string)
        self.buffer += string
        
        if '\n' in self.buffer:
            lines = self.buffer.split('\n')
            self.buffer = lines[-1] 
            
            for line in lines[:-1]:
                self.text_widget.configure(state='normal')
                
                if "[+]" in line:
                    self.text_widget.insert(tk.END, line + '\n', "success")
                elif "[!]" in line:
                    self.text_widget.insert(tk.END, line + '\n', "error")
                elif "[*]" in line:
                    self.text_widget.insert(tk.END, line + '\n', "info")
                elif "PASSWORD FOUND" in line:
                    self.text_widget.insert(tk.END, line + '\n', "password")
                else:
                    self.text_widget.insert(tk.END, line + '\n')
                
                self.text_widget.configure(state='disabled')
                self.text_widget.see(tk.END) 
                
    def _strip_ansi_codes(self, s):
        """Strip ANSI color codes from string"""
        import re
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', s)
    
    def flush(self):
        pass


class P12CrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("P12 Password Cracker & Changer (v2.0) - Nabzclan")
        self.root.geometry("900x750")
        

        self.root.minsize(850, 700)
        
        self.bg_color = "#2E3440"  # Dark blue-gray
        self.accent_color = "#88C0D0"  # Cyan
        self.text_color = "#ECEFF4"  # Off-white
        self.success_color = "#A3BE8C"  # Green
        self.error_color = "#BF616A"  # Red
        self.warning_color = "#EBCB8B"  # Yellow
        self.info_color = "#81A1C1"  # Light blue
        
        self.root.configure(bg=self.bg_color)
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        self.style.configure('TFrame', background=self.bg_color)
        self.style.configure('TLabel', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 18, 'bold'), background=self.bg_color, foreground=self.accent_color)
        
        self.style.configure('TButton', font=('Segoe UI', 10), background=self.accent_color, foreground=self.bg_color)
        self.style.map('TButton', 
                     background=[('active', self.info_color), ('pressed', self.accent_color)],
                     foreground=[('active', self.bg_color), ('pressed', self.bg_color)])
        
        self.style.configure('TNotebook', background=self.bg_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', background=self.bg_color, foreground=self.text_color, 
                           padding=[10, 5], font=('Segoe UI', 10))
        self.style.map('TNotebook.Tab', 
                     background=[('selected', self.accent_color)],
                     foreground=[('selected', self.bg_color)])
        
        self.style.configure('TEntry', fieldbackground="#3B4252", foreground=self.text_color)
        self.style.configure('TCheckbutton', background=self.bg_color, foreground=self.text_color)
        self.style.map('TCheckbutton', background=[('active', self.bg_color)])
        self.style.configure('TRadiobutton', background=self.bg_color, foreground=self.text_color)
        self.style.map('TRadiobutton', background=[('active', self.bg_color)])
        self.style.configure('TLabelframe', background=self.bg_color, foreground=self.accent_color)
        self.style.configure('TLabelframe.Label', background=self.bg_color, foreground=self.accent_color, font=('Segoe UI', 11, 'bold'))
        
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.crack_tab = ttk.Frame(self.notebook)
        self.change_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.crack_tab, text='Crack Password')
        self.notebook.add(self.change_tab, text='Change Password')
        self.notebook.add(self.about_tab, text='About')
        
        self.init_crack_tab()
        self.init_change_tab()
        self.init_about_tab()
        
        self.create_console_output()
        
        self.stdout_redirect = RedirectText(self.console_text)
        self.old_stdout = sys.stdout
        sys.stdout = self.stdout_redirect
        
        self.cancel_event = threading.Event()
        
        try:
            check_api_key()
        except SystemExit:
                messagebox.showerror("API Key Error", 
                               "API key is not set or valid.\n\nPlease check your configuration file.")
        
        # Show fullscreen recommendation popup after a short delay
        self.root.after(500, self.show_fullscreen_tip)

    def send_notification(self, title, message):
        """Send a macOS system notification via AppleScript"""
        try:
            script = f'display notification "{message}" with title "{title}" subtitle "P12 Cracker" sound name "default"'
            subprocess.run(['osascript', '-e', script])
        except Exception as e:
            print(f"[!] Notification Error: {e}")

    def show_fullscreen_tip(self):
        """Show a tip recommending fullscreen mode"""
        messagebox.showinfo(
            "Display Recommendation", 
            "For the best experience and to see all features clearly, \nwe recommend maximizing the window or using full screen."
        )
    
    def create_console_output(self):
        """Create the console output area"""
        output_frame = ttk.LabelFrame(self.root, text="Console Output")
        output_frame.pack(fill='both', expand=True, padx=5, pady=(0, 5))
        
        self.console_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD,
                                                   width=80, height=6,
                                                   font=('Consolas', 9),
                                                   bg="#2E3440", fg="#D8DEE9",
                                                   insertbackground="#D8DEE9",
                                                   selectbackground="#4C566A",
                                                   selectforeground="#ECEFF4",
                                                   relief=tk.FLAT,
                                                   padx=5, pady=5)
        self.console_text.pack(fill='both', expand=True, padx=5, pady=5)
        self.console_text.configure(state='disabled')
        
        self.console_text.tag_configure("success", foreground=self.success_color)
        self.console_text.tag_configure("error", foreground=self.error_color)
        self.console_text.tag_configure("info", foreground=self.info_color)
        self.console_text.tag_configure("warning", foreground=self.warning_color)
        self.console_text.tag_configure("password", foreground=self.success_color, font=('Consolas', 11, 'bold'))
        
        btn_frame = ttk.Frame(output_frame)
        btn_frame.pack(fill='x', padx=5, pady=5)
        
        self.style.configure('Clear.TButton', background="#4C566A")
        self.style.configure('Cancel.TButton', background=self.error_color)
        
        clear_btn = ttk.Button(btn_frame, text="Clear Console", style="Clear.TButton", command=self.clear_console)
        clear_btn.pack(side='left', padx=5)
        
        self.cancel_btn = ttk.Button(btn_frame, text="STOP 🛑", style="Cancel.TButton", command=self.cancel_operation)
        self.cancel_btn.pack(side='right', padx=5)
        self.cancel_btn.configure(state='disabled') 
    
    def init_crack_tab(self):
        """Initialize the crack password tab"""
        main_frame = ttk.Frame(self.crack_tab)
        main_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 15))

        header_label = ttk.Label(header_frame, text="Crack P12 Password", style='Header.TLabel')
        header_label.pack(side='left', pady=5)
        
        file_frame = ttk.LabelFrame(main_frame, text="P12 File Selection")
        file_frame.pack(fill='x', padx=5, pady=10)
        
        file_content = ttk.Frame(file_frame)
        file_content.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(file_content, text="P12 File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        self.p12_path_var = tk.StringVar()
        p12_entry = ttk.Entry(file_content, textvariable=self.p12_path_var, width=50)
        p12_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        
        self.style.configure('Browse.TButton', background="#5E81AC")
        browse_btn = ttk.Button(file_content, text="Browse", style="Browse.TButton", command=self.browse_p12_file)
        browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        file_content.grid_columnconfigure(1, weight=1)
        
        method_frame = ttk.LabelFrame(main_frame, text="Cracking Method")
        method_frame.pack(fill='x', padx=5, pady=10)
        
        method_content = ttk.Frame(method_frame)
        method_content.pack(fill='x', padx=10, pady=10)
        
        self.crack_method = tk.StringVar(value="smart")
        
        self.style.configure('Crack.TRadiobutton', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        
        # Smart mode (default)
        ttk.Radiobutton(method_content, text="Smart Mode (Recommended)", variable=self.crack_method,
                      value="smart", style='Crack.TRadiobutton', command=self.update_crack_ui).grid(
            row=0, column=0, sticky='w', padx=5, pady=8)
        
        ttk.Label(method_content, text="Uses common P12 passwords", 
                 font=('Segoe UI', 8, 'italic'), foreground=self.info_color).grid(
            row=0, column=1, sticky='w', padx=5, pady=8)
        
        # Single password
        ttk.Radiobutton(method_content, text="Single Password", variable=self.crack_method,
                      value="single", style='Crack.TRadiobutton', command=self.update_crack_ui).grid(
            row=1, column=0, sticky='w', padx=5, pady=8)
        
        self.single_pass_var = tk.StringVar()
        self.single_pass_entry = ttk.Entry(method_content, textvariable=self.single_pass_var, width=40, state='disabled')
        self.single_pass_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=8)
        
        self.show_password_var = tk.BooleanVar(value=True)
        show_pass_check = ttk.Checkbutton(method_content, text="Show",
                                       variable=self.show_password_var,
                                       command=self.toggle_password_visibility)
        show_pass_check.grid(row=1, column=2, padx=5, pady=8)
        
        # Custom wordlist
        ttk.Radiobutton(method_content, text="Custom Wordlist", variable=self.crack_method,
                      value="wordlist", style='Crack.TRadiobutton', command=self.update_crack_ui).grid(
            row=2, column=0, sticky='w', padx=5, pady=8)
        
        self.wordlist_path_var = tk.StringVar()
        self.wordlist_entry = ttk.Entry(method_content, textvariable=self.wordlist_path_var, width=40, state='disabled')
        self.wordlist_entry.grid(row=2, column=1, sticky='ew', padx=5, pady=8)
        
        self.wordlist_browse_btn = ttk.Button(method_content, text="Browse", style="Browse.TButton",
                                           command=self.browse_wordlist, state='disabled')
        self.wordlist_browse_btn.grid(row=2, column=2, padx=5, pady=8)
        
        # Brute force mode (VIP only)
        ttk.Radiobutton(method_content, text="Brute Force (VIP ⭐️)", variable=self.crack_method,
                      value="brute", style='Crack.TRadiobutton', command=self.update_crack_ui).grid(
            row=3, column=0, sticky='w', padx=5, pady=8)
        
        brute_options = ttk.Frame(method_content)
        brute_options.grid(row=3, column=1, sticky='w', padx=5, pady=8)
        
        ttk.Label(brute_options, text="Charset:").pack(side='left', padx=(0, 5))
        self.charset_var = tk.StringVar(value="abcdefghijklmnopqrstuvwxyz0123456789")
        self.charset_entry = ttk.Entry(brute_options, textvariable=self.charset_var, width=20, state='disabled')
        self.charset_entry.pack(side='left', padx=(0, 10))
        
        ttk.Label(brute_options, text="Max Length:").pack(side='left', padx=(0, 5))
        self.max_length_var = tk.StringVar(value="4")
        self.max_length_entry = ttk.Entry(brute_options, textvariable=self.max_length_var, width=5, state='disabled')
        self.max_length_entry.pack(side='left')
        
        method_content.grid_columnconfigure(1, weight=1)
        
        password_frame = ttk.LabelFrame(main_frame, text="Password Change Options")
        password_frame.pack(fill='x', padx=5, pady=10)
        
        password_content = ttk.Frame(password_frame)
        password_content.pack(fill='x', padx=10, pady=10)
        
        self.change_after_crack_var = tk.BooleanVar(value=False)
        change_after_crack_chk = ttk.Checkbutton(password_content, text="Change password if cracking succeeds",
                                               variable=self.change_after_crack_var,
                                               command=self.update_crack_ui)
        change_after_crack_chk.grid(row=0, column=0, sticky='w', padx=5, pady=8, columnspan=2)
        
        ttk.Label(password_content, text="New Password:").grid(row=1, column=0, sticky='w', padx=5, pady=8)
        
        self.new_pass_var = tk.StringVar()
        self.new_pass_entry = ttk.Entry(password_content, textvariable=self.new_pass_var, width=30, state='disabled')
        self.new_pass_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=8)
        
        password_content.grid_columnconfigure(1, weight=1)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', padx=5, pady=15)
        
        self.style.configure('Start.TButton', 
                           background=self.success_color, 
                           foreground=self.bg_color,
                           font=('Segoe UI', 14, 'bold'),
                           borderwidth=2,
                           relief='raised')
        self.style.map('Start.TButton', 
                     background=[('active', '#8FBCBB'), ('pressed', self.success_color)])
        
        crack_btn = ttk.Button(button_frame, text="▶ START CRACKING", style="Start.TButton", command=self.start_cracking)
        crack_btn.pack(side='top', padx=5, pady=5, ipadx=20, ipady=10, anchor='center', expand=True)

        separator = ttk.Separator(button_frame, orient='horizontal')
        separator.pack(fill='x', pady=5)
        
        self.help_expanded = tk.BooleanVar(value=False)
        help_header = ttk.Frame(main_frame)
        help_header.pack(fill='x', padx=5, pady=2)
        
        help_toggle = ttk.Checkbutton(help_header, text="Show Help", 
                                   variable=self.help_expanded,
                                   command=self.toggle_help_visibility,
                                   style='TCheckbutton')
        help_toggle.pack(side='left', padx=5)
        
        self.help_frame = ttk.LabelFrame(main_frame, text="Help")
        
        help_content = ttk.Frame(self.help_frame)
        help_content.pack(fill='x', padx=10, pady=10)
        
        help_text = ("To crack a P12 certificate password:\n"
                   "1. Select your P12 file or enter a URL\n"
                   "2. Choose either a single password attempt or select a local wordlist file\n"
                   "3. Optionally enable changing the password if found\n"
                   "4. Click 'Start Cracking' to begin")
        
        ttk.Label(help_content, text=help_text, justify='left').pack(padx=5, pady=5, anchor='w')
    
    def toggle_password_visibility(self):
        """Toggle password visibility for password fields"""
        if self.show_password_var.get():
            self.single_pass_entry.configure(show="")
            self.new_pass_entry.configure(show="")
        else:
            self.single_pass_entry.configure(show="•")
            self.new_pass_entry.configure(show="•")
            
    def toggle_help_visibility(self):
        """Toggle visibility of help frame in crack tab"""
        if self.help_expanded.get():
            self.help_frame.pack(fill='x', padx=5, pady=5)
        else:
            self.help_frame.pack_forget()
            
    def toggle_change_help_visibility(self):
        """Toggle visibility of help frame in change tab"""
        if self.change_help_expanded.get():
            self.change_help_frame.pack(fill='x', padx=5, pady=5)
        else:
            self.change_help_frame.pack_forget()
    
    def init_change_tab(self):
        """Initialize the change password tab"""

        main_frame = ttk.Frame(self.change_tab)
        main_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill='x', pady=(0, 15))
        
        header_label = ttk.Label(header_frame, text="Change P12 Password", style='Header.TLabel')
        header_label.pack(side='left', pady=5)
        
        file_frame = ttk.LabelFrame(main_frame, text="P12 File Selection")
        file_frame.pack(fill='x', padx=5, pady=10)
        
        file_content = ttk.Frame(file_frame)
        file_content.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(file_content, text="P12 File:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
        
        self.change_p12_path_var = tk.StringVar()
        change_p12_entry = ttk.Entry(file_content, textvariable=self.change_p12_path_var, width=50)
        change_p12_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=5)
        
        change_browse_btn = ttk.Button(file_content, text="Browse", style="Browse.TButton", command=self.browse_change_p12_file)
        change_browse_btn.grid(row=0, column=2, padx=5, pady=5)
        
        file_content.grid_columnconfigure(1, weight=1)
        
        password_frame = ttk.LabelFrame(main_frame, text="Password Information")
        password_frame.pack(fill='x', padx=5, pady=10)
        
        password_content = ttk.Frame(password_frame)
        password_content.pack(fill='x', padx=10, pady=10)
        
        ttk.Label(password_content, text="Current Password:").grid(row=0, column=0, sticky='w', padx=5, pady=8)
        self.old_pass_var = tk.StringVar()
        self.old_pass_entry = ttk.Entry(password_content, textvariable=self.old_pass_var, width=30)
        self.old_pass_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=8)
        
        ttk.Label(password_content, text="New Password:").grid(row=1, column=0, sticky='w', padx=5, pady=8)
        self.change_new_pass_var = tk.StringVar()
        self.change_new_pass_entry = ttk.Entry(password_content, textvariable=self.change_new_pass_var, width=30)
        self.change_new_pass_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=8)
        
        self.change_show_password_var = tk.BooleanVar(value=True)
        change_show_pass_check = ttk.Checkbutton(password_content, text="Show passwords",
                                             variable=self.change_show_password_var,
                                             command=self.toggle_change_password_visibility)
        change_show_pass_check.grid(row=2, column=1, sticky='w', padx=5, pady=8)
        
        password_content.grid_columnconfigure(1, weight=1)
        
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill='x', padx=5, pady=15)
        
        self.style.configure('Change.TButton', 
                           background="#B48EAD", 
                           foreground=self.bg_color,
                           font=('Segoe UI', 14, 'bold'),
                           borderwidth=2,
                           relief='raised')
        self.style.map('Change.TButton', 
                     background=[('active', '#d8b9fa'), ('pressed', '#B48EAD')])
        
        change_btn = ttk.Button(button_frame, text="▶ CHANGE PASSWORD", style="Change.TButton", command=self.start_changing)
        change_btn.pack(side='top', padx=5, pady=5, ipadx=20, ipady=10, anchor='center', expand=True)
        
        separator = ttk.Separator(button_frame, orient='horizontal')
        separator.pack(fill='x', pady=5)
        
        self.change_help_expanded = tk.BooleanVar(value=False)
        help_header = ttk.Frame(main_frame)
        help_header.pack(fill='x', padx=5, pady=2)
        
        help_toggle = ttk.Checkbutton(help_header, text="Show Help", 
                                   variable=self.change_help_expanded,
                                   command=self.toggle_change_help_visibility,
                                   style='TCheckbutton')
        help_toggle.pack(side='left', padx=5)
        
        self.change_help_frame = ttk.LabelFrame(main_frame, text="Help")
        
        help_content = ttk.Frame(self.change_help_frame)
        help_content.pack(fill='x', padx=10, pady=10)
        
        help_text = ("To change a P12 certificate password:\n"
                   "1. Select your P12 file or enter a URL\n"
                   "2. Enter the current password\n"
                   "3. Enter the new password you want to set\n"
                   "4. Click 'Change Password' to begin")
        
        ttk.Label(help_content, text=help_text, justify='left').pack(padx=5, pady=5, anchor='w')
    
    def toggle_change_password_visibility(self):
        """Toggle password visibility for password fields in change tab"""
        if self.change_show_password_var.get():
            self.old_pass_entry.configure(show="")
            self.change_new_pass_entry.configure(show="")
        else:
            self.old_pass_entry.configure(show="•")
            self.change_new_pass_entry.configure(show="•")
    
    def init_about_tab(self):
        """Initialize the About tab"""
        # Clear any existing widgets
        for widget in self.about_tab.winfo_children():
            widget.destroy()
            
        main_frame = ttk.Frame(self.about_tab)
        main_frame.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Banner using text
        banner_font = ('Segoe UI', 24, 'bold')
        ttk.Label(main_frame, text="P12 Password Cracker", 
                 font=banner_font, foreground=self.accent_color).pack(pady=(10, 5))
        
        ttk.Label(main_frame, text="v2.0 - GUI Edition", 
                 font=('Segoe UI', 12), foreground=self.text_color).pack(pady=(0, 20))
        
        # Features
        features_frame = ttk.LabelFrame(main_frame, text="Features")
        features_frame.pack(fill='x', padx=5, pady=10)
        
        features_content = ttk.Frame(features_frame)
        features_content.pack(fill='x', padx=10, pady=10)
        
        features_text = (
            "• Smart Mode: Uses common P12 passwords patterns (Recommended)\n"
            "• Dictionary Attack: Supports custom wordlist files\n"
            "• Brute Force ⭐️: Comprehensive attack for short passwords (VIP only)\n"
            "• Single Password Verification: Quickly check a specific password\n"
            "• Password Changer: Change P12 password directly\n"
            "• Direct File Upload: Securely process local files via API"
        )
        
        ttk.Label(features_content, text=features_text, justify='left').pack(
            padx=5, pady=5, fill='x', anchor='w')
        
        # User Status Section
        status_frame = ttk.LabelFrame(main_frame, text="User Status")
        status_frame.pack(fill='x', padx=5, pady=10)
        
        status_content = ttk.Frame(status_frame)
        status_content.pack(fill='x', padx=10, pady=10)
        
        try:
            profile = get_user_profile()
            if profile:
                plan_name = profile.get('plan', {}).get('name', 'Free')
                user_name = profile.get('name', 'Unknown')
                user_id = profile.get('nabzclan_user_id', 'N/A')
                
                usage = profile.get('usage', {})
                limit = usage.get('limit', 0)
                limit_str = "Unlimited" if limit == -1 else str(limit)
                
                # Row 1: User Info
                ttk.Label(status_content, text=f"User: {user_name} (ID: {user_id})", 
                         style='APIStatus.TLabel').pack(anchor='w', padx=5)
                
                # Row 2: Plan Info (using frame for alignment)
                plan_frame = ttk.Frame(status_content)
                plan_frame.pack(anchor='w', padx=5)
                
                ttk.Label(plan_frame, text=f"Plan: {plan_name}", 
                         style='APIStatus.TLabel').pack(side='left')
                
                if 'vip' not in plan_name.lower():
                     ttk.Label(plan_frame, text=" (Upgrade for Brute Force)", 
                             foreground=self.warning_color, font=('Segoe UI', 9, 'italic')).pack(side='left', padx=5)
                
                # Row 3: Limits
                ttk.Label(status_content, text=f"Daily Limit: {limit_str}", 
                         style='APIStatus.TLabel').pack(anchor='w', padx=5)
            else:
                ttk.Label(status_content, text="Could not fetch user profile. Check API key.", foreground=self.error_color).pack(anchor='w', padx=5)
        except Exception:
             ttk.Label(status_content, text="Error loading profile", foreground=self.error_color).pack()

        # Credits
        credits_frame = ttk.LabelFrame(main_frame, text="Credits")
        credits_frame.pack(fill='x', padx=5, pady=10)
        
        credits_content = ttk.Frame(credits_frame)
        credits_content.pack(fill='x', padx=10, pady=10)
        
        credits_text = "Powered by Nabzclan Developer platform \nGUI created to make it easier for users to use the API"
        ttk.Label(credits_content, text=credits_text, justify='center').pack(padx=5, pady=5)
        
        copyright_text = "Nabz Clan © 2027 All Rights Reserved - nabzclan.vip"
        copyright_label = ttk.Label(main_frame, text=copyright_text,
                                 font=('Segoe UI', 8), foreground="#6c7a89")
        copyright_label.pack(pady=(15, 5))
    
    def browse_p12_file(self):
        """Open file dialog to select a P12 file"""
        filetypes = [("P12 Files", "*.p12"), ("All Files", "*.*")]
        filename = filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            self.p12_path_var.set(filename)
    
    def browse_change_p12_file(self):
        """Open file dialog to select a P12 file for the change tab"""
        filetypes = [("P12 Files", "*.p12"), ("All Files", "*.*")]
        filename = filedialog.askopenfilename(filetypes=filetypes)
        if filename:
            self.change_p12_path_var.set(filename)
    
    def browse_wordlist(self):
        """Open file dialog to select a local wordlist file"""
        filetypes = [("Text Files", "*.txt"), ("Word Lists", "*.lst"), ("Dictionary Files", "*.dict"), ("All Files", "*.*")]
        
        filename = filedialog.askopenfilename(
            title="Select Local Wordlist File",
            filetypes=filetypes
        )
        
        if filename:
            if os.path.exists(filename) and os.path.isfile(filename):
                self.wordlist_path_var.set(filename)
            else:
                messagebox.showerror("Invalid File", "The selected file does not exist or is not accessible.")
                return
    
    def update_crack_ui(self):
        """Update UI elements based on selected options"""
        method = self.crack_method.get()
        
        # Reset all to disabled first
        self.single_pass_entry.configure(state='disabled')
        self.wordlist_entry.configure(state='disabled')
        self.wordlist_browse_btn.configure(state='disabled')
        self.charset_entry.configure(state='disabled')
        self.max_length_entry.configure(state='disabled')
        
        if method == "single":
            self.single_pass_entry.configure(state='normal')
        elif method == "wordlist":
            self.wordlist_entry.configure(state='normal')
            self.wordlist_browse_btn.configure(state='normal')
        elif method == "brute":
            self.charset_entry.configure(state='normal')
            self.max_length_entry.configure(state='normal')
        # smart mode doesn't need any additional input
        
        if self.change_after_crack_var.get():
            self.new_pass_entry.configure(state='normal')
        else:
            self.new_pass_entry.configure(state='disabled')
    
    def clear_console(self):
        """Clear the console output"""
        self.console_text.configure(state='normal')
        self.console_text.delete(1.0, tk.END)
        self.console_text.configure(state='disabled')
    
    def cancel_operation(self):
        """Cancel the current operation"""
        self.cancel_event.set()
        print("[!] Cancelling operation...")
        self.cancel_btn.configure(state='disabled')
    
    def start_cracking(self):
        """Start the password cracking process"""
        p12_path = self.p12_path_var.get().strip()
        if not p12_path:
            messagebox.showerror("Error", "Please select a P12 file")
            return
        
        method = self.crack_method.get()
        if method == "single":
            password = self.single_pass_var.get().strip()
            if not password:
                messagebox.showerror("Error", "Please enter a password to try")
                return
        elif method == "wordlist":
            wordlist = self.wordlist_path_var.get().strip()
            if not wordlist:
                messagebox.showerror("Error", "Please select a wordlist file")
                return
        elif method == "brute":
            try:
                max_len = int(self.max_length_var.get())
                if max_len > 6:
                    messagebox.showerror("Error", "Maximum password length for brute force is 6")
                    return
            except ValueError:
                messagebox.showerror("Error", "Invalid max length value")
                return
        
        if self.change_after_crack_var.get():
            new_password = self.new_pass_var.get().strip()
            if not new_password:
                messagebox.showerror("Error", "Please enter a new password")
                return
        
        self.cancel_event.clear()
        self.cancel_btn.configure(state='normal')
        
        threading.Thread(target=self.crack_thread, daemon=True).start()
    
    def crack_thread(self):
        """Thread function for password cracking"""
        try:
            p12_path = self.p12_path_var.get().strip()
            

            if not os.path.exists(p12_path):
                messagebox.showerror("Error", f"P12 file not found: {p12_path}")
                self.cancel_btn.configure(state='disabled')
                return
            
            if not os.path.isfile(p12_path):
                messagebox.showerror("Error", f"Path is not a file: {p12_path}")
                self.cancel_btn.configure(state='disabled')
                return
            
            print(f"[*] P12 file validated: {p12_path}")
            
            method = self.crack_method.get()
            success = False
            password = None
            
            if method == "smart":

                print(f"[*] Mode: Smart Attack (using common P12 passwords)")
                success, password, _ = crack_p12_password(p12_path, mode='smart')
                
            elif method == "single":

                test_password = self.single_pass_var.get().strip()
                print(f"[*] Mode: Single Password Verification")
                success, password, _ = verify_p12_password(p12_path, test_password)
                
            elif method == "wordlist":

                wordlist_path = self.wordlist_path_var.get().strip()
                if not os.path.exists(wordlist_path):
                    messagebox.showerror("Error", f"The wordlist file '{wordlist_path}' does not exist.\n\nPlease select a valid local wordlist file.")
                    self.cancel_btn.configure(state='disabled')
                    return
                
                print(f"[*] Mode: Dictionary Attack")

                is_vip, _ = is_vip_user()
                if not is_vip:
                    print(f"[*] Limits: Free=1,000 passwords, VIP=50MB. See: https://developer.nabzclan.vip/docs/endpoints/p12-cracker")
                success, password, _ = crack_p12_password(p12_path, mode='dictionary', wordlist=wordlist_path)
                
            elif method == "brute":

                print(f"[*] Mode: Brute Force Attack (VIP only ⭐️)")
                

                is_vip, plan_name = is_vip_user()
                if not is_vip:
                    print(f"[!] Error: Brute force mode requires a VIP subscription")
                    print(f"[*] Your current plan: {plan_name or 'Free'}")
                    print(f"[*] Upgrade at: https://developer.nabzclan.vip")
                    messagebox.showerror("VIP Required", "Brute force mode requires a VIP subscription.\n\nUpgrade at: https://developer.nabzclan.vip")
                    self.cancel_btn.configure(state='disabled')
                    return
                
                print(f"[+] VIP status confirmed: {plan_name}")
                charset = self.charset_var.get().strip() or None
                max_length = int(self.max_length_var.get())
                success, password, _ = crack_p12_password(
                    p12_path, 
                    mode='brute_force',
                    charset=charset,
                    min_length=1,
                    max_length=max_length
                )
            
            if success and password and self.change_after_crack_var.get():
                new_password = self.new_pass_var.get().strip()
                print(f"\n[*] Proceeding to change password...")
                
                
                change_success, download_url, change_error = change_p12_password(p12_path, password, new_password, interactive=False)
                
                if change_success and download_url:
                    self.root.after(100, lambda: self.show_download_dialog(download_url))
            
            # Send Notification
            if success:
                self.send_notification("Password Found! 🔓", f"Success: {password}")
            else:
                self.send_notification("Crack Failed ❌", "Password could not be found.")
            
        except Exception as e:
            print(f"[!] Error: {str(e)}")
        finally:
            self.cancel_btn.configure(state='disabled')
    
    def start_changing(self):
        """Start the password changing process"""
        p12_path = self.change_p12_path_var.get().strip()
        if not p12_path:
            messagebox.showerror("Error", "Please select a P12 file or enter a URL")
            return
        
        old_password = self.old_pass_var.get().strip()
        if not old_password:
            messagebox.showerror("Error", "Please enter the current password")
            return
        
        new_password = self.change_new_pass_var.get().strip()
        if not new_password:
            messagebox.showerror("Error", "Please enter the new password")
            return
        
        self.cancel_event.clear()
        self.cancel_btn.configure(state='normal')
        
        threading.Thread(target=self.change_thread, daemon=True).start()
    
    def change_thread(self):
        """Thread function for password changing"""
        try:
            p12_path = self.change_p12_path_var.get().strip()
            

            if not os.path.exists(p12_path):
                messagebox.showerror("Error", f"P12 file not found: {p12_path}")
                self.cancel_btn.configure(state='disabled')
                return
            
            if not os.path.isfile(p12_path):
                messagebox.showerror("Error", f"Path is not a file: {p12_path}")
                self.cancel_btn.configure(state='disabled')
                return
            
            print(f"[*] P12 file validated: {p12_path}")
            
            old_password = self.old_pass_var.get().strip()
            new_password = self.change_new_pass_var.get().strip()
            
            success, download_url, error = change_p12_password(p12_path, old_password, new_password, interactive=False)
            
            if success and download_url:
                self.root.after(100, lambda: self.show_download_dialog(download_url))
            
        except Exception as e:
            print(f"[!] Error: {str(e)}")
        finally:
            self.cancel_btn.configure(state='disabled')
    
    def show_download_dialog(self, download_url):
        """Show a dialog asking if the user wants to download the modified P12 file"""
        want_download = messagebox.askyesno(
            "Download Modified P12",
            "Password changed successfully!\n\nDo you want to download the modified P12 file?",
            icon=messagebox.INFO
        )
        
        if want_download:
            filename = download_url.split('/')[-1]
            save_path = filedialog.asksaveasfilename(
                defaultextension=".p12",
                filetypes=[("P12 Files", "*.p12"), ("All Files", "*.*")],
                initialfile=filename
            )
            
            if save_path:
                threading.Thread(
                    target=self.download_file_thread, 
                    args=(download_url, save_path),
                    daemon=True
                ).start()
    
    def download_file_thread(self, url, output_path):
        """Thread to download a file and show progress"""
        try:
            print(f"[*] Downloading modified P12 file to {output_path}...")
            
            success = download_file(url, output_path)
            
            if success:
                messagebox.showinfo(
                    "Download Complete", 
                    f"The modified P12 file has been saved to:\n{output_path}"
                )
            else:
                messagebox.showerror(
                    "Download Failed",
                    "Failed to download the modified P12 file. Please try again or manually download it from the URL in the console output."
                )
        except Exception as e:
            print(f"[!] Error downloading file: {e}")
            messagebox.showerror("Download Error", f"Error: {str(e)}")
    
    def __del__(self):
        """Restore stdout when the app is closed"""
        if hasattr(self, 'old_stdout'):
            sys.stdout = self.old_stdout


def main():
    """Main function to run the GUI application"""
    root = tk.Tk()
    
    # window on screen dimensions - you may tweak it to your liking
    window_width = 750
    window_height = 550
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    
    center_x = int(screen_width/2 - window_width/2)
    center_y = int(screen_height/2 - window_height/2)
    
    root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
    
    app = P12CrackerGUI(root)
    
    print(
        "╔════════════════════════════════════════════════════════╗\n"
        "║                                                        ║\n"
        "║  P12 Password Cracker & Changer v2.0 - GUI Edition     ║\n"
        "║  Powered by Nabzclan Developer API                     ║\n"
        "║                                                        ║\n"
        "╚════════════════════════════════════════════════════════╝\n"
    )
    
    print("[*] GUI loaded. Select a tab to begin on the screen please.")
    
    root.mainloop()


if __name__ == "__main__":
    main()
