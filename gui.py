#!/usr/bin/env python3
"""
P12 Password Cracker & Changer GUI - UI for the P12 Password Cracker tool made by nabzclan.vip 
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

from main import (
    API_KEY, CRACK_ENDPOINT, CHANGE_ENDPOINT, UPLOAD_URL,
    upload_p12, validate_url, process_local_wordlist, crack_p12_password, 
    change_p12_password, download_file, check_api_key
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
        self.root.title("P12 Password Cracker & Changer")
        self.root.geometry("750x550")
        self.root.minsize(700, 500)
        
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
                               "API key is not set or is using the default placeholder value.\n"
                               "Please edit the main.py file and update the API_KEY variable."
                               "\n\nYou can get your API key from: https://api-aries.com/dashboard")
    
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
        
        self.cancel_btn = ttk.Button(btn_frame, text="Cancel Operation", style="Cancel.TButton", command=self.cancel_operation)
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
        
        self.crack_method = tk.StringVar(value="single")
        
        self.style.configure('Crack.TRadiobutton', background=self.bg_color, foreground=self.text_color, font=('Segoe UI', 10))
        
        ttk.Radiobutton(method_content, text="Single Password", variable=self.crack_method,
                      value="single", style='Crack.TRadiobutton', command=self.update_crack_ui).grid(
            row=0, column=0, sticky='w', padx=5, pady=8)
        
        ttk.Radiobutton(method_content, text="Custom Wordlist", variable=self.crack_method,
                      value="wordlist", style='Crack.TRadiobutton', command=self.update_crack_ui).grid(
            row=1, column=0, sticky='w', padx=5, pady=8)
        
        self.single_pass_var = tk.StringVar()
        self.single_pass_entry = ttk.Entry(method_content, textvariable=self.single_pass_var, width=50, show="•")
        self.single_pass_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=8)
        
        self.show_password_var = tk.BooleanVar(value=False)
        show_pass_check = ttk.Checkbutton(method_content, text="Show password",
                                       variable=self.show_password_var,
                                       command=self.toggle_password_visibility)
        show_pass_check.grid(row=0, column=2, padx=5, pady=8)
        
        self.wordlist_path_var = tk.StringVar()
        self.wordlist_entry = ttk.Entry(method_content, textvariable=self.wordlist_path_var, width=50, state='disabled')
        self.wordlist_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=8)
        
        self.wordlist_browse_btn = ttk.Button(method_content, text="Browse", style="Browse.TButton",
                                           command=self.browse_wordlist, state='disabled')
        self.wordlist_browse_btn.grid(row=1, column=2, padx=5, pady=8)
        
        wordlist_note = ttk.Label(method_content, text="Note: Only local wordlist files are supported",
                               font=('Segoe UI', 8, 'italic'), foreground=self.warning_color)
        wordlist_note.grid(row=2, column=1, sticky='w', padx=5, pady=2)
        
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
        self.new_pass_entry = ttk.Entry(password_content, textvariable=self.new_pass_var, width=30, state='disabled', show="•")
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
        self.old_pass_entry = ttk.Entry(password_content, textvariable=self.old_pass_var, width=30, show="•")
        self.old_pass_entry.grid(row=0, column=1, sticky='ew', padx=5, pady=8)
        
        ttk.Label(password_content, text="New Password:").grid(row=1, column=0, sticky='w', padx=5, pady=8)
        self.change_new_pass_var = tk.StringVar()
        self.change_new_pass_entry = ttk.Entry(password_content, textvariable=self.change_new_pass_var, width=30, show="•")
        self.change_new_pass_entry.grid(row=1, column=1, sticky='ew', padx=5, pady=8)
        
        self.change_show_password_var = tk.BooleanVar(value=False)
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
        """Initialize the about tab"""
        main_frame = ttk.Frame(self.about_tab)
        main_frame.pack(fill='both', expand=True, padx=5, pady=5)
        
        logo_frame = ttk.Frame(main_frame)
        logo_frame.pack(pady=10)
        
        title_label = ttk.Label(main_frame, text="P12 Password Cracker & Changer",
                              style='Header.TLabel')
        title_label.pack(pady=5)
        
        self.style.configure('Version.TLabel', font=('Segoe UI', 10, 'italic'), 
                           background=self.bg_color, foreground=self.accent_color)
        version_label = ttk.Label(main_frame, text="Version 1.4", style='Version.TLabel')
        version_label.pack(pady=2)
        
        description_frame = ttk.LabelFrame(main_frame, text="Description")
        description_frame.pack(fill='x', padx=5, pady=10)
        
        description_content = ttk.Frame(description_frame)
        description_content.pack(fill='x', padx=10, pady=10)
        
        desc_text = ("A tool to crack and change passwords for P12/PKCS#12 certificate files "
                   "utilizing the API-Aries services.\n\n"
                   "This tool allows you to:\n"
                   "1. Crack P12 file passwords using single password attempts or wordlists\n"
                   "2. Change P12 file passwords after finding the correct password\n"
                   "3. Upload local P12 files to the service automatically")
        
        ttk.Label(description_content, text=desc_text, justify='left', wraplength=700).pack(
            padx=5, pady=5, fill='x')
        
        features_frame = ttk.LabelFrame(main_frame, text="Features")
        features_frame.pack(fill='x', padx=5, pady=5)
        
        features_content = ttk.Frame(features_frame)
        features_content.pack(fill='x', padx=10, pady=5)
        
        features_text = (
            " ✓ Multiple cracking methods\n"
            " ✓ p12 Password changing"
        )
        
        ttk.Label(features_content, text=features_text, justify='left', wraplength=650).pack(
            padx=5, pady=2, fill='x', anchor='w')
        
        api_frame = ttk.LabelFrame(main_frame, text="API Information")
        api_frame.pack(fill='x', padx=5, pady=10)
        
        api_content = ttk.Frame(api_frame)
        api_content.pack(fill='x', padx=10, pady=10)
        
        api_text = ("This tool uses the API-Aries service for P12 password cracking and changing.\n"
                  "You need a valid API key to use this tool.\n")
        
        ttk.Label(api_content, text=api_text, justify='left', wraplength=700).pack(
            padx=5, pady=5, fill='x', anchor='w')
        
        status_frame = ttk.Frame(api_content)
        status_frame.pack(fill='x', padx=5, pady=5, anchor='w')
        
        ttk.Label(status_frame, text="Current API key status: ").pack(side='left')
        
        try:
            check_api_key()
            api_status = "Valid API key configured"
            api_status_color = self.success_color
        except SystemExit:
            api_status = "Invalid or missing API key"
            api_status_color = self.error_color
        
        self.style.configure('APIStatus.TLabel', font=('Segoe UI', 10, 'bold'), 
                           background=self.bg_color, foreground=api_status_color)
        
        api_status_label = ttk.Label(status_frame, text=api_status, style='APIStatus.TLabel')
        api_status_label.pack(side='left')
        
        self.style.configure('Link.TLabel', font=('Segoe UI', 10, 'underline'), 
                           background=self.bg_color, foreground=self.info_color)
        
        ttk.Label(api_content, text="You can get your API key from: https://api-aries.com/dashboard",
                style='Link.TLabel', cursor="hand2").pack(padx=5, pady=5, anchor='w')
        
        credits_frame = ttk.LabelFrame(main_frame, text="Credits")
        credits_frame.pack(fill='x', padx=5, pady=10)
        
        credits_content = ttk.Frame(credits_frame)
        credits_content.pack(fill='x', padx=10, pady=10)
        
        credits_text = "Powered by API-Aries & Nabz Clan \nGUI enhanced for improved user experience"
        ttk.Label(credits_content, text=credits_text, justify='center').pack(padx=5, pady=5)
        
        copyright_text = "Nabz Clan © 2025 All Rights Reserved - nabzclan.vip"
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
        if self.crack_method.get() == "single":
            self.single_pass_entry.configure(state='normal')
            self.wordlist_entry.configure(state='disabled')
            self.wordlist_browse_btn.configure(state='disabled')
        else:
            self.single_pass_entry.configure(state='disabled')
            self.wordlist_entry.configure(state='normal')
            self.wordlist_browse_btn.configure(state='normal')
        
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
            messagebox.showerror("Error", "Please select a P12 file or enter a URL")
            return
        
        method = self.crack_method.get()
        if method == "single":
            password = self.single_pass_var.get().strip()
            if not password:
                messagebox.showerror("Error", "Please enter a password to try")
                return
        else: 
            wordlist = self.wordlist_path_var.get().strip()
            if not wordlist:
                messagebox.showerror("Error", "Please select a wordlist file or enter a URL")
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
            
            if os.path.exists(p12_path) and not p12_path.startswith(('http://', 'https://')):
                print(f"[*] Detected local file. Uploading {p12_path} first...")
                p12_url = upload_p12(p12_path)
                if not p12_url:
                    messagebox.showerror("Error", "Failed to upload file")
                    self.cancel_btn.configure(state='disabled')
                    return
            else:
                if not p12_path.startswith(('http://', 'https://')):
                    messagebox.showerror("Error", "File path must be a valid local file or start with http:// or https://")
                    self.cancel_btn.configure(state='disabled')
                    return
                
                if not validate_url(p12_path):
                    if not messagebox.askyesno("Warning", "The URL might not be valid. Do you want to proceed anyway?"):
                        self.cancel_btn.configure(state='disabled')
                        return
                p12_url = p12_path
            
            method = self.crack_method.get()
            success = False
            password = None
            
            if method == "single":
                test_password = self.single_pass_var.get().strip()
                url = f"{CRACK_ENDPOINT}?p12={p12_url}&password={test_password}"
                success, password, _ = crack_p12_password(url, p12_url, "Single Password", test_password)
            else: 
                wordlist_path = self.wordlist_path_var.get().strip()
                if not os.path.exists(wordlist_path):
                    messagebox.showerror("Error", f"The wordlist file '{wordlist_path}' does not exist.\n\nPlease select a valid local wordlist file.")
                    self.cancel_btn.configure(state='disabled')
                    return
                
                success, password, _ = process_local_wordlist(p12_url, wordlist_path)
            
            if success and password and self.change_after_crack_var.get():
                new_password = self.new_pass_var.get().strip()
                print(f"\n[*] Proceeding to change password...")
                
                try:
                    headers = {
                        'APITOKEN': API_KEY,
                        'User-Agent': 'P12PasswordChanger/1.4'
                    }
                    
                    url = f"{CHANGE_ENDPOINT}?p12={p12_url}&old_password={password}&new_password={new_password}"
                    
                    print(f"[*] Attempting to change P12 password...")
                    print(f"[*] Working with uploaded P12 file...")
                    print(f"[*] Sending request to API-Aries...")
                    
                    response = requests.get(url, headers=headers, timeout=120)
                    response.raise_for_status()
                    
                    result = response.json()
                    
                    if result.get('success') is True:
                        download_url = result.get('download_url')
                        print(f"\n[+] Password changed successfully!")
                        print(f"[+] Modified P12 file available at: {download_url}")
                        print(f"[+] Timestamp: {result.get('timestamp', 'unknown')}")
                        
                        change_success = True
                        change_error = None
                    else:
                        error_msg = result.get('message', 'Unknown error')
                        print(f"\n[!] Failed to change password: {error_msg}")
                        change_success = False
                        download_url = None
                        change_error = error_msg
                except Exception as e:
                    print(f"[!] Error changing password: {e}")
                    change_success = False
                    download_url = None
                    change_error = str(e)
                
                if change_success and download_url:
                    self.root.after(100, lambda: self.show_download_dialog(download_url))
            
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
            
            if os.path.exists(p12_path) and not p12_path.startswith(('http://', 'https://')):
                print(f"[*] Detected local file. Uploading {p12_path} first...")
                p12_url = upload_p12(p12_path)
                if not p12_url:
                    messagebox.showerror("Error", "Failed to upload file")
                    self.cancel_btn.configure(state='disabled')
                    return
            else:
                if not p12_path.startswith(('http://', 'https://')):
                    messagebox.showerror("Error", "File path must be a valid local file or start with http:// or https://")
                    self.cancel_btn.configure(state='disabled')
                    return
                
                if not validate_url(p12_path):
                    if not messagebox.askyesno("Warning", "The URL might not be valid. Do you want to proceed anyway?"):
                        self.cancel_btn.configure(state='disabled')
                        return
                p12_url = p12_path
            
            old_password = self.old_pass_var.get().strip()
            new_password = self.change_new_pass_var.get().strip()
            
            try:
                headers = {
                    'APITOKEN': API_KEY,
                    'User-Agent': 'P12PasswordChanger/1.4'
                }
                
                url = f"{CHANGE_ENDPOINT}?p12={p12_url}&old_password={old_password}&new_password={new_password}"
                
                print(f"[*] Attempting to change P12 password...")
                print(f"[*] Working with uploaded P12 file...")
                print(f"[*] Sending request to API-Aries...")
                
                response = requests.get(url, headers=headers, timeout=120)
                response.raise_for_status()
                
                result = response.json()
                
                if result.get('success') is True:
                    download_url = result.get('download_url')
                    print(f"\n[+] Password changed successfully!")
                    print(f"[+] Modified P12 file available at: {download_url}")
                    print(f"[+] Timestamp: {result.get('timestamp', 'unknown')}")
                    
                    success = True
                    error = None
                else:
                    error_msg = result.get('message', 'Unknown error')
                    print(f"\n[!] Failed to change password: {error_msg}")
                    success = False
                    download_url = None
                    error = error_msg
            except Exception as e:
                print(f"[!] Error changing password: {e}")
                success = False
                download_url = None
                error = str(e)
            
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
        "║  P12 Password Cracker & Changer v1.4 - GUI Edition     ║\n"
        "║  Powered by API-Aries & nabzclan.vip                   ║\n"
        "║                                                        ║\n"
        "╚════════════════════════════════════════════════════════╝\n"
    )
    
    print("[*] GUI loaded. Select a tab to begin on the screen please.")
    
    root.mainloop()


if __name__ == "__main__":
    main()
