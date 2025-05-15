#!/usr/bin/env python3
# Network Toolkit Launcher
# This is the main file to run both parts of the project

import os
import sys
import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import signal
import time
import webbrowser

# Import Part A (Network Toolkit) main class
from network_toolkit import NetworkToolkitApp

class ProjectLauncher:
    """Main launcher for both parts of the project"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Tools Project")
        self.root.geometry("500x400")
        self.root.minsize(500, 400)
        
        # Store process references
        self.chat_server_process = None
        
        # Create main frame
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(expand=True, fill="both")
        
        # Title
        title_label = ttk.Label(main_frame, text="Network Tools Project", font=("Arial", 16, "bold"))
        title_label.pack(pady=(0, 20))
        
        # Part A button
        part_a_frame = ttk.LabelFrame(main_frame, text="Part A: Network Toolkit")
        part_a_frame.pack(fill="x", padx=10, pady=10)
        
        part_a_desc = ttk.Label(part_a_frame, 
                              text="Launch the GUI-based network toolkit with various modules\n"
                                   "for network scanning, crawling, file transfer, and more.")
        part_a_desc.pack(pady=10)
        
        part_a_btn = ttk.Button(part_a_frame, text="Launch Network Toolkit", command=self.launch_part_a)
        part_a_btn.pack(pady=(0, 10))
        
        # Part B button
        part_b_frame = ttk.LabelFrame(main_frame, text="Part B: Web-Based Chat")
        part_b_frame.pack(fill="x", padx=10, pady=10)
        
        part_b_desc = ttk.Label(part_b_frame, 
                              text="Start the web-based chat server and automatically\n"
                                   "open the chat interface in your browser.")
        part_b_desc.pack(pady=10)
        
        self.part_b_btn = ttk.Button(part_b_frame, text="Start Chat Server", command=self.toggle_chat_server)
        self.part_b_btn.pack(side=tk.LEFT, padx=10, pady=(0, 10))
        
        self.open_browser_btn = ttk.Button(part_b_frame, text="Open Chat Interface", 
                                        command=self.open_chat_interface, state=tk.DISABLED)
        self.open_browser_btn.pack(side=tk.RIGHT, padx=10, pady=(0, 10))
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(main_frame, textvariable=self.status_var, font=("Arial", 10, "italic"))
        status_label.pack(pady=10)
        
        # Exit button
        exit_btn = ttk.Button(main_frame, text="Exit", command=self.on_exit)
        exit_btn.pack(pady=10)
        
        # Bind window close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_exit)
    
    def launch_part_a(self):
        """Launch Part A: Network Toolkit"""
        self.status_var.set("Starting Network Toolkit...")
        
        # Create a new Toplevel window for the toolkit
        toolkit_window = tk.Toplevel(self.root)
        toolkit_window.title("Network Toolkit")
        toolkit_window.geometry("800x600")
        toolkit_window.minsize(800, 600)
        
        # Create the toolkit app in the new window
        app = NetworkToolkitApp(toolkit_window)
        
        self.status_var.set("Network Toolkit launched")
    
    def toggle_chat_server(self):
        """Start or stop the chat server"""
        if self.chat_server_process is None:
            # Start the chat server
            self.start_chat_server()
        else:
            # Stop the chat server
            self.stop_chat_server()
    
    def start_chat_server(self):
        """Start the chat server process"""
        self.status_var.set("Starting chat server...")
        
        try:
            # Get the directory of the current script
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Path to the chat server script
            server_script = os.path.join(script_dir, "chat_server.py")
            
            # Check if the script exists
            if not os.path.exists(server_script):
                raise FileNotFoundError(f"Chat server script not found: {server_script}")
            
            # Start the chat server as a subprocess
            if sys.platform.startswith('win'):
                # Windows - don't show console window
                from subprocess import CREATE_NO_WINDOW
                self.chat_server_process = subprocess.Popen(
                    [sys.executable, server_script],
                    creationflags=CREATE_NO_WINDOW,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            else:
                # Linux/Mac
                self.chat_server_process = subprocess.Popen(
                    [sys.executable, server_script],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
            
            # Wait a moment for the server to start
            time.sleep(1)
            
            # Check if the process is still running
            if self.chat_server_process.poll() is not None:
                # Process has terminated
                stderr = self.chat_server_process.stderr.read().decode('utf-8')
                raise Exception(f"Server failed to start: {stderr}")
            
            # Update UI
            self.part_b_btn.config(text="Stop Chat Server")
            self.open_browser_btn.config(state=tk.NORMAL)
            self.status_var.set("Chat server running on http://localhost:8000")
            
            # Open browser automatically
            self.open_chat_interface()
            
        except Exception as e:
            messagebox.showerror("Server Error", str(e))
            self.chat_server_process = None
            self.status_var.set("Failed to start chat server")
    
    def stop_chat_server(self):
        """Stop the chat server process"""
        if self.chat_server_process:
            self.status_var.set("Stopping chat server...")
            
            try:
                # Terminate the process
                if sys.platform.startswith('win'):
                    # Windows
                    self.chat_server_process.terminate()
                else:
                    # Linux/Mac - use SIGTERM
                    os.kill(self.chat_server_process.pid, signal.SIGTERM)
                
                # Wait for the process to terminate
                self.chat_server_process.wait(timeout=5)
                
            except subprocess.TimeoutExpired:
                # Force kill if it doesn't terminate
                if sys.platform.startswith('win'):
                    os.kill(self.chat_server_process.pid, signal.SIGTERM)
                else:
                    os.kill(self.chat_server_process.pid, signal.SIGKILL)
            
            except Exception as e:
                messagebox.showwarning("Warning", f"Error stopping server: {str(e)}")
            
            finally:
                # Update UI regardless of any errors
                self.chat_server_process = None
                self.part_b_btn.config(text="Start Chat Server")
                self.open_browser_btn.config(state=tk.DISABLED)
                self.status_var.set("Chat server stopped")
    
    def open_chat_interface(self):
        """Open the chat interface in the default web browser"""
        try:
            webbrowser.open("http://localhost:8000")
        except Exception as e:
            messagebox.showerror("Browser Error", f"Could not open browser: {str(e)}")
    
    def on_exit(self):
        """Handle the exit event"""
        # Stop any running processes
        if self.chat_server_process:
            self.stop_chat_server()
        
        # Exit the application
        self.root.destroy()

if __name__ == "__main__":
    # Set up main application window
    root = tk.Tk()
    app = ProjectLauncher(root)
    
    # Start the application
    root.mainloop()