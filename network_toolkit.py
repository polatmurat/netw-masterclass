#!/usr/bin/env python3
# Network Toolkit GUI - Main Application
# This is the main GUI interface for the network toolkit application.
# It provides access to various network tools through a graphical menu.

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import socket
import threading
import os
import sys
import re
import time
import json
import ipaddress
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import struct

class NetworkToolkitApp:
    """Main application class for the Network Toolkit"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Network Toolkit")
        self.root.geometry("800x600")
        self.root.minsize(800, 600)
        
        # Create a notebook (tabbed interface)
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill="both", padx=10, pady=10)
        
        # Create tabs for each module
        self.create_port_scanner_tab()
        self.create_web_crawler_tab()
        self.create_file_transfer_tab()
        self.create_wiki_fetcher_tab()
        self.create_device_scanner_tab()
        self.create_broadcast_msg_tab()
        
    def create_port_scanner_tab(self):
        """Create the Port Scanner module tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Port Scanner")
        
        # Target input
        ttk.Label(frame, text="Target IP:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.target_ip = ttk.Entry(frame, width=30)
        self.target_ip.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.target_ip.insert(0, "127.0.0.1")
        
        # Port range
        ttk.Label(frame, text="Port Range:").grid(row=1, column=0, padx=10, pady=10, sticky="w")
        port_frame = ttk.Frame(frame)
        port_frame.grid(row=1, column=1, padx=10, pady=10, sticky="w")
        
        self.start_port = ttk.Entry(port_frame, width=6)
        self.start_port.pack(side=tk.LEFT)
        self.start_port.insert(0, "1")
        
        ttk.Label(port_frame, text=" to ").pack(side=tk.LEFT)
        
        self.end_port = ttk.Entry(port_frame, width=6)
        self.end_port.pack(side=tk.LEFT)
        self.end_port.insert(0, "1024")
        
        # Scan button
        self.scan_btn = ttk.Button(frame, text="Scan Ports", command=self.scan_ports)
        self.scan_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Results area
        ttk.Label(frame, text="Results:").grid(row=3, column=0, padx=10, pady=5, sticky="nw")
        self.port_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.port_results.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        # Make the results area expand with the window
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        
    def create_web_crawler_tab(self):
        """Create the Web Crawler module tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Web Crawler")
        
        # URL input
        ttk.Label(frame, text="URL:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.crawl_url = ttk.Entry(frame, width=50)
        self.crawl_url.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.crawl_url.insert(0, "https://en.wikipedia.org/")
        
        # Crawl button
        self.crawl_btn = ttk.Button(frame, text="Extract Links", command=self.crawl_web)
        self.crawl_btn.grid(row=1, column=0, columnspan=2, pady=10)
        
        # Save to file option
        self.save_links_var = tk.IntVar()
        self.save_checkbox = ttk.Checkbutton(frame, text="Save to file", variable=self.save_links_var)
        self.save_checkbox.grid(row=2, column=0, padx=10, pady=5, sticky="w")
        
        # Results area
        ttk.Label(frame, text="Links:").grid(row=3, column=0, padx=10, pady=5, sticky="nw")
        self.crawl_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.crawl_results.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        # Make the results area expand with the window
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
        
    def create_file_transfer_tab(self):
        """Create the File Transfer module tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="File Transfer")
        
        # Mode selection
        mode_frame = ttk.LabelFrame(frame, text="Mode")
        mode_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        self.transfer_mode = tk.StringVar(value="server")
        ttk.Radiobutton(mode_frame, text="Server (Receive)", variable=self.transfer_mode, 
                      value="server", command=self.update_transfer_ui).pack(side=tk.LEFT, padx=10, pady=5)
        ttk.Radiobutton(mode_frame, text="Client (Send)", variable=self.transfer_mode, 
                      value="client", command=self.update_transfer_ui).pack(side=tk.LEFT, padx=10, pady=5)
        
        # Server settings
        self.server_frame = ttk.LabelFrame(frame, text="Server Settings")
        self.server_frame.grid(row=1, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        ttk.Label(self.server_frame, text="IP:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.server_ip = ttk.Entry(self.server_frame, width=15)
        self.server_ip.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.server_ip.insert(0, "127.0.0.1")
        
        ttk.Label(self.server_frame, text="Port:").grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.server_port = ttk.Entry(self.server_frame, width=6)
        self.server_port.grid(row=0, column=3, padx=10, pady=5, sticky="w")
        self.server_port.insert(0, "9000")
        
        ttk.Label(self.server_frame, text="Save Directory:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.save_dir = ttk.Entry(self.server_frame, width=40)
        self.save_dir.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="w")
        self.save_dir.insert(0, os.path.join(os.getcwd(), "received_files"))
        
        self.browse_btn = ttk.Button(self.server_frame, text="Browse", command=self.browse_save_dir)
        self.browse_btn.grid(row=1, column=3, padx=10, pady=5)
        
        # Client settings
        self.client_frame = ttk.LabelFrame(frame, text="Client Settings")
        self.client_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        ttk.Label(self.client_frame, text="Server IP:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.client_server_ip = ttk.Entry(self.client_frame, width=15)
        self.client_server_ip.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.client_server_ip.insert(0, "127.0.0.1")
        
        ttk.Label(self.client_frame, text="Port:").grid(row=0, column=2, padx=10, pady=5, sticky="w")
        self.client_server_port = ttk.Entry(self.client_frame, width=6)
        self.client_server_port.grid(row=0, column=3, padx=10, pady=5, sticky="w")
        self.client_server_port.insert(0, "9000")
        
        ttk.Label(self.client_frame, text="File to Send:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.file_to_send = ttk.Entry(self.client_frame, width=40)
        self.file_to_send.grid(row=1, column=1, columnspan=2, padx=10, pady=5, sticky="w")
        
        self.browse_file_btn = ttk.Button(self.client_frame, text="Browse", command=self.browse_file_to_send)
        self.browse_file_btn.grid(row=1, column=3, padx=10, pady=5)
        
        # Control buttons
        self.start_transfer_btn = ttk.Button(frame, text="Start Server", command=self.start_file_transfer)
        self.start_transfer_btn.grid(row=3, column=0, padx=10, pady=10)
        
        self.stop_transfer_btn = ttk.Button(frame, text="Stop Server", command=self.stop_file_transfer)
        self.stop_transfer_btn.grid(row=3, column=1, padx=10, pady=10)
        self.stop_transfer_btn.config(state=tk.DISABLED)
        
        # Log area
        ttk.Label(frame, text="Log:").grid(row=4, column=0, padx=10, pady=5, sticky="nw")
        self.transfer_log = scrolledtext.ScrolledText(frame, width=80, height=15)
        self.transfer_log.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        # Initialize transfer state
        self.transfer_thread = None
        self.server_running = False
        self.update_transfer_ui()
        
        # Make the log area expand with the window
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)
        
    def create_wiki_fetcher_tab(self):
        """Create the Wikipedia Data Fetcher module tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Wikipedia Fetcher")
        
        # Search input
        ttk.Label(frame, text="Search Topic:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.wiki_topic = ttk.Entry(frame, width=50)
        self.wiki_topic.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        
        # Search button
        self.wiki_btn = ttk.Button(frame, text="Fetch Summary", command=self.fetch_wiki)
        self.wiki_btn.grid(row=1, column=0, columnspan=2, pady=10)
        
        # Results area
        ttk.Label(frame, text="Results:").grid(row=2, column=0, padx=10, pady=5, sticky="nw")
        self.wiki_results = scrolledtext.ScrolledText(frame, width=80, height=20)
        self.wiki_results.grid(row=3, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        # Make the results area expand with the window
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(3, weight=1)
        
    def create_device_scanner_tab(self):
        """Create the Network Device Scanner module tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Device Scanner")
        
        # Network input
        ttk.Label(frame, text="Network Range:").grid(row=0, column=0, padx=10, pady=10, sticky="w")
        self.network_range = ttk.Entry(frame, width=20)
        self.network_range.grid(row=0, column=1, padx=10, pady=10, sticky="w")
        self.network_range.insert(0, "192.168.1.1-254")
        
        # Help text
        help_text = ttk.Label(frame, text="Format: 192.168.1.1-254 (first 3 octets fixed)")
        help_text.grid(row=1, column=0, columnspan=2, padx=10, sticky="w")
        
        # Scan button
        self.device_scan_btn = ttk.Button(frame, text="Scan Network", command=self.scan_network)
        self.device_scan_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Progress bar
        ttk.Label(frame, text="Progress:").grid(row=3, column=0, padx=10, pady=5, sticky="w")
        self.scan_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.scan_progress.grid(row=3, column=1, padx=10, pady=5, sticky="w")
        
        # Results area
        ttk.Label(frame, text="Active Devices:").grid(row=4, column=0, padx=10, pady=5, sticky="nw")
        self.device_results = scrolledtext.ScrolledText(frame, width=80, height=15)
        self.device_results.grid(row=5, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        # Make the results area expand with the window
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(5, weight=1)
        
    def create_broadcast_msg_tab(self):
        """Create the Broadcast Messaging module tab"""
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="Broadcast Messaging")
        
        # Broadcast settings
        settings_frame = ttk.LabelFrame(frame, text="Settings")
        settings_frame.grid(row=0, column=0, columnspan=2, padx=10, pady=10, sticky="nsew")
        
        ttk.Label(settings_frame, text="Port:").grid(row=0, column=0, padx=10, pady=5, sticky="w")
        self.broadcast_port = ttk.Entry(settings_frame, width=6)
        self.broadcast_port.grid(row=0, column=1, padx=10, pady=5, sticky="w")
        self.broadcast_port.insert(0, "5005")
        
        self.start_broadcast_btn = ttk.Button(settings_frame, text="Start Listening", command=self.start_broadcast_listener)
        self.start_broadcast_btn.grid(row=0, column=2, padx=10, pady=5)
        
        self.stop_broadcast_btn = ttk.Button(settings_frame, text="Stop Listening", command=self.stop_broadcast_listener)
        self.stop_broadcast_btn.grid(row=0, column=3, padx=10, pady=5)
        self.stop_broadcast_btn.config(state=tk.DISABLED)
        
        # Message composition
        ttk.Label(frame, text="Broadcast Message:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.broadcast_msg = ttk.Entry(frame, width=50)
        self.broadcast_msg.grid(row=1, column=1, padx=10, pady=5, sticky="w")
        
        self.send_broadcast_btn = ttk.Button(frame, text="Send Broadcast", command=self.send_broadcast)
        self.send_broadcast_btn.grid(row=2, column=0, columnspan=2, pady=10)
        
        # Message log
        ttk.Label(frame, text="Messages:").grid(row=3, column=0, padx=10, pady=5, sticky="nw")
        self.broadcast_log = scrolledtext.ScrolledText(frame, width=80, height=15)
        self.broadcast_log.grid(row=4, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        
        # Initialize broadcast state
        self.broadcast_thread = None
        self.broadcast_running = False
        
        # Make the log area expand with the window
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(4, weight=1)
    
    # Port Scanner methods
    def scan_ports(self):
        """Scan ports on the target IP"""
        target = self.target_ip.get().strip()
        try:
            start = int(self.start_port.get().strip())
            end = int(self.end_port.get().strip())
            
            if start < 1 or end > 65535 or start > end:
                raise ValueError("Port range must be between 1-65535 and start must be less than end")
            
            self.port_results.delete(1.0, tk.END)
            self.port_results.insert(tk.END, f"Scanning {target} from port {start} to {end}...\n\n")
            self.port_results.update()
            
            # Disable the scan button during scanning
            self.scan_btn.config(state=tk.DISABLED)
            
            # Start scanning in a separate thread
            threading.Thread(target=self._scan_ports_thread, 
                            args=(target, start, end), 
                            daemon=True).start()
            
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
    
    def _scan_ports_thread(self, target, start, end):
        """Thread function for port scanning"""
        open_ports = []
        
        try:
            # Check if the target is valid
            socket.gethostbyname(target)
            
            for port in range(start, end + 1):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((target, port))
                if result == 0:
                    # Try to get the service name
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    open_ports.append((port, service))
                    self.port_results.insert(tk.END, f"Port {port}: Open ({service})\n")
                    self.port_results.see(tk.END)
                    self.port_results.update()
                sock.close()
            
            if not open_ports:
                self.port_results.insert(tk.END, "No open ports found in the specified range.\n")
            else:
                self.port_results.insert(tk.END, f"\nFound {len(open_ports)} open ports.\n")
        
        except socket.gaierror:
            self.port_results.insert(tk.END, "Error: Invalid hostname or IP address.\n")
        except Exception as e:
            self.port_results.insert(tk.END, f"Error: {str(e)}\n")
        
        # Re-enable the scan button
        self.root.after(0, lambda: self.scan_btn.config(state=tk.NORMAL))
    
    # Web Crawler methods
    def crawl_web(self):
        """Extract links from the specified URL"""
        url = self.crawl_url.get().strip()
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        self.crawl_results.delete(1.0, tk.END)
        self.crawl_results.insert(tk.END, f"Crawling {url}...\n\n")
        self.crawl_results.update()
        
        # Disable the button during crawling
        self.crawl_btn.config(state=tk.DISABLED)
        
        # Start crawling in a separate thread
        threading.Thread(target=self._crawl_web_thread, args=(url,), daemon=True).start()
    
    def _crawl_web_thread(self, url):
        """Thread function for web crawling"""
        try:
            # Send request to the URL
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()  # Raise exception for 4XX/5XX responses
            
            # Parse HTML
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find all links
            links = []
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                full_url = urljoin(url, href)
                links.append(full_url)
            
            # Display results
            self.crawl_results.insert(tk.END, f"Found {len(links)} links:\n\n")
            
            for i, link in enumerate(links, 1):
                self.crawl_results.insert(tk.END, f"{i}. {link}\n")
            
            # Save to file if requested
            if self.save_links_var.get() == 1:
                filename = f"links_{time.strftime('%Y%m%d_%H%M%S')}.txt"
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"Links extracted from {url}\n")
                    f.write(f"Extracted on {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    for i, link in enumerate(links, 1):
                        f.write(f"{i}. {link}\n")
                
                self.crawl_results.insert(tk.END, f"\nLinks saved to {filename}\n")
        
        except requests.exceptions.RequestException as e:
            self.crawl_results.insert(tk.END, f"Error: Could not fetch URL: {str(e)}\n")
        except Exception as e:
            self.crawl_results.insert(tk.END, f"Error: {str(e)}\n")
        
        # Re-enable the button
        self.root.after(0, lambda: self.crawl_btn.config(state=tk.NORMAL))
    
    # File Transfer methods
    def update_transfer_ui(self):
        """Update the file transfer UI based on the selected mode"""
        mode = self.transfer_mode.get()
        
        if mode == "server":
            self.client_frame.grid_remove()
            self.server_frame.grid()
            self.start_transfer_btn.config(text="Start Server")
        else:
            self.server_frame.grid_remove()
            self.client_frame.grid()
            self.start_transfer_btn.config(text="Send File")
    
    def browse_save_dir(self):
        """Open a dialog to select the save directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.save_dir.delete(0, tk.END)
            self.save_dir.insert(0, directory)
    
    def browse_file_to_send(self):
        """Open a dialog to select a file to send"""
        filename = filedialog.askopenfilename()
        if filename:
            self.file_to_send.delete(0, tk.END)
            self.file_to_send.insert(0, filename)
    
    def start_file_transfer(self):
        """Start file transfer server or client based on selected mode"""
        mode = self.transfer_mode.get()
        
        if mode == "server":
            # Start server mode
            try:
                ip = self.server_ip.get().strip()
                port = int(self.server_port.get().strip())
                save_dir = self.save_dir.get().strip()
                
                # Ensure save directory exists
                if not os.path.exists(save_dir):
                    os.makedirs(save_dir)
                
                # Start server in a separate thread
                self.server_running = True
                self.transfer_thread = threading.Thread(
                    target=self._run_file_server,
                    args=(ip, port, save_dir),
                    daemon=True
                )
                self.transfer_thread.start()
                
                # Update UI
                self.start_transfer_btn.config(state=tk.DISABLED)
                self.stop_transfer_btn.config(state=tk.NORMAL)
                self.transfer_log.insert(tk.END, f"Server started on {ip}:{port}\n")
                self.transfer_log.insert(tk.END, f"Files will be saved to: {save_dir}\n")
                self.transfer_log.insert(tk.END, "Waiting for connections...\n")
                self.transfer_log.see(tk.END)
            
            except ValueError as e:
                messagebox.showerror("Input Error", "Invalid port number")
            except Exception as e:
                messagebox.showerror("Server Error", str(e))
        
        else:
            # Client mode (send file)
            try:
                server_ip = self.client_server_ip.get().strip()
                server_port = int(self.client_server_port.get().strip())
                file_path = self.file_to_send.get().strip()
                
                if not os.path.exists(file_path):
                    raise FileNotFoundError("Selected file does not exist")
                
                # Start client in a separate thread
                threading.Thread(
                    target=self._run_file_client,
                    args=(server_ip, server_port, file_path),
                    daemon=True
                ).start()
                
                self.transfer_log.insert(tk.END, f"Connecting to {server_ip}:{server_port}...\n")
                self.transfer_log.see(tk.END)
            
            except ValueError:
                messagebox.showerror("Input Error", "Invalid port number")
            except FileNotFoundError as e:
                messagebox.showerror("File Error", str(e))
            except Exception as e:
                messagebox.showerror("Client Error", str(e))
    
    def stop_file_transfer(self):
        """Stop the file transfer server"""
        if self.server_running:
            self.server_running = False
            self.transfer_log.insert(tk.END, "Server shutting down...\n")
            self.transfer_log.see(tk.END)
            
            # Update UI
            self.start_transfer_btn.config(state=tk.NORMAL)
            self.stop_transfer_btn.config(state=tk.DISABLED)
    
    def _run_file_server(self, ip, port, save_dir):
        """Run the file transfer server in a separate thread"""
        try:
            # Create server socket
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((ip, port))
            server_socket.listen(5)
            server_socket.settimeout(1)  # 1-second timeout for checking stop flag
            
            while self.server_running:
                try:
                    client_socket, addr = server_socket.accept()
                    self._log_transfer(f"Connection from {addr[0]}:{addr[1]}")
                    
                    # Handle client in a separate thread
                    client_handler = threading.Thread(
                        target=self._handle_file_client,
                        args=(client_socket, addr, save_dir),
                        daemon=True
                    )
                    client_handler.start()
                
                except socket.timeout:
                    # Timeout is used to check the stop flag
                    continue
                except Exception as e:
                    self._log_transfer(f"Error accepting connection: {str(e)}")
            
            # Close server socket when stopped
            server_socket.close()
            self._log_transfer("Server stopped")
        
        except Exception as e:
            self._log_transfer(f"Server error: {str(e)}")
            # Re-enable the start button in case of error
            self.root.after(0, lambda: self.start_transfer_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_transfer_btn.config(state=tk.DISABLED))
    
    def _handle_file_client(self, client_socket, addr, save_dir):
        """Handle a client connection for file transfer"""
        try:
            # Receive the file size and name
            header = client_socket.recv(1024).decode('utf-8')
            if not header:
                raise Exception("Empty header received")
            
            file_info = json.loads(header)
            file_name = os.path.basename(file_info['filename'])
            file_size = int(file_info['filesize'])
            
            self._log_transfer(f"Receiving {file_name} ({file_size} bytes) from {addr[0]}:{addr[1]}")
            self._log_transfer(f"Receiving {file_name} ({file_size} bytes) from {addr[0]}:{addr[1]}")
            
            # Create the file path
            file_path = os.path.join(save_dir, file_name)
            
            # Receive the file
            received = 0
            with open(file_path, 'wb') as f:
                while received < file_size:
                    # Receive data in chunks
                    chunk_size = min(4096, file_size - received)
                    data = client_socket.recv(chunk_size)
                    if not data:
                        break
                    
                    f.write(data)
                    received += len(data)
                    
                    # Update progress (log every 10%)
                    progress = int(received / file_size * 100)
                    if progress % 10 == 0:
                        self._log_transfer(f"Progress: {progress}%")
            
            # Confirm to client
            client_socket.send("File received successfully".encode('utf-8'))
            self._log_transfer(f"File saved to {file_path}")
        
        except Exception as e:
            self._log_transfer(f"Error receiving file: {str(e)}")
        finally:
            client_socket.close()
    
    def _run_file_client(self, server_ip, server_port, file_path):
        """Send a file to the server"""
        try:
            # Create client socket
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((server_ip, server_port))
            
            # Get file info
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            
            # Send file info
            file_info = {
                'filename': file_name,
                'filesize': file_size
            }
            client_socket.send(json.dumps(file_info).encode('utf-8'))
            
            # Wait a moment for the server to process the header
            time.sleep(0.1)
            
            # Send the file
            self._log_transfer(f"Sending {file_name} ({file_size} bytes)")
            sent = 0
            with open(file_path, 'rb') as f:
                while sent < file_size:
                    # Send data in chunks
                    chunk = f.read(4096)
                    if not chunk:
                        break
                    
                    client_socket.send(chunk)
                    sent += len(chunk)
                    
                    # Update progress (log every 10%)
                    progress = int(sent / file_size * 100)
                    if progress % 10 == 0:
                        self._log_transfer(f"Progress: {progress}%")
            
            # Wait for confirmation
            response = client_socket.recv(1024).decode('utf-8')
            self._log_transfer(f"Server response: {response}")
        
        except ConnectionRefusedError:
            self._log_transfer("Error: Connection refused. Make sure the server is running.")
        except Exception as e:
            self._log_transfer(f"Error sending file: {str(e)}")
        finally:
            client_socket.close()
    
    def _log_transfer(self, message):
        """Log a message to the transfer log"""
        self.root.after(0, lambda: self._append_to_log(message))
    
    def _append_to_log(self, message):
        """Append a message to the transfer log (from main thread)"""
        timestamp = time.strftime("%H:%M:%S")
        self.transfer_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.transfer_log.see(tk.END)
    
    # Wiki Fetcher methods
    def fetch_wiki(self):
        """Fetch Wikipedia summary for the given topic"""
        topic = self.wiki_topic.get().strip()
        
        if not topic:
            messagebox.showerror("Input Error", "Please enter a search topic")
            return
        
        self.wiki_results.delete(1.0, tk.END)
        self.wiki_results.insert(tk.END, f"Searching for: {topic}...\n\n")
        self.wiki_results.update()
        
        # Disable the button during fetching
        self.wiki_btn.config(state=tk.DISABLED)
        
        # Start fetching in a separate thread
        threading.Thread(target=self._fetch_wiki_thread, args=(topic,), daemon=True).start()
    
    def _fetch_wiki_thread(self, topic):
        """Thread function for fetching Wikipedia data"""
        try:
            # Build the API URL
            api_url = "https://en.wikipedia.org/api/rest_v1/page/summary/"
            url = api_url + requests.utils.quote(topic)
            
            # Send request
            headers = {
                'User-Agent': 'NetworkToolkit/1.0 (Python/3.x; Contact: student@example.com)'
            }
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            # Parse JSON response
            data = response.json()
            
            # Extract and display the data
            if 'title' in data:
                self.wiki_results.insert(tk.END, f"Title: {data['title']}\n\n")
            
            if 'extract' in data:
                self.wiki_results.insert(tk.END, f"{data['extract']}\n\n")
            
            if 'content_urls' in data and 'desktop' in data['content_urls'] and 'page' in data['content_urls']['desktop']:
                page_url = data['content_urls']['desktop']['page']
                self.wiki_results.insert(tk.END, f"Full article: {page_url}\n")
            
        except requests.exceptions.RequestException as e:
            self.wiki_results.insert(tk.END, f"Error: Could not fetch data: {str(e)}\n")
        except Exception as e:
            self.wiki_results.insert(tk.END, f"Error: {str(e)}\n")
        
        # Re-enable the button
        self.root.after(0, lambda: self.wiki_btn.config(state=tk.NORMAL))
    
    # Device Scanner methods
    def scan_network(self):
        """Scan the local network for active devices"""
        network_range = self.network_range.get().strip()
        
        # Validate input
        pattern = r"^(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})$"
        match = re.match(pattern, network_range)
        
        if not match:
            messagebox.showerror("Input Error", "Invalid network range format. Example: 192.168.1.1-254")
            return
        
        subnet = match.group(1)
        start = int(match.group(2))
        end = int(match.group(3))
        
        if start < 1 or end > 255 or start > end:
            messagebox.showerror("Input Error", "IP range must be between 1-255 and start must be less than end")
            return
        
        self.device_results.delete(1.0, tk.END)
        self.device_results.insert(tk.END, f"Scanning network {subnet}.{start}-{end}\n\n")
        self.device_results.update()
        
        # Reset and configure progress bar
        self.scan_progress['value'] = 0
        self.scan_progress['maximum'] = end - start + 1
        
        # Disable the scan button during scanning
        self.device_scan_btn.config(state=tk.DISABLED)
        
        # Start scanning in a separate thread
        threading.Thread(target=self._scan_network_thread, 
                        args=(subnet, start, end), 
                        daemon=True).start()
    
    def _scan_network_thread(self, subnet, start, end):
        """Thread function for network scanning"""
        active_devices = []
        
        for i in range(start, end + 1):
            ip = f"{subnet}.{i}"
            
            try:
                # Try to connect to port 7 (Echo) with a short timeout
                # This is faster than using ping for basic connectivity check
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                result = sock.connect_ex((ip, 7))
                
                if result == 0:
                    # Port is open
                    status = "Port 7 (Echo) open"
                    is_active = True
                else:
                    # Try to resolve the hostname
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        status = f"Resolved to {hostname}"
                        is_active = True
                    except socket.herror:
                        # Try one more common port (80 - HTTP)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        sock.settimeout(0.1)
                        result = sock.connect_ex((ip, 80))
                        
                        if result == 0:
                            status = "Port 80 (HTTP) open"
                            is_active = True
                        else:
                            # Device is likely not active
                            status = "Not responding"
                            is_active = False
                
                sock.close()
                
                if is_active:
                    active_devices.append((ip, status))
                    self.root.after(0, lambda ip=ip, status=status: self._add_device_result(ip, status))
            
            except Exception as e:
                # Skip any errors and continue with next IP
                pass
            
            # Update progress bar from main thread
            self.root.after(0, lambda value=i-start+1: self._update_scan_progress(value))
        
        # Scanning completed
        self.root.after(0, lambda count=len(active_devices): self._finish_network_scan(count))
    
    def _add_device_result(self, ip, status):
        """Add a device result to the text area (from main thread)"""
        self.device_results.insert(tk.END, f"IP: {ip} - {status}\n")
        self.device_results.see(tk.END)
    
    def _update_scan_progress(self, value):
        """Update the progress bar (from main thread)"""
        self.scan_progress['value'] = value
    
    def _finish_network_scan(self, count):
        """Complete the network scan (from main thread)"""
        self.device_results.insert(tk.END, f"\nScan complete. Found {count} active devices.\n")
        self.device_scan_btn.config(state=tk.NORMAL)
    
    # Broadcast Messaging methods
    def start_broadcast_listener(self):
        """Start the broadcast message listener"""
        try:
            port = int(self.broadcast_port.get().strip())
            
            if port < 1024 or port > 65535:
                raise ValueError("Port must be between 1024 and 65535")
            
            # Start listener in a separate thread
            self.broadcast_running = True
            self.broadcast_thread = threading.Thread(
                target=self._run_broadcast_listener,
                args=(port,),
                daemon=True
            )
            self.broadcast_thread.start()
            
            # Update UI
            self.start_broadcast_btn.config(state=tk.DISABLED)
            self.stop_broadcast_btn.config(state=tk.NORMAL)
            self.broadcast_log.insert(tk.END, f"Started listening on port {port}\n")
            self.broadcast_log.see(tk.END)
        
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))
        except Exception as e:
            messagebox.showerror("Broadcast Error", str(e))
    
    def stop_broadcast_listener(self):
        """Stop the broadcast message listener"""
        if self.broadcast_running:
            self.broadcast_running = False
            
            # Update UI
            self.start_broadcast_btn.config(state=tk.NORMAL)
            self.stop_broadcast_btn.config(state=tk.DISABLED)
            self.broadcast_log.insert(tk.END, "Stopped listening\n")
            self.broadcast_log.see(tk.END)
    
    def send_broadcast(self):
        """Send a broadcast message"""
        try:
            port = int(self.broadcast_port.get().strip())
            message = self.broadcast_msg.get().strip()
            
            if not message:
                messagebox.showerror("Input Error", "Please enter a message to broadcast")
                return
            
            # Start sending in a separate thread
            threading.Thread(
                target=self._send_broadcast_thread,
                args=(port, message),
                daemon=True
            ).start()
            
            # Clear the message field
            self.broadcast_msg.delete(0, tk.END)
        
        except ValueError:
            messagebox.showerror("Input Error", "Invalid port number")
        except Exception as e:
            messagebox.showerror("Broadcast Error", str(e))
    
    def _run_broadcast_listener(self, port):
        """Run the broadcast message listener in a separate thread"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', port))
            sock.settimeout(1)  # 1-second timeout for checking stop flag
            
            self._log_broadcast("Listening for broadcast messages...")
            
            while self.broadcast_running:
                try:
                    data, addr = sock.recvfrom(1024)
                    message = data.decode('utf-8')
                    self._log_broadcast(f"From {addr[0]}: {message}")
                
                except socket.timeout:
                    # Timeout is used to check the stop flag
                    continue
                except Exception as e:
                    self._log_broadcast(f"Error receiving broadcast: {str(e)}")
            
            # Close socket when stopped
            sock.close()
        
        except Exception as e:
            self._log_broadcast(f"Listener error: {str(e)}")
            # Re-enable the start button in case of error
            self.root.after(0, lambda: self.start_broadcast_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_broadcast_btn.config(state=tk.DISABLED))
    
    def _send_broadcast_thread(self, port, message):
        """Send a broadcast message in a separate thread"""
        try:
            # Create UDP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
            # Send to broadcast address
            sock.sendto(message.encode('utf-8'), ('<broadcast>', port))
            
            self._log_broadcast(f"Sent broadcast: {message}")
            
            # Close socket
            sock.close()
        
        except Exception as e:
            self._log_broadcast(f"Error sending broadcast: {str(e)}")
    
    def _log_broadcast(self, message):
        """Log a message to the broadcast log"""
        self.root.after(0, lambda: self._append_to_broadcast_log(message))
    
    def _append_to_broadcast_log(self, message):
        """Append a message to the broadcast log (from main thread)"""
        timestamp = time.strftime("%H:%M:%S")
        self.broadcast_log.insert(tk.END, f"[{timestamp}] {message}\n")
        self.broadcast_log.see(tk.END)

# Main entry point
if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkToolkitApp(root)
    root.mainloop()