```markdown
# Network Tools Project

git clone https://github.com/polatmurat/netw-masterclass.git

This project consists of two main components:

1. **Network Toolkit (GUI Application)**  
   A comprehensive Tkinter-based desktop application providing various network utilities such as port scanning, web crawling, file transfer, Wikipedia data fetching, device scanning, and UDP broadcast messaging.

2. **Web-Based Real-Time Chat Server**  
   A lightweight chat server using WebSockets and a built-in HTTP server to serve a simple HTML/JS frontend for real-time messaging.

---

## Project Structure

```

.
├── launcher.py               # Main launcher to run both parts
├── chat\_server.py            # WebSocket and HTTP server for chat
├── NetworkToolkitApp.py      # Network Toolkit GUI app
├── web/
│   └── chat.html             # Frontend for chat client

````

---

## Features

### Network Toolkit GUI
- Port Scanner
- Web Crawler for extracting links
- File Transfer (Server & Client)
- Wikipedia Summary Fetcher
- Local Network Device Scanner
- UDP Broadcast Messaging Sender and Listener

### Web Chat
- Real-time chat messaging with WebSockets
- System messages for user join/leave events
- Auto-reconnect support on disconnections
- Simple, clean HTML/JS frontend

---

## Requirements

- Python 3.7 or higher
- Packages:
  ```bash
  pip install websockets requests beautifulsoup4
````

* `tkinter` (usually included with Python, but check your system)

---

## How to Run

### Run the complete project (recommended)

```bash
python launcher.py
```

* This will open a launcher GUI where you can:

  * Launch the Network Toolkit GUI
  * Start/Stop the chat server and open the chat interface in your browser

---

### Run components individually

* To run the chat server alone:

  ```bash
  python chat_server.py
  ```

  Then open [http://localhost:8000](http://localhost:8000) in your browser.

* To run only the Network Toolkit GUI:

  ```bash
  python NetworkToolkitApp.py
  ```

---

## Notes

* Make sure the `web/` directory containing `chat.html` is in the same folder as `chat_server.py`.
* The chat server runs HTTP on port **8000** and WebSocket on port **8001**.
* The launcher uses subprocess to run the chat server; ensure permissions allow subprocess creation.

---

## License

This project is licensed under the MIT License.

---

## Author

\[Murat Polat] – Feel free to fork, modify, and contribute!
