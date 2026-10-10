"""
CDP Launcher — single .exe (via PyInstaller)
Double-click: kill old → start Chrome CDP → start TCP proxy → WSL can connect
FIX v3: proxy connects Chrome via IPv4-then-IPv6 fallback (Chrome 版本不同监听不同)
"""
import os, sys, subprocess, time, socket, threading, ctypes

BIND = ('0.0.0.0', 9222)  # 对外监听 IPv4（WSL 经 172.27.64.1 连）


def connect_chrome():
    """连调试 Chrome：先 IPv4 127.0.0.1，失败再 IPv6 ::1（Chrome 版本不同监听不同）。"""
    for family, addr in ((socket.AF_INET, ('127.0.0.1', 9222)),
                         (socket.AF_INET6, ('::1', 9222))):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect(addr)
            return s
        except Exception:
            try:
                s.close()
            except Exception:
                pass
    return None

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_admin():
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

def kill_all():
    # 只杀 Chrome（避免旧实例占用调试端口）。不再杀 python —— 会误杀 HackMate 等其它 Python 进程
    subprocess.run(["taskkill", "/f", "/im", "chrome.exe"], capture_output=True)
    time.sleep(2)

def firewall():
    subprocess.run([
        "netsh", "advfirewall", "firewall", "add", "rule",
        "name=CDP_9222", "dir=in", "action=allow",
        "protocol=TCP", "localport=9222"
    ], capture_output=True)

def start_chrome():
    chrome = os.path.expandvars(r"%ProgramFiles%\Google\Chrome\Application\chrome.exe")
    if not os.path.exists(chrome):
        chrome = os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")
    data_dir = os.path.expandvars(r"%TEMP%\cdp-proxy")
    subprocess.Popen(
        [chrome, f"--remote-debugging-port=9222", f"--user-data-dir={data_dir}",
         "--remote-allow-origins=*"],
        creationflags=subprocess.CREATE_NO_WINDOW
    )
    time.sleep(4)

def proxy_handle(client, addr):
    try:
        remote = connect_chrome()
        if remote is None:
            return
        remote.settimeout(30)
        client.settimeout(30)
        def forward(src, dst):
            try:
                while True:
                    data = src.recv(8192)
                    if not data: break
                    dst.send(data)
            except: pass
            finally:
                try: dst.close()
                except: pass
        t1 = threading.Thread(target=forward, args=(client, remote), daemon=True)
        t2 = threading.Thread(target=forward, args=(remote, client), daemon=True)
        t1.start(); t2.start()
        t1.join(); t2.join()
    except: pass
    finally:
        try: client.close()
        except: pass

def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(BIND)
    server.listen(50)
    while True:
        client, addr = server.accept()
        threading.Thread(target=proxy_handle, args=(client, addr), daemon=True).start()

def main():
    if not is_admin():
        run_admin()

    kill_all()
    firewall()
    start_chrome()
    
    # Test Chrome is ready
    for _ in range(10):
        s = connect_chrome()
        if s:
            s.close()
            break
        time.sleep(1)

    print("CDP Ready — WSL: curl http://172.27.64.1:9222/json")
    
    # Start proxy in background
    proxy_thread = threading.Thread(target=start_proxy, daemon=True)
    proxy_thread.start()
    
    # Show message box
    ctypes.windll.user32.MessageBoxW(0, 
        "CDP Ready!\n\nFrom WSL:\ncurl http://172.27.64.1:9222/json",
        "CDP Launcher", 0x40)
    
    # Keep running for proxy
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
