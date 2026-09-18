import base64
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

PORT = 8000
SECRET_PATH = "/sub"

CONFIG = {
    "default_domain": "app-analytics-services.com",
    "port": 443,
    "uuid": "cxlvin777",
    "password": "Cxlvin777",
    "ss_method": "chacha20-ietf-poly1305"
}

def extract_run_app_host(host_header):
    """Extracts host without port from HTTP Host header for authority."""
    if host_header:
        return host_header.split(':')[0]
    return "example.run.app"

def generate_subscription(host_header):
    run_app_host = extract_run_app_host(host_header)
    fixed_address = "app-analytics-services.com"
    port = CONFIG["port"]
    uuid = CONFIG["uuid"]
    pwd = CONFIG["password"]
    ss_credentials = base64.b64encode(f"{CONFIG['ss_method']}:{pwd}".encode()).decode()

    vmess_base = {
        "v": "2",
        "add": fixed_address,
        "port": str(port),
        "id": uuid,
        "aid": "0",
        "scy": "auto",
        "tls": "tls",
        "sni": fixed_address,
        "alpn": "h2,http/1.1",
        "fp": "chrome"
    }

    links = []

    # 1. gRPC NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&encryption=none&insecure=0&fp=chrome&type=grpc&serviceName=cxlvinvl-grpc&authority={run_app_host}&allowInsecure=0&sni={fixed_address}#vless-grpc"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&insecure=0&fp=chrome&type=grpc&serviceName=cxlvintr-grpc&authority={run_app_host}&allowInsecure=0&sni={fixed_address}#trojan-grpc"
    )
    vmess_grpc = vmess_base.copy()
    vmess_grpc.update({
        "ps": "vmess-grpc",
        "net": "grpc",
        "type": "gun",
        "path": "cxlvinvm-grpc",
        "host": run_app_host
    })
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_grpc).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?mode=gun&security=tls&alpn=h2%2Chttp%2F1.1&insecure=0&fp=chrome&type=grpc&serviceName=cxlvinss-grpc&authority={run_app_host}&allowInsecure=0&sni={fixed_address}#ss-grpc"
    )

    # 2. WEBSOCKET NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?encryption=none&type=ws&headerType=none&path=%2FCxlvinVlWS%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinVlWS%20v6"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?type=ws&headerType=none&path=%2FCxlvinTRWS%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinTRWS%20v6"
    )
    vmess_ws = vmess_base.copy()
    vmess_ws.update({"ps": "CxlvinVMWS v6", "net": "ws", "type": "none", "host": run_app_host, "path": "/CxlvinVMWS?ed=2560"})
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_ws).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?type=ws&headerType=none&path=%2FCxlvinSSWS%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinSSWS%20v6"
    )

    # 3. HTTP UPGRADE NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?encryption=none&type=httpupgrade&headerType=none&path=%2FCxlvinVlHU%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinVlHU%20v6"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?type=httpupgrade&headerType=none&path=%2FCxlvinTRHU%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinTRHU%20v6"
    )
    vmess_hu = vmess_base.copy()
    vmess_hu.update({"ps": "CxlvinVMHU v6", "net": "httpupgrade", "type": "none", "host": run_app_host, "path": "/CxlvinVMHU?ed=2560"})
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_hu).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?type=httpupgrade&headerType=none&path=%2FCxlvinSSHU%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinSSHU%20v6"
    )

    # 4. XHTTP NODES
    links.append(
        f"vless://{uuid}@{fixed_address}:{port}?encryption=none&type=xhttp&headerType=auto&path=%2FCxlvinVlXH%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinVlXH%20v6"
    )
    links.append(
        f"trojan://{pwd}@{fixed_address}:{port}?type=xhttp&headerType=auto&path=%2FCxlvinTRXH%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinTRXH%20v6"
    )
    vmess_xh = vmess_base.copy()
    vmess_xh.update({"ps": "CxlvinVMXH v6", "net": "xhttp", "type": "auto", "host": run_app_host, "path": "/CxlvinVMXH?ed=2560"})
    links.append("vmess://" + base64.b64encode(json.dumps(vmess_xh).encode()).decode())
    links.append(
        f"ss://{ss_credentials}@{fixed_address}:{port}?type=xhttp&headerType=auto&path=%2FCxlvinSSXH%3Fed%3D2560&security=tls&host={run_app_host}#CxlvinSSXH%20v6"
    )

    raw_payload = "\n".join(links)
    return base64.b64encode(raw_payload.encode('utf-8'))

class SubHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        host_header = self.headers.get('Host', '')
        
        if self.path == SECRET_PATH or self.path.startswith(f"{SECRET_PATH}?"):
            sub_body = generate_subscription(host_header)
            self.send_response(200)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Profile-Update-Interval', '24')
            self.end_headers()
            self.wfile.write(sub_body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def log_message(self, format, *args):
        return

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', PORT), SubHandler)
    print(f"Subscription server running on port {PORT}...")
    server.serve_forever()
