#!/usr/bin/env bash
set -euo pipefail

if [[ $(id -u) -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

echo "=== VPN Router Setup with Web Interface ==="
echo ""

# Ввод VLESS URL
read -r -p "Введите VLESS ссылку: " VLESS_URL
if [[ -z "${VLESS_URL// /}" ]]; then
  echo "Empty URL"
  exit 1
fi
if [[ "${VLESS_URL}" != vless://* ]]; then
  echo "URL must start with vless://"
  exit 1
fi

# Парсинг VLESS URL
RAW="${VLESS_URL#vless://}"
UUID="$(echo "$RAW" | cut -d@ -f1)"
AFTER_AT="$(echo "$RAW" | cut -d@ -f2)"
SERVER_ADDR="$(echo "$AFTER_AT" | cut -d: -f1)"
SERVER_PORT="$(echo "$AFTER_AT" | cut -d: -f2 | cut -d? -f1)"
PARAMS="$(echo "$AFTER_AT" | cut -d? -f2 | cut -d# -f1 || true)"
REALITY_PUBKEY="$(echo "$PARAMS" | tr '&' '\n' | grep '^pbk=' | cut -d= -f2 || true)"
REALITY_SHORTID="$(echo "$PARAMS" | tr '&' '\n' | grep '^sid=' | cut -d= -f2 || true)"
REALITY_SNI="$(echo "$PARAMS" | tr '&' '\n' | grep '^sni=' | cut -d= -f2 || true)"
REALITY_FP="$(echo "$PARAMS" | tr '&' '\n' | grep '^fp=' | cut -d= -f2 || true)"

if [[ -z "$UUID" || -z "$SERVER_ADDR" || -z "$SERVER_PORT" ]]; then
  echo "URL parse failed"
  exit 1
fi

# Настройки hotspot
read -r -p "SSID для точки (по умолчанию DarkStarVPN): " HOTSPOT_SSID
HOTSPOT_SSID="${HOTSPOT_SSID:-DarkStarVPN}"
read -r -p "Пароль для точки (мин 8 символов, по умолчанию SuperSecretPass): " HOTSPOT_PASS
HOTSPOT_PASS="${HOTSPOT_PASS:-SuperSecretPass}"

WLAN_IF="wlan0"
SOCKS_PORT="1080"
HTTP_PORT="8080"
REDSOCKS_PORT="12345"
WEBUI_PORT="8888"

echo ""
echo "=== [1/7] Установка базовых пакетов ==="
apt update
apt install -y curl wget jq unzip hostapd network-manager redsocks iptables iptables-persistent python3 python3-pip python3-flask

echo ""
echo "=== [2/7] Установка Xray ==="
TMP_DIR="$(mktemp -d)"
cd "$TMP_DIR"

# Скачивание Xray
XRAY_VERSION="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest | jq -r .tag_name)"
XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-arm64-v8a.zip"

echo "Downloading Xray ${XRAY_VERSION}..."
wget -q --show-progress "$XRAY_URL" -O xray.zip
unzip -q xray.zip
mv xray /usr/local/bin/
chmod +x /usr/local/bin/xray
cd /
rm -rf "$TMP_DIR"

echo ""
echo "=== [3/7] Настройка Xray ==="
mkdir -p /usr/local/etc/xray
mkdir -p /var/log/xray

cat > /usr/local/etc/xray/config.json <<EOF
{
  "log":{
    "access":"/var/log/xray/access.log",
    "error":"/var/log/xray/error.log",
    "loglevel":"warning"
  },
  "inbounds":[
    {"port":${SOCKS_PORT},"listen":"127.0.0.1","protocol":"socks","settings":{"auth":"noauth","udp":true}},
    {"port":${HTTP_PORT},"listen":"127.0.0.1","protocol":"http","settings":{}}
  ],
  "outbounds":[
    {
      "protocol":"vless",
      "settings":{"vnext":[{"address":"${SERVER_ADDR}","port":${SERVER_PORT},"users":[{"id":"${UUID}","flow":""}]}]},
      "streamSettings":{
        "network":"tcp",
        "security":"reality",
        "realitySettings":{
          "publicKey":"${REALITY_PUBKEY}",
          "shortId":"${REALITY_SHORTID}",
          "serverName":"${REALITY_SNI}",
          "fingerprint":"${REALITY_FP}",
          "spx":"/"
        }
      }
    },
    {"protocol":"freedom","settings":{}}
  ],
  "routing":{"domainStrategy":"IPIfNonMatch","rules":[]}
}
EOF

cat > /etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
After=network.target

[Service]
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable xray
systemctl start xray

echo ""
echo "=== [4/7] Настройка WiFi Hotspot ==="
nmcli dev set ${WLAN_IF} managed yes || true
nmcli radio wifi on || true
nmcli dev wifi hotspot ifname ${WLAN_IF} ssid "${HOTSPOT_SSID}" password "${HOTSPOT_PASS}" || nmcli con up Hotspot || true
nmcli con modify Hotspot connection.autoconnect yes || true

HOTSPOT_IP="$(ip -4 addr show ${WLAN_IF} | awk '/inet /{print $2}' | cut -d/ -f1 || true)"
if [[ -z "$HOTSPOT_IP" ]]; then
  sleep 2
  HOTSPOT_IP="$(ip -4 addr show ${WLAN_IF} | awk '/inet /{print $2}' | cut -d/ -f1 || true)"
fi

echo ""
echo "=== [5/7] Настройка IP forwarding и Redsocks ==="
sysctl -w net.ipv4.ip_forward=1 >/dev/null
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-forward.conf
sysctl --system >/dev/null || true

cat > /etc/redsocks.conf <<EOF
base {
  log_debug = on;
  log_info = on;
  log = "syslog:daemon";
  daemon = on;
  redirector = iptables;
}
redsocks {
  local_ip = 0.0.0.0;
  local_port = ${REDSOCKS_PORT};
  ip = 127.0.0.1;
  port = ${SOCKS_PORT};
  type = socks5;
  login = "";
  password = "";
  timeout = 10;
  max_accept_backlog = 128;
}
EOF

systemctl enable redsocks
systemctl restart redsocks

echo ""
echo "=== [6/7] Настройка iptables ==="
iptables -t nat -N REDSOCKS 2>/dev/null || true
iptables -t nat -F REDSOCKS
iptables -t nat -C PREROUTING -i ${WLAN_IF} -p tcp -j REDSOCKS 2>/dev/null || iptables -t nat -A PREROUTING -i ${WLAN_IF} -p tcp -j REDSOCKS
iptables -t nat -A REDSOCKS -d 127.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 10.0.0.0/8 -j RETURN
iptables -t nat -A REDSOCKS -d 172.16.0.0/12 -j RETURN
iptables -t nat -A REDSOCKS -d 192.168.0.0/16 -j RETURN
iptables -t nat -A REDSOCKS -d 224.0.0.0/4 -j RETURN
if [[ -n "${HOTSPOT_IP:-}" ]]; then
  iptables -t nat -A REDSOCKS -d ${HOTSPOT_IP}/32 -j RETURN
fi
iptables -t nat -A REDSOCKS -p tcp -m multiport --dports 22,${HTTP_PORT},${SOCKS_PORT},${REDSOCKS_PORT},${WEBUI_PORT} -j RETURN
iptables -t nat -A REDSOCKS -p tcp -j REDIRECT --to-ports ${REDSOCKS_PORT}
iptables -t mangle -C PREROUTING -i ${WLAN_IF} -p udp --dport 443 -j DROP 2>/dev/null || iptables -t mangle -A PREROUTING -i ${WLAN_IF} -p udp --dport 443 -j DROP
netfilter-persistent save || true

echo ""
echo "=== [7/7] Установка веб-интерфейса ==="
mkdir -p /opt/vpn-router
mkdir -p /etc/vpn-router
mkdir -p /var/log/vpn-router

# Сохранение текущих настроек
cat > /etc/vpn-router/config.json <<EOF
{
  "ssid": "${HOTSPOT_SSID}",
  "password": "${HOTSPOT_PASS}",
  "interface": "${WLAN_IF}"
}
EOF

# Создание Python приложения (встроенный код)
cat > /opt/vpn-router/app.py << 'EOFPYTHON'
#!/usr/bin/env python3
from flask import Flask, render_template_string, request, jsonify
import subprocess, json, os
from datetime import datetime

app = Flask(__name__)
CONFIG_FILE = '/etc/vpn-router/config.json'

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {'ssid': 'DarkStarVPN', 'password': 'SuperSecretPass', 'interface': 'wlan0'}

def save_config(config):
    os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
        return {'success': r.returncode == 0, 'output': r.stdout, 'error': r.stderr}
    except:
        return {'success': False, 'error': 'Timeout'}

def get_hotspot_status():
    r = run_cmd("nmcli -t -f NAME,STATE con show --active | grep Hotspot")
    return {'active': r['success'] and r['output'], 'info': r['output'].strip() if r['success'] else 'Неактивен'}

def get_clients():
    r = run_cmd("iw dev wlan0 station dump | grep Station | wc -l")
    try: return int(r['output'].strip())
    except: return 0

def get_xray_status():
    r = run_cmd("systemctl is-active xray")
    return r['output'].strip() == 'active'

def apply_hotspot(ssid, password, interface='wlan0'):
    if len(ssid) < 1 or len(ssid) > 32:
        return {'success': False, 'error': 'SSID: 1-32 символа'}
    if len(password) < 8:
        return {'success': False, 'error': 'Пароль минимум 8 символов'}
    
    cfg = load_config()
    cfg.update({'ssid': ssid, 'password': password, 'interface': interface})
    save_config(cfg)
    
    run_cmd("nmcli con down Hotspot 2>/dev/null || true")
    run_cmd("nmcli con delete Hotspot 2>/dev/null || true")
    r = run_cmd(f'nmcli dev wifi hotspot ifname {interface} ssid "{ssid}" password "{password}"')
    if not r['success']: return r
    run_cmd("nmcli con modify Hotspot connection.autoconnect yes")
    return {'success': True, 'message': 'OK'}

HTML = '''<!DOCTYPE html>
<html lang="ru"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VPN Router</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}.container{background:#fff;border-radius:20px;box-shadow:0 20px 60px rgba(0,0,0,.3);max-width:500px;width:100%;overflow:hidden}.header{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff;padding:30px;text-align:center}.header h1{font-size:28px;margin-bottom:10px}.header p{opacity:.9;font-size:14px}.status-bar{display:flex;padding:20px 30px;background:#f8f9fa;border-bottom:1px solid #e9ecef}.status-item{flex:1;text-align:center}.status-label{font-size:12px;color:#6c757d;text-transform:uppercase;margin-bottom:5px}.status-value{font-size:18px;font-weight:600}.status-active{color:#28a745}.status-inactive{color:#dc3545}.content{padding:30px}.form-group{margin-bottom:25px}label{display:block;margin-bottom:8px;color:#495057;font-weight:500;font-size:14px}input[type=text],input[type=password]{width:100%;padding:12px 15px;border:2px solid #e9ecef;border-radius:10px;font-size:16px;transition:border-color .3s}input[type=text]:focus,input[type=password]:focus{outline:0;border-color:#667eea}.input-hint{font-size:12px;color:#6c757d;margin-top:5px}.btn{width:100%;padding:15px;border:none;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;transition:all .3s}.btn-primary{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff}.btn-primary:hover{transform:translateY(-2px);box-shadow:0 10px 20px rgba(102,126,234,.4)}.btn-primary:disabled{opacity:.6;cursor:not-allowed;transform:none}.alert{padding:15px;border-radius:10px;margin-bottom:20px;display:none}.alert-success{background:#d4edda;color:#155724;border:1px solid #c3e6cb}.alert-error{background:#f8d7da;color:#721c24;border:1px solid #f5c6cb}.alert-info{background:#d1ecf1;color:#0c5460;border:1px solid #bee5eb}.countdown{text-align:center;font-size:48px;font-weight:700;color:#667eea;margin:20px 0}.countdown-text{text-align:center;color:#6c757d;margin-bottom:20px}.modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.5);z-index:1000;align-items:center;justify-content:center}.modal-content{background:#fff;border-radius:20px;padding:40px;max-width:400px;text-align:center}.spinner{border:4px solid #f3f3f3;border-top:4px solid #667eea;border-radius:50%;width:50px;height:50px;animation:spin 1s linear infinite;margin:20px auto}@keyframes spin{0%{transform:rotate(0)}100%{transform:rotate(360deg)}}</style></head><body>
<div class="container"><div class="header"><h1>🛡️ VPN Router</h1><p>Управление Wi-Fi точкой доступа</p></div>
<div class="status-bar"><div class="status-item"><div class="status-label">Hotspot</div><div class="status-value" id="hs"><span class="status-inactive">●</span> ...</div></div>
<div class="status-item"><div class="status-label">VPN</div><div class="status-value" id="vpn"><span class="status-inactive">●</span> ...</div></div>
<div class="status-item"><div class="status-label">Клиенты</div><div class="status-value" id="cl">-</div></div></div>
<div class="content"><div class="alert alert-success" id="as"></div><div class="alert alert-error" id="ae"></div><div class="alert alert-info" id="ai"></div>
<form id="f"><div class="form-group"><label for="ssid">Название сети (SSID)</label><input type="text" id="ssid" required maxlength="32"><div class="input-hint">От 1 до 32 символов</div></div>
<div class="form-group"><label for="pwd">Пароль Wi-Fi</label><input type="password" id="pwd" required minlength="8"><div class="input-hint">Минимум 8 символов</div></div>
<button type="submit" class="btn btn-primary" id="btn">Применить настройки</button></form></div></div>
<div class="modal" id="m"><div class="modal-content"><h2>Перезагрузка</h2><div class="countdown" id="cd">10</div><div class="countdown-text">Переподключитесь к новой сети</div><div class="spinner"></div></div></div>
<script>let t;async function loadStatus(){try{const r=await fetch('/api/status'),d=await r.json();document.getElementById('hs').innerHTML=d.hotspot.active?'<span class="status-active">●</span> Активен':'<span class="status-inactive">●</span> Неактивен';document.getElementById('vpn').innerHTML=d.xray_active?'<span class="status-active">●</span> Работает':'<span class="status-inactive">●</span> Остановлен';document.getElementById('cl').textContent=d.clients}catch(e){console.error(e)}}async function loadSettings(){try{const r=await fetch('/api/settings'),d=await r.json();document.getElementById('ssid').value=d.ssid;document.getElementById('pwd').value=d.password}catch(e){console.error(e)}}function showAlert(type,msg){['as','ae','ai'].forEach(id=>document.getElementById(id).style.display='none');const el=document.getElementById('a'+type.charAt(0));el.textContent=msg;el.style.display='block';setTimeout(()=>el.style.display='none',5000)}function startCountdown(){const m=document.getElementById('m'),c=document.getElementById('cd');m.style.display='flex';let s=10;c.textContent=s;t=setInterval(()=>{s--;c.textContent=s;if(s<=0){clearInterval(t);m.style.display='none';loadStatus();showAlert('info','Переподключитесь к новой сети')}},1000)}document.getElementById('f').addEventListener('submit',async(e)=>{e.preventDefault();const ssid=document.getElementById('ssid').value,pwd=document.getElementById('pwd').value,btn=document.getElementById('btn');btn.disabled=true;btn.textContent='Применяем...';try{const r=await fetch('/api/apply',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ssid,password:pwd})}),d=await r.json();if(d.success){showAlert('success','Применено!');startCountdown()}else showAlert('error',d.error||'Ошибка')}catch(e){showAlert('error','Ошибка соединения')}finally{btn.disabled=false;btn.textContent='Применить настройки'}});loadStatus();loadSettings();setInterval(loadStatus,5000)</script></body></html>'''

@app.route('/')
def index(): return render_template_string(HTML)

@app.route('/api/status')
def api_status(): return jsonify({'hotspot': get_hotspot_status(), 'clients': get_clients(), 'xray_active': get_xray_status(), 'timestamp': datetime.now().isoformat()})

@app.route('/api/settings')
def api_settings(): return jsonify(load_config())

@app.route('/api/apply', methods=['POST'])
def api_apply():
    d = request.get_json()
    return jsonify(apply_hotspot(d.get('ssid','').strip(), d.get('password','').strip()))

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Run as root")
        exit(1)
    app.run(host='0.0.0.0', port=8888, debug=False)
EOFPYTHON

chmod +x /opt/vpn-router/app.py

# Создание systemd сервиса для веб-интерфейса
cat > /etc/systemd/system/vpn-router-web.service <<'EOFSERVICE'
[Unit]
Description=VPN Router Web Interface
After=network.target xray.service

[Service]
Type=simple
User=root
WorkingDirectory=/opt/vpn-router
ExecStart=/usr/bin/python3 /opt/vpn-router/app.py
Restart=always
RestartSec=5
StandardOutput=append:/var/log/vpn-router/webui.log
StandardError=append:/var/log/vpn-router/webui-error.log

[Install]
WantedBy=multi-user.target
EOFSERVICE

systemctl daemon-reload
systemctl enable vpn-router-web.service
systemctl start vpn-router-web.service

echo ""
echo "=========================================="
echo "✅ VPN Router установлен успешно!"
echo "=========================================="
echo ""
echo "📊 Статус сервисов:"
ss -lntp | grep -E ":${SOCKS_PORT}|:${HTTP_PORT}|:${REDSOCKS_PORT}|:${WEBUI_PORT}" || true
nmcli -t -f NAME,DEVICE,STATE con show --active || true
echo ""
echo "🌐 Веб-интерфейс доступен по адресу:"
echo "   http://${HOTSPOT_IP:-10.42.0.1}:${WEBUI_PORT}"
echo ""
echo "📡 Wi-Fi сеть:"
echo "   SSID: ${HOTSPOT_SSID}"
echo "   Пароль: ${HOTSPOT_PASS}"
echo ""
echo "🔧 Управление:"
echo "   Статус Xray:     systemctl status xray"
echo "   Статус веб-UI:   systemctl status vpn-router-web"
echo "   Логи веб-UI:     journalctl -u vpn-router-web -f"
echo ""
echo "=========================================="
