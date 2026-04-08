import requests
import subprocess
import json
import time
import sys
import os
import socket
import base64
from urllib.parse import urlparse, parse_qs
from concurrent.futures import ThreadPoolExecutor, as_completed

# Отключаем буферизацию вывода
sys.stdout.reconfigure(line_buffering=True)

SINGBOX_PATH = "sing-box.exe"
PROXY_LIST_FILE = "proxy.txt"
MAX_WORKERS = 80
TCP_TIMEOUT = 1.5
HTTP_TIMEOUT = 3
SINGBOX_WAIT = 0.8
VALID_STATUSES = {200, 204, 301, 302}

def parse_vless(link):
    try:
        parsed = urlparse(link)
        uuid = parsed.username
        server = parsed.hostname
        port = parsed.port
        if not all([uuid, server, port]):
            return None
        params = parse_qs(parsed.query)
        return {
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "flow": params.get("flow", [""])[0],
            "sni": params.get("sni", [""])[0],
            "pbk": params.get("pbk", [""])[0],
            "sid": params.get("sid", [""])[0],
            "fp": params.get("fp", ["chrome"])[0],
            "network": params.get("type", ["tcp"])[0],
        }
    except:
        return None


def parse_vmess(link):
    try:
        # vmess://base64(json)
        encoded = link[8:]  # убираем vmess://
        # Добавляем паддинг если нужно
        encoded += "=" * (4 - len(encoded) % 4) if len(encoded) % 4 else ""
        data = json.loads(base64.b64decode(encoded))
        return {
            "type": "vmess",
            "server": data.get("add", ""),
            "port": int(data.get("port", 0)),
            "uuid": data.get("id", ""),
            "network": data.get("net", "tcp"),
            "sni": data.get("sni", data.get("host", "")),
            "path": data.get("path", ""),
            "fp": data.get("fp", "chrome"),
            "aid": int(data.get("aid", 0)),
        }
    except:
        return None


def parse_trojan(link):
    try:
        parsed = urlparse(link)
        password = parsed.username
        server = parsed.hostname
        port = parsed.port
        if not all([password, server, port]):
            return None
        params = parse_qs(parsed.query)
        return {
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password,
            "sni": params.get("sni", [""])[0],
            "fp": params.get("fp", ["chrome"])[0],
            "network": params.get("type", ["tcp"])[0],
        }
    except:
        return None


def parse_shadowsocks(link):
    try:
        parsed = urlparse(link)
        server = parsed.hostname
        port = parsed.port
        if not all([server, port]):
            return None

        # Формат: ss://base64(method:password)@server:port#name
        # или ss://method:password@server:port#name
        userinfo = parsed.username
        if not userinfo:
            # Пробуем декодировать из base64
            userinfo_encoded = link[5:].split("@")[0]
            userinfo_encoded += "=" * (4 - len(userinfo_encoded) % 4) if len(userinfo_encoded) % 4 else ""
            userinfo = base64.b64decode(userinfo_encoded).decode()
            if ":" not in userinfo:
                return None

        method, password = userinfo.split(":", 1)
        return {
            "type": "shadowsocks",
            "server": server,
            "port": port,
            "method": method,
            "password": password,
        }
    except:
        return None


def parse_link(link):
    if link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("ss://"):
        return parse_shadowsocks(link)
    return None


def create_outbound(data):
    proto = data["type"]

    if proto == "vless":
        outbound = {
            "type": "vless",
            "server": data["server"],
            "server_port": data["port"],
            "uuid": data["uuid"],
            "flow": data["flow"],
            "tls": {
                "enabled": True,
                "server_name": data["sni"],
                "utls": {
                    "enabled": True,
                    "fingerprint": data["fp"],
                },
            },
        }
        if data.get("pbk"):
            outbound["tls"]["reality"] = {
                "enabled": True,
                "public_key": data["pbk"],
                "short_id": data["sid"],
            }
        return outbound

    elif proto == "vmess":
        outbound = {
            "type": "vmess",
            "server": data["server"],
            "server_port": data["port"],
            "uuid": data["uuid"],
            "security": "auto",
            "alter_id": data["aid"],
            "tls": {
                "enabled": True,
                "server_name": data["sni"],
                "utls": {
                    "enabled": True,
                    "fingerprint": data["fp"],
                },
            } if data.get("sni") else {"enabled": False},
        }
        return outbound

    elif proto == "trojan":
        return {
            "type": "trojan",
            "server": data["server"],
            "server_port": data["port"],
            "password": data["password"],
            "tls": {
                "enabled": True,
                "server_name": data["sni"],
                "utls": {
                    "enabled": True,
                    "fingerprint": data["fp"],
                },
            } if data.get("sni") else {"enabled": False},
        }

    elif proto == "shadowsocks":
        return {
            "type": "shadowsocks",
            "server": data["server"],
            "server_port": data["port"],
            "method": data["method"],
            "password": data["password"],
        }

    return None


def check_proxy(link, index, total):
    data = parse_link(link)
    if not data:
        return None

    port_local = 10000 + index
    config_file = f"temp_{port_local}.json"
    proc = None

    try:
        outbound = create_outbound(data)
        if not outbound:
            return None

        config = {
            "log": {"level": "error"},
            "inbounds": [{
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": port_local,
            }],
            "outbounds": [outbound],
        }

        with open(config_file, "w") as f:
            json.dump(config, f)

        proc = subprocess.Popen(
            [SINGBOX_PATH, "run", "-c", config_file],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(SINGBOX_WAIT)

        # Шаг 1: TCP проверка
        tcp_start = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TCP_TIMEOUT)
            sock.connect(("127.0.0.1", port_local))
            sock.close()
            tcp_ok = True
        except:
            tcp_ok = False

        if not tcp_ok:
            print(f"[{index}/{total}] {data['server']}:{data['port']} [{data['type']}] ❌ TCP")
            return None

        tcp_latency = int((time.time() - tcp_start) * 1000)

        # Шаг 2: HTTP проверка
        http_start = time.time()
        r = requests.get(
            "http://cp.cloudflare.com/",
            proxies={
                "http": f"socks5h://127.0.0.1:{port_local}",
                "https": f"socks5h://127.0.0.1:{port_local}",
            },
            timeout=HTTP_TIMEOUT,
        )

        http_latency = int((time.time() - http_start) * 1000)
        total_latency = tcp_latency + http_latency

        if r.status_code in VALID_STATUSES:
            print(f"[{index}/{total}] {data['server']}:{data['port']} [{data['type']}] ✅ {total_latency}ms")
            return link, total_latency
        else:
            print(f"[{index}/{total}] {data['server']}:{data['port']} [{data['type']}] ❌ HTTP {r.status_code}")
            return None

    except Exception as e:
        print(f"[{index}/{total}] {data['server']}:{data['port']} [{data['type']}] ❌ FAIL")
        return None

    finally:
        if proc:
            try:
                proc.kill()
            except:
                pass
        try:
            os.remove(config_file)
        except:
            pass


def main():
    print("📥 Загружаем источники...", flush=True)

    # Читаем список URL из proxy.txt
    try:
        with open(PROXY_LIST_FILE, "r", encoding="utf-8") as f:
            source_urls = [line.strip() for line in f if line.strip().startswith("http")]
    except Exception as e:
        print(f"❌ Ошибка чтения {PROXY_LIST_FILE}: {e}", flush=True)
        return

    if not source_urls:
        print(f"❌ Нет URL в {PROXY_LIST_FILE}!", flush=True)
        return

    print(f"🔗 Источников: {len(source_urls)}", flush=True)

    # Загружаем все прокси из всех источников
    all_links = []
    for i, url in enumerate(source_urls, 1):
        print(f"  [{i}/{len(source_urls)}] Загружаем {url.split('/')[-1]}...", end=" ", flush=True)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            lines = response.text.splitlines()
            links = [
                line.strip() for line in lines
                if line.strip() and any(
                    line.strip().startswith(p) for p in ("vless://", "vmess://", "trojan://", "ss://")
                )
            ]
            all_links.extend(links)
            print(f"✅ {len(links)} прокси", flush=True)
        except Exception as e:
            print(f"❌ {e}", flush=True)

    # Удаляем дубликаты
    all_links = list(dict.fromkeys(all_links))

    if not all_links:
        print("❌ Не найдено валидных ссылок!", flush=True)
        return

    total = len(all_links)
    print(f"\n🔎 Всего уникальных прокси: {total}", flush=True)

    working = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(check_proxy, proxy, i, total): proxy
            for i, proxy in enumerate(all_links, start=1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result:
                working.append(result)

    print(f"\n⚡ Найдено рабочих: {len(working)} из {total}", flush=True)

    working.sort(key=lambda x: x[1])

    final_list = [p[0] for p in working[:100]]

    with open("working.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(final_list))

    print("💾 Сохранено в working.txt", flush=True)

    # Пушим на GitHub
    push_to_github(final_list)


def push_to_github(links):
    """Пушит список рабочих прокси на GitHub через API"""
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{GITHUB_FILE}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json",
    }

    content = "\n".join(links)

    # Получаем текущий SHA файла (если существует)
    try:
        resp = requests.get(url, headers=headers, params={"ref": GITHUB_BRANCH}, timeout=10)
        sha = resp.json().get("sha") if resp.status_code == 200 else None
    except:
        sha = None

    # Создаём/обновляем файл
    data = {
        "message": f"🔄 Auto-update: {len(links)} working proxies ({time.strftime('%H:%M:%S')})",
        "content": base64.b64encode(content.encode()).decode(),
        "branch": GITHUB_BRANCH,
    }
    if sha:
        data["sha"] = sha

    try:
        resp = requests.put(url, headers=headers, json=data, timeout=10)
        if resp.status_code in (200, 201):
            commit_url = resp.json()["commit"]["html_url"]
            print(f"🚀 GitHub обновлён: {commit_url}", flush=True)
        else:
            print(f"❌ GitHub ошибка: {resp.status_code} {resp.text}", flush=True)
    except Exception as e:
        print(f"❌ GitHub ошибка сети: {e}", flush=True)


if __name__ == "__main__":
    main()
