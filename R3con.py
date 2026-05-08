import asyncio
import httpx
import ssl
import socket
import argparse
import aiohttp
import urllib.parse
from bs4 import BeautifulSoup

# note: implement more alternative options sites for dns_enumerate
async def dns_enumerate(domain, results):
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    async with httpx.AsyncClient(timeout=60.0) as client:
        try:
            r = await client.get(url, params=params)
            try:
                data = r.json()
            except Exception:
                return
            if not isinstance(data, list):
                return
        except Exception:
            return
    for item in data:
        name = item.get("name_value")
        if name:
            # crt.sh often returns multiple domains separated by newline
            for sub in name.split("\n"):
                if sub not in results:
                    results.append(sub)


async def dns_probe(domain, results):
    def _probe():
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
            alt = cert.get("subjectAltName", [])
            for i in alt:
                results.append(i[1])
            subjects = cert.get("subject", [])
            if subjects:
                results.append(subjects[0][0][1])
        except Exception:
            return

    await asyncio.to_thread(_probe)


async def resolve_domains(domains):
    def resolve(domain):
        try:
            return socket.gethostbyname(domain)
        except Exception:
            return None

    tasks = [asyncio.to_thread(resolve, d) for d in domains]
    ips = await asyncio.gather(*tasks)
    ip_map = {}
    for domain, ip in zip(domains, ips):
        if ip:
            ip_map.setdefault(ip, set()).add(domain)
    return ip_map


async def banner_grab(ip, domains):
    def _grab():
        banners = {}
        try:
            for port in [80, 443]:
                try:
                    s = socket.socket()
                    s.settimeout(5)
                    s.connect((ip, port))
                    s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = s.recv(1024).decode(errors="ignore").strip()
                    s.close()
                    banners[port] = banner
                except Exception:
                    continue
        except Exception:
            pass
        return banners

    result = await asyncio.to_thread(_grab)
    return {
        "ip": ip,
        "domains": list(domains),
        "banners": result
    }


async def passive_mode(target):
    # --- Existing DNS/IP Logic ---
    enum_results = []
    await dns_enumerate(target, enum_results)
    domains = list(set(enum_results))
    print("\n[+] Collected Domains (PASSIVE):")
    print(domains)

    ip_map = await resolve_domains(domains)
    print("\n[+] IP map:")
    print(ip_map)

    # --- UPDATED DORKING PIPELINE ---
    async def dork(target):
        # 1. SEARCH: Modular & Expanded Dork List
        dork_queries = [
            # --- 1. THE ROADMAP (Robots & Sitemaps) ---
            f'site:{target} filetype:txt "robots.txt" disallow',
            f'site:{target} filetype:xml "sitemap.xml"',
            f'site:{target} inurl:security.txt',  # Modern standard for vulnerability disclosure

            # --- 2. SENSITIVE FILES & ENVIRONMENTAL LEAKS ---
            f'site:{target} ext:log OR ext:txt OR ext:conf OR ext:env OR ext:ini',
            f'site:{target} ext:sql OR ext:dbf OR ext:mdb',
            f'site:{target} ext:bkp OR ext:bak OR ext:old OR ext:backup',

            # --- 3. MODERN TECH STACK EXPOSURES (Firebase, Docker, Node) ---
            f'site:{target} "firebaseio.com" OR "firebaseapp.com"',  # Firebase DB leaks
            f'site:{target} inurl:docker-compose.yml OR inurl:Dockerfile',  # Container configs
            f'site:{target} inurl:.vscode OR inurl:.idea',  # IDE metadata
            f'site:{target} "production.json" OR "development.json"',  # Node.js/Express configs
            f'site:{target} inurl:__next/static OR inurl:_next/data',  # Next.js data exposure

            # --- 4. DIRECTORY LISTING & INFO EXPOSURE ---
            f'site:{target} intitle:"index of" "parent directory"',
            f'site:{target} intitle:"index of" "password.txt"',
            f'site:{target} intitle:phpinfo "published by the PHP Group"',

            # --- 5. HIDDEN MANAGEMENT & AUTH PORTALS ---
            f'site:{target} inurl:admin OR inurl:login OR inurl:dashboard OR inurl:setup',
            f'site:{target} inurl:wp-content OR inurl:wp-admin',
            f'site:{target} inurl:api OR inurl:v1 OR inurl:v2',

            # --- 6. SOURCE CODE & DOCUMENTATION ---
            f'site:{target} inurl:github OR inurl:gitlab OR inurl:bitbucket',
            f'site:{target} ext:json OR ext:xml OR ext:yaml OR ext:yml',

            # --- 7. HARDCODED CREDENTIALS / ERROR LOGS ---
            f'site:{target} "password" OR "api_key" OR "secret" OR "token"',
            f'site:{target} "SQL syntax error" OR "mysql_fetch_array" OR "ORA-00933"'
        ]
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Custom/Brave"
        ]
        engines = ["https://www.google.com/search?q=", "https://duckduckgo.com/html/?q="]
        results = []
        seen_urls = set()
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i, query in enumerate(dork_queries):
                engine_url = f"{engines[i % len(engines)]}{urllib.parse.quote(query)}"
                headers = {"User-Agent": user_agents[i % len(user_agents)]}
                async def fetch(url, h):
                    try:
                        async with session.get(url, headers=h, timeout=10) as r:
                            return await r.text() if r.status == 200 else None
                    except:
                        return None
                tasks.append(fetch(engine_url, headers))
            responses = await asyncio.gather(*tasks)
            for html in responses:
                if not html: continue
                soup = BeautifulSoup(html, 'html.parser')
                for a in soup.find_all('a', href=True):
                    raw_url = a['href']
                    if "/url?q=" in raw_url:
                        raw_url = raw_url.split("/url?q=")[1].split("&")[0]
                    if not raw_url.startswith("http") or target not in raw_url:
                        continue
                    clean_url = raw_url.split('#')[0].split('?')[0].rstrip('/')
                    if clean_url not in seen_urls and len(results) < 10:
                        seen_urls.add(clean_url)
                        # CATEGORIZE based on the expanded list
                        category = "General Exposure"
                        lower_url = clean_url.lower()
                        if any(x in lower_url for x in ['.env', '.log', '.sql', '.bak', '.old']):
                            category = "CRITICAL: Sensitive File/Backup"
                        elif "robots.txt" in lower_url or "sitemap" in lower_url:
                            cat = "Recon Roadmap"
                        elif "security.txt" in lower_url:
                            cat = "VDP/Security Policy"
                        elif "docker" in lower_url or "firebase" in lower_url:
                            cat = "Modern Infrastructure Leak"
                        elif "index" in lower_url or "parent" in lower_url:
                            category = "Directory Listing"
                        elif any(x in lower_url for x in ['admin', 'login', 'wp-']):
                            category = "Auth/Management Portal"
                        elif "api" in lower_url:
                            category = "API Endpoint"
                        results.append({"url": clean_url, "cat": category})
        return results
    # --- FINAL OUTPUT ---
    print(f"\n[*] Running Deep Passive Dorking for {target}...")
    dork_results = await dork(target)
    if dork_results:
        print(f"[+] Dorking Results Found:")
        for res in dork_results:
            print(f"    - [{res['cat']}] {res['url']}")
    else:
        print("[-] No critical exposures found via dorking.")
    return {"domains": domains, "ips": ip_map, "leaks": dork_results}


async def active_mode(target):
    probe_results = []
    await dns_probe(target, probe_results)
    domains = list(set(probe_results))
    print("\n[+] Collected Domains (ACTIVE):")
    print(domains)
    ip_map = await resolve_domains(domains)
    tasks = []
    for ip, doms in ip_map.items():
        tasks.append(banner_grab(ip, doms))
    results = await asyncio.gather(*tasks)
    print("\n========== FINAL RESULTS ==========\n")
    for r in results:
        print(f"IP: {r['ip']}")
        print(f"Domains: {r['domains']}")
        print("Banners:")
        for port, banner in r["banners"].items():
            print(f"  Port {port}: {banner[:200]}")
        print("-----------------------------------\n")



def main():
    parser = argparse.ArgumentParser(description="recon tool")
    parser.add_argument("--target", required=True, help="Target domain")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-p", action="store_true", help="Passive recon (dns_enum only)")
    group.add_argument("-a", action="store_true", help="Active recon (dns_probe + banner_grab)")
    args = parser.parse_args()
    if args.p:
        asyncio.run(passive_mode(args.target))
    elif args.a:
        asyncio.run(active_mode(args.target))


if __name__ == "__main__":
    main()