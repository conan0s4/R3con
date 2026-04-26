import asyncio
import httpx
import ssl
import socket
import argparse


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
    enum_results = []
    await dns_enumerate(target, enum_results)
    domains = list(set(enum_results))
    print("\n[+] Collected Domains (PASSIVE):")
    print(domains)
    ip_map = await resolve_domains(domains)
    print("\n[+] IP map:")
    print(ip_map)


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