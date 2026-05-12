import asyncio
import ssl
import socket


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

