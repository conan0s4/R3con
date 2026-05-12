import asyncio
import argparse
from passive import dns_enumerate , dork
from active import resolve_domains , dns_probe , banner_grab


#note: add proxy rotation bypass rate limit , captcha
# note: implement more alternative options sites for dns_enumerate


async def passive_mode(target):
    enum_results = []
    await dns_enumerate(target, enum_results)
    domains = list(set(enum_results))
    print("\n[+] Collected Domains (PASSIVE):")
    print(domains)
    ip_map = await resolve_domains(domains)
    print("\n[+] IP map:")
    print(ip_map)

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