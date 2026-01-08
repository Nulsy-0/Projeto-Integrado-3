#!/usr/bin/env python3
import socket
import nmap


def resolve(addr):
    try:
        return socket.gethostbyname(addr)
    except Exception as e:
        print("Erro ao resolver endereço:", e)
        return None


def parse_ports(text):
    text = text.strip()
    if not text:
        return None

    if "-" in text:
        a, b = map(int, text.split("-", 1))
        return list(range(max(1, a), min(65535, b) + 1))

    return [int(p) for p in text.split(",") if p.strip().isdigit()]


def scan_ports(ip, ports):
    nm = nmap.PortScanner()
    if ports is None:
        nm.scan(ip, arguments="-Pn -p-")
    else:
        nm.scan(ip, ports=",".join(map(str, ports)), arguments="-Pn")
    tcp = nm[ip].get("tcp", {})
    return [p for p, v in tcp.items() if v["state"] == "open"]

def main():
    addr = input("IP ou URL: ")
    ip = resolve(addr)
    if not ip:
        return

    ports = parse_ports(input("Portas (80,443 | 1-1024 | Enter = todas): "))

    print(f"Escaneando {ip}...")
    open_ports = scan_ports(ip, ports)

    if open_ports:
        for p in sorted(open_ports):
            print("Porta aberta:", p)
    else:
        print("Nenhuma porta aberta encontrada.")


if __name__ == "__main__":
    main()