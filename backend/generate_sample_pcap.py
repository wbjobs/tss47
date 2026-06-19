import os
import time
import random
from scapy.all import Ether, IP, IPv6, TCP, UDP, ICMP, Raw, wrpcap


def generate_sample_pcap(output_path: str, num_packets: int = 2000):
    packets = []
    base_time = time.time() - 60

    servers = [
        ("10.0.0.1", 80),
        ("10.0.0.2", 443),
        ("10.0.0.3", 8080),
        ("192.168.1.100", 22),
        ("192.168.1.101", 53),
    ]

    clients = [
        f"192.168.0.{i}" for i in range(10, 30)
    ]

    dns_servers = ["8.8.8.8", "1.1.1.1", "114.114.114.114"]

    for i in range(num_packets):
        ts_offset = random.uniform(0, 55)
        pkt_time = base_time + ts_offset

        r = random.random()

        if r < 0.55:
            server = random.choice(servers[:3])
            client_ip = random.choice(clients)
            client_port = random.randint(1024, 65535)
            is_request = random.random() < 0.5
            payload_len = random.randint(40, 1500) if random.random() < 0.7 else random.randint(60, 120)

            if is_request:
                flags = "S" if random.random() < 0.05 else "PA" if random.random() < 0.6 else "A"
                pkt = (
                    Ether()
                    / IP(src=client_ip, dst=server[0])
                    / TCP(sport=client_port, dport=server[1], flags=flags)
                    / Raw(load=os.urandom(payload_len))
                )
            else:
                flags = "SA" if random.random() < 0.05 else "PA" if random.random() < 0.6 else "A"
                pkt = (
                    Ether()
                    / IP(src=server[0], dst=client_ip)
                    / TCP(sport=server[1], dport=client_port, flags=flags)
                    / Raw(load=os.urandom(int(payload_len * 1.2)))
                )
            pkt.time = pkt_time
            packets.append(pkt)

        elif r < 0.80:
            client_ip = random.choice(clients)
            server_ip = random.choice(dns_servers)
            client_port = random.randint(1024, 65535)
            payload_len = random.randint(30, 120)
            pkt = (
                Ether()
                / IP(src=client_ip, dst=server_ip)
                / UDP(sport=client_port, dport=53)
                / Raw(load=os.urandom(payload_len))
            )
            pkt.time = pkt_time
            packets.append(pkt)

        elif r < 0.88:
            client_ip = random.choice(clients)
            server_ip = random.choice(clients)
            pkt = (
                Ether()
                / IP(src=client_ip, dst=server_ip)
                / ICMP(type=8 if random.random() < 0.5 else 0)
            )
            pkt.time = pkt_time
            packets.append(pkt)

        elif r < 0.95:
            server = servers[3]
            client_ip = random.choice(clients)
            client_port = random.randint(1024, 65535)
            is_client = random.random() < 0.5
            payload_len = random.randint(30, 200)
            if is_client:
                pkt = (
                    Ether()
                    / IP(src=client_ip, dst=server[0])
                    / TCP(sport=client_port, dport=server[1], flags="PA")
                    / Raw(load=os.urandom(payload_len))
                )
            else:
                pkt = (
                    Ether()
                    / IP(src=server[0], dst=client_ip)
                    / TCP(sport=server[1], dport=client_port, flags="PA")
                    / Raw(load=os.urandom(payload_len))
                )
            pkt.time = pkt_time
            packets.append(pkt)

        else:
            client_ip = random.choice(clients)
            client_port = random.randint(1024, 65535)
            dst_ip = f"239.255.{random.randint(0, 255)}.{random.randint(0, 255)}"
            dst_port = random.choice([1900, 5353, 123])
            payload_len = random.randint(20, 200)
            pkt = (
                Ether()
                / IP(src=client_ip, dst=dst_ip)
                / UDP(sport=client_port, dport=dst_port)
                / Raw(load=os.urandom(payload_len))
            )
            pkt.time = pkt_time
            packets.append(pkt)

    for idx in range(10):
        burst_time = base_time + 10 + idx * 5 + random.uniform(-0.2, 0.2)
        server = servers[1]
        client_ip = clients[idx % len(clients)]
        client_port = random.randint(1024, 65535)
        for _ in range(random.randint(20, 60)):
            pkt = (
                Ether()
                / IP(src=client_ip, dst=server[0])
                / TCP(sport=client_port, dport=server[1], flags="PA")
                / Raw(load=os.urandom(random.randint(500, 1450)))
            )
            pkt.time = burst_time + random.uniform(-0.3, 0.3)
            packets.append(pkt)

    packets.sort(key=lambda p: float(p.time))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    wrpcap(output_path, packets)
    print(f"✅ 生成 {len(packets)} 个数据包 -> {output_path}")
    print(f"   时间跨度: ~{packets[-1].time - packets[0].time:.1f} 秒")

    protocols = {}
    for p in packets:
        if IP in p:
            proto = p[IP].proto
            proto_name = {6: "TCP", 17: "UDP", 1: "ICMP"}.get(proto, f"PROTO_{proto}")
            protocols[proto_name] = protocols.get(proto_name, 0) + 1
    print(f"   协议分布: {protocols}")
    return output_path


if __name__ == "__main__":
    out_dir = os.path.join(os.path.dirname(__file__), "test_data")
    generate_sample_pcap(os.path.join(out_dir, "sample_traffic.pcap"), num_packets=2000)
    generate_sample_pcap(os.path.join(out_dir, "sample_traffic_large.pcap"), num_packets=8000)
