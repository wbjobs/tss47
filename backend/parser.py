import os
import time
from typing import Optional, Tuple, Dict, Any
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw, PacketList
from database import get_db_sync


PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    88: "EIGRP",
    89: "OSPF",
    132: "SCTP",
}


def get_protocol_name(proto_num: int) -> str:
    return PROTOCOL_MAP.get(proto_num, f"UNK({proto_num})")


def parse_packet(pkt) -> Optional[Dict[str, Any]]:
    result = {}

    if IP in pkt:
        ip_layer = pkt[IP]
        result["src_ip"] = ip_layer.src
        result["dst_ip"] = ip_layer.dst
        result["protocol"] = get_protocol_name(ip_layer.proto)
    elif IPv6 in pkt:
        ip_layer = pkt[IPv6]
        result["src_ip"] = ip_layer.src
        result["dst_ip"] = ip_layer.dst
        result["protocol"] = get_protocol_name(ip_layer.nh)
    else:
        return None

    result["src_port"] = None
    result["dst_port"] = None
    result["tcp_flags"] = None
    result["tcp_seq"] = None
    result["tcp_ack"] = None

    if TCP in pkt:
        tcp_layer = pkt[TCP]
        result["src_port"] = int(tcp_layer.sport)
        result["dst_port"] = int(tcp_layer.dport)
        flags = []
        if tcp_layer.flags.F:
            flags.append("FIN")
        if tcp_layer.flags.S:
            flags.append("SYN")
        if tcp_layer.flags.R:
            flags.append("RST")
        if tcp_layer.flags.P:
            flags.append("PSH")
        if tcp_layer.flags.A:
            flags.append("ACK")
        if tcp_layer.flags.U:
            flags.append("URG")
        result["tcp_flags"] = ",".join(flags) if flags else None
        result["tcp_seq"] = int(tcp_layer.seq)
        result["tcp_ack"] = int(tcp_layer.ack)
    elif UDP in pkt:
        udp_layer = pkt[UDP]
        result["src_port"] = int(udp_layer.sport)
        result["dst_port"] = int(udp_layer.dport)
    elif ICMP in pkt:
        result["src_port"] = None
        result["dst_port"] = None

    result["length"] = len(pkt)
    if Raw in pkt:
        result["payload_size"] = len(pkt[Raw].load)
    else:
        result["payload_size"] = 0

    try:
        result["timestamp"] = float(pkt.time)
    except Exception:
        result["timestamp"] = time.time()

    proto = result.get("protocol", "")
    src_ip = result.get("src_ip", "")
    dst_ip = result.get("dst_ip", "")
    sp = result.get("src_port") or 0
    dp = result.get("dst_port") or 0
    ip1, ip2 = sorted([src_ip, dst_ip])
    p1, p2 = sorted([sp, dp]) if proto in ("TCP", "UDP") else (0, 0)
    result["session_id"] = f"{proto}-{ip1}-{ip2}-{p1}-{p2}"

    return result


def parse_pcap_file(filepath: str, upload_id: int) -> Tuple[int, float, float]:
    sessions: Dict[str, Dict[str, Any]] = {}
    packet_count = 0
    min_ts = None
    max_ts = None

    try:
        packets = rdpcap(filepath)
    except Exception as e:
        print(f"Error reading pcap: {e}")
        return 0, 0, 0

    batch = []
    BATCH_SIZE = 5000

    with get_db_sync() as conn:
        c = conn.cursor()

        for pkt in packets:
            parsed = parse_packet(pkt)
            if parsed is None:
                continue

            packet_count += 1
            ts = parsed["timestamp"]
            if min_ts is None or ts < min_ts:
                min_ts = ts
            if max_ts is None or ts > max_ts:
                max_ts = ts

            sid = parsed["session_id"]
            if sid not in sessions:
                sessions[sid] = {
                    "id": sid,
                    "upload_id": upload_id,
                    "src_ip": parsed["src_ip"],
                    "dst_ip": parsed["dst_ip"],
                    "src_port": parsed["src_port"],
                    "dst_port": parsed["dst_port"],
                    "protocol": parsed["protocol"],
                    "packet_count": 0,
                    "total_bytes": 0,
                    "start_time": ts,
                    "end_time": ts,
                }
            sess = sessions[sid]
            sess["packet_count"] += 1
            sess["total_bytes"] += parsed["length"]
            if ts < sess["start_time"]:
                sess["start_time"] = ts
            if ts > sess["end_time"]:
                sess["end_time"] = ts

            batch.append((
                upload_id,
                ts,
                parsed["src_ip"],
                parsed["dst_ip"],
                parsed["src_port"],
                parsed["dst_port"],
                parsed["protocol"],
                parsed["length"],
                parsed["payload_size"],
                parsed["tcp_flags"],
                parsed["tcp_seq"],
                parsed["tcp_ack"],
                sid,
            ))

            if len(batch) >= BATCH_SIZE:
                c.executemany("""
                    INSERT INTO packets
                    (upload_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                     protocol, length, payload_size, tcp_flags, tcp_seq, tcp_ack, session_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, batch)
                batch.clear()

        if batch:
            c.executemany("""
                INSERT INTO packets
                (upload_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                 protocol, length, payload_size, tcp_flags, tcp_seq, tcp_ack, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, batch)

        for sess in sessions.values():
            c.execute("""
                INSERT OR REPLACE INTO sessions
                (id, upload_id, src_ip, dst_ip, src_port, dst_port, protocol,
                 packet_count, total_bytes, start_time, end_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                sess["id"],
                sess["upload_id"],
                sess["src_ip"],
                sess["dst_ip"],
                sess["src_port"],
                sess["dst_port"],
                sess["protocol"],
                sess["packet_count"],
                sess["total_bytes"],
                sess["start_time"],
                sess["end_time"],
            ))

        c.execute("""
            UPDATE uploads SET packet_count=?, status='completed'
            WHERE id=?
        """, (packet_count, upload_id))

        conn.commit()

    return packet_count, min_ts or 0, max_ts or 0
