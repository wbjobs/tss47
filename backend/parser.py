import os
import sys
import csv
import time
import shutil
import tempfile
import subprocess
import traceback
from typing import Optional, Tuple, Dict, Any, Callable

from database import (
    get_db_sync,
    import_packets_from_csv,
    aggregate_sessions_from_db,
    PACKET_CSV_COLUMNS,
)

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False


PROTOCOL_MAP = {
    1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6",
    47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6",
    88: "EIGRP", 89: "OSPF", 132: "SCTP",
}


def get_protocol_name(proto_num) -> str:
    try:
        n = int(proto_num)
        return PROTOCOL_MAP.get(n, f"UNK({n})")
    except (TypeError, ValueError):
        s = str(proto_num).strip()
        if not s:
            return ""
        if s.isdigit():
            n = int(s)
            return PROTOCOL_MAP.get(n, f"UNK({n})")
        return s.upper()


def make_session_id(proto: str, src_ip: str, dst_ip: str,
                    src_port, dst_port) -> str:
    proto = proto or "OTHER"
    sip = src_ip or ""
    dip = dst_ip or ""
    try:
        sp = int(src_port) if src_port not in (None, "") else 0
    except (ValueError, TypeError):
        sp = 0
    try:
        dp = int(dst_port) if dst_port not in (None, "") else 0
    except (ValueError, TypeError):
        dp = 0
    ip1, ip2 = (sip, dip) if sip <= dip else (dip, sip)
    if proto in ("TCP", "UDP"):
        p1, p2 = (sp, dp) if sp <= dp else (dp, sp)
    else:
        p1, p2 = 0, 0
    return f"{proto}-{ip1}-{ip2}-{p1}-{p2}"


_TSHARK_FIELDS = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "udp.srcport",
    "udp.dstport",
    "ip.proto",
    "ipv6.nxt",
    "frame.len",
    "tcp.payload",
    "udp.length",
    "tcp.flags",
    "tcp.seq",
    "tcp.ack",
    "_ws.col.Protocol",
]

_TSHARK_HEADER_CSV = [
    "timestamp",
    "ip_src", "ip_dst",
    "ipv6_src", "ipv6_dst",
    "tcp_sport", "tcp_dport",
    "udp_sport", "udp_dport",
    "ip_proto", "ipv6_nxt",
    "frame_len",
    "tcp_payload_len",
    "udp_length",
    "tcp_flags_hex",
    "tcp_seq", "tcp_ack",
    "col_proto",
]


def tcp_flags_from_hex(hex_str: str) -> str:
    if not hex_str:
        return ""
    try:
        v = int(hex_str, 16)
    except (ValueError, TypeError):
        return ""
    bits = [
        (0x01, "FIN"),
        (0x02, "SYN"),
        (0x04, "RST"),
        (0x08, "PSH"),
        (0x10, "ACK"),
        (0x20, "URG"),
        (0x40, "ECE"),
        (0x80, "CWR"),
    ]
    flags = [name for (mask, name) in bits if v & mask]
    return ",".join(flags)


def find_tshark() -> Optional[str]:
    candidates = [
        shutil.which("tshark"),
        r"C:\Program Files\Wireshark\tshark.exe",
        r"C:\Program Files (x86)\Wireshark\tshark.exe",
        "/usr/bin/tshark",
        "/usr/local/bin/tshark",
        "/opt/homebrew/bin/tshark",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    return None


def tshark_version_ok(tshark_path: str) -> bool:
    try:
        r = subprocess.run(
            [tshark_path, "-v"],
            capture_output=True, text=True, timeout=15,
        )
        return r.returncode == 0
    except Exception:
        return False


def _run_tshark_to_csv(pcap_path: str, csv_path: str,
                       progress_cb: Optional[Callable[[float, str], None]] = None
                       ) -> Tuple[bool, str, int]:
    tshark = find_tshark()
    if not tshark:
        return False, "未找到 tshark (Wireshark CLI)，请安装 Wireshark 并确保 tshark 在 PATH 中", 0
    if not tshark_version_ok(tshark):
        return False, "tshark 无法执行，请检查 Wireshark 安装", 0

    cmd = [
        tshark,
        "-r", pcap_path,
        "-T", "fields",
        "-E", "separator=,",
        "-E", "quote=d",
        "-E", "header=y",
        "-E", "occurrence=f",
    ]
    for f in _TSHARK_FIELDS:
        cmd.extend(["-e", f])

    file_size = os.path.getsize(pcap_path)
    approx_pkts = max(1, file_size // 600)

    try:
        with open(csv_path, "w", encoding="utf-8", newline="") as out_f:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                bufsize=1 << 20,
            )
            assert proc.stdout is not None
            buf = bytearray()
            line_count = 0
            last_pct = -1
            header_written = False

            for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace")
                if not header_written:
                    out_f.write(",".join(_TSHARK_HEADER_CSV) + "\n")
                    header_written = True
                    continue
                out_f.write(line)
                line_count += 1
                if progress_cb and line_count % 50000 == 0:
                    pct = min(45.0, (line_count / max(1, approx_pkts)) * 45.0)
                    if int(pct) > last_pct:
                        last_pct = int(pct)
                        progress_cb(pct, f"tshark 导出中... 已处理 {line_count} 行")

            retcode = proc.wait(timeout=600)
            if retcode != 0:
                return False, f"tshark 退出码非零: {retcode}", line_count

            if progress_cb:
                progress_cb(45, f"tshark 导出完成，共 {line_count} 行，正在清洗数据并导入...")
        return True, "ok", line_count
    except subprocess.TimeoutExpired:
        return False, "tshark 执行超时", 0
    except Exception as e:
        return False, f"tshark 执行出错: {e}", 0


def _transform_tshark_csv_to_packets(
    raw_csv: str, out_csv: str,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> Tuple[int, float, float]:
    """读取 tshark 导出的 CSV，归一化字段，计算 session_id，写入标准 packets CSV。"""
    rows = 0
    min_ts = None
    max_ts = None

    if PANDAS_AVAILABLE and os.path.getsize(raw_csv) < 5 * 1024 * 1024 * 1024:
        try:
            rows, min_ts, max_ts = _transform_with_pandas(raw_csv, out_csv, progress_cb)
            if rows > 0:
                return rows, min_ts or 0, max_ts or 0
        except Exception as e:
            print(f"[warn] pandas 处理失败，回退到逐行处理: {e}")

    chunk_size = 500000
    batch: list = []
    with open(raw_csv, "r", encoding="utf-8", newline="") as fin, \
         open(out_csv, "w", encoding="utf-8", newline="") as fout:
        reader = csv.DictReader(fin)
        writer = csv.DictWriter(fout, fieldnames=PACKET_CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()

        total_est = max(1, os.path.getsize(raw_csv) // 200)
        processed = 0
        last_pct = 0

        for r in reader:
            ts_raw = (r.get("timestamp") or "").strip()
            if not ts_raw:
                continue
            try:
                ts = float(ts_raw)
            except ValueError:
                continue

            src_ip = (r.get("ip_src") or r.get("ipv6_src") or "").strip()
            dst_ip = (r.get("ip_dst") or r.get("ipv6_dst") or "").strip()
            if not src_ip or not dst_ip:
                continue

            proto_num = (r.get("ip_proto") or r.get("ipv6_nxt") or "").strip()
            col_proto = (r.get("col_proto") or "").strip().upper()
            proto_name = get_protocol_name(proto_num) if proto_num else ""

            tcp_sport = (r.get("tcp_sport") or "").strip()
            tcp_dport = (r.get("tcp_dport") or "").strip()
            udp_sport = (r.get("udp_sport") or "").strip()
            udp_dport = (r.get("udp_dport") or "").strip()

            sport = tcp_sport or udp_sport or ""
            dport = tcp_dport or udp_dport or ""

            if not proto_name and col_proto:
                if col_proto.startswith("TCP"):
                    proto_name = "TCP"
                elif col_proto.startswith("UDP"):
                    proto_name = "UDP"
                elif col_proto.startswith("ICMP"):
                    proto_name = "ICMP"
                elif col_proto.startswith("DNS"):
                    proto_name = "UDP" if udp_sport or udp_dport else "TCP"
                else:
                    proto_name = col_proto.split()[0][:16]

            if (tcp_sport or tcp_dport) and proto_name not in ("TCP",):
                proto_name = "TCP"
            if (udp_sport or udp_dport) and proto_name not in ("UDP",):
                if proto_name in ("", "OTHER") or proto_name.startswith("UNK"):
                    proto_name = "UDP"

            if not proto_name:
                proto_name = "OTHER"

            try:
                frame_len = int(r.get("frame_len") or 0)
            except ValueError:
                frame_len = 0

            payload_size = 0
            if proto_name == "TCP":
                tp = r.get("tcp_payload_len") or ""
                if tp:
                    try:
                        payload_size = int(tp)
                    except ValueError:
                        pass
            elif proto_name == "UDP":
                ul = r.get("udp_length") or ""
                if ul:
                    try:
                        payload_size = max(0, int(ul) - 8)
                    except ValueError:
                        pass

            flags = tcp_flags_from_hex((r.get("tcp_flags_hex") or "").strip()) \
                if proto_name == "TCP" else ""
            tcp_seq = (r.get("tcp_seq") or "").strip() if proto_name == "TCP" else ""
            tcp_ack = (r.get("tcp_ack") or "").strip() if proto_name == "TCP" else ""

            sid = make_session_id(proto_name, src_ip, dst_ip, sport, dport)

            row = {
                "upload_id": 0,
                "timestamp": f"{ts:.9f}",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": sport or "",
                "dst_port": dport or "",
                "protocol": proto_name,
                "length": frame_len,
                "payload_size": payload_size,
                "tcp_flags": flags,
                "tcp_seq": tcp_seq,
                "tcp_ack": tcp_ack,
                "session_id": sid,
            }
            batch.append(row)
            rows += 1
            processed += 1

            if min_ts is None or ts < min_ts:
                min_ts = ts
            if max_ts is None or ts > max_ts:
                max_ts = ts

            if len(batch) >= chunk_size:
                writer.writerows(batch)
                batch.clear()

                pct = 45 + min(25, (processed / max(1, total_est)) * 25)
                if progress_cb and int(pct) > last_pct:
                    last_pct = int(pct)
                    progress_cb(pct, f"数据清洗中... 已处理 {processed} 条")

        if batch:
            writer.writerows(batch)

        if progress_cb:
            progress_cb(72, f"数据清洗完成：{rows} 条有效记录，即将批量导入数据库...")

    return rows, min_ts or 0, max_ts or 0


def _transform_with_pandas(
    raw_csv: str, out_csv: str,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> Tuple[int, float, float]:
    import numpy as np

    if progress_cb:
        progress_cb(46, "使用 pandas 加载数据...")

    usecols = [c for c in _TSHARK_HEADER_CSV]
    dtypes = {c: "object" for c in usecols}

    rows_total = 0
    min_ts = None
    max_ts = None
    header_written = False

    for ci, df in enumerate(pd.read_csv(raw_csv, usecols=usecols, dtype=dtypes,
                                        chunksize=1_000_000, low_memory=False)):
        if progress_cb:
            progress_cb(47 + min(18, ci * 2),
                        f"pandas 处理块 #{ci + 1} ({len(df)} 行)...")

        ts_s = pd.to_numeric(df["timestamp"], errors="coerce")
        mask = ts_s.notna()
        df = df[mask].copy()
        ts_s = ts_s[mask]

        has_ip = df["ip_src"].notna() & df["ip_dst"].notna()
        has_ipv6 = df["ipv6_src"].notna() & df["ipv6_dst"].notna()
        df["src_ip"] = np.where(has_ip, df["ip_src"], df["ipv6_src"])
        df["dst_ip"] = np.where(has_ip, df["ip_dst"], df["ipv6_dst"])
        df = df[df["src_ip"].notna() & df["dst_ip"].notna()].copy()
        ts_s = ts_s[df.index]

        proto_from_num = df["ip_proto"].fillna(df["ipv6_nxt"]).map(
            lambda x: get_protocol_name(x) if pd.notna(x) and str(x).strip() else ""
        )
        df["proto"] = proto_from_num

        has_tcp = df["tcp_sport"].notna() | df["tcp_dport"].notna()
        has_udp = df["udp_sport"].notna() | df["udp_dport"].notna()

        df["sport"] = df["tcp_sport"].fillna(df["udp_sport"]).fillna("")
        df["dport"] = df["tcp_dport"].fillna(df["udp_dport"]).fillna("")

        df.loc[has_tcp & (df["proto"] == ""), "proto"] = "TCP"
        df.loc[has_udp & (df["proto"] == ""), "proto"] = "UDP"
        col_proto_s = df["col_proto"].fillna("").astype(str).str.upper()
        mask_empty = df["proto"].fillna("") == ""
        df.loc[mask_empty & col_proto_s.str.startswith("ICMP"), "proto"] = "ICMP"
        df.loc[mask_empty & col_proto_s.str.startswith("TCP"), "proto"] = "TCP"
        df.loc[mask_empty & col_proto_s.str.startswith("UDP"), "proto"] = "UDP"
        df["proto"] = df["proto"].replace("", "OTHER")

        frame_len_s = pd.to_numeric(df["frame_len"], errors="coerce").fillna(0).astype("int64")

        payload_s = pd.Series(0, index=df.index, dtype="int64")
        tcp_mask = df["proto"] == "TCP"
        if tcp_mask.any():
            tp = pd.to_numeric(df.loc[tcp_mask, "tcp_payload_len"], errors="coerce").fillna(0)
            payload_s.loc[tcp_mask] = tp.astype("int64").values
        udp_mask = df["proto"] == "UDP"
        if udp_mask.any():
            ul = pd.to_numeric(df.loc[udp_mask, "udp_length"], errors="coerce").fillna(0)
            payload_s.loc[udp_mask] = (ul - 8).clip(lower=0).astype("int64").values

        flags_s = pd.Series("", index=df.index, dtype="object")
        seq_s = pd.Series("", index=df.index, dtype="object")
        ack_s = pd.Series("", index=df.index, dtype="object")
        if tcp_mask.any():
            flags_s.loc[tcp_mask] = (
                df.loc[tcp_mask, "tcp_flags_hex"].fillna("").astype(str).map(tcp_flags_from_hex)
            )
            seq_s.loc[tcp_mask] = df.loc[tcp_mask, "tcp_seq"].fillna("").astype(str)
            ack_s.loc[tcp_mask] = df.loc[tcp_mask, "tcp_ack"].fillna("").astype(str)

        proto_arr = df["proto"].astype(str).values
        src_arr = df["src_ip"].astype(str).values
        dst_arr = df["dst_ip"].astype(str).values
        sp_arr = df["sport"].astype(str).values
        dp_arr = df["dport"].astype(str).values
        sids = [
            make_session_id(proto_arr[i], src_arr[i], dst_arr[i], sp_arr[i], dp_arr[i])
            for i in range(len(df))
        ]

        out_df = pd.DataFrame({
            "upload_id": 0,
            "timestamp": ts_s.values,
            "src_ip": src_arr,
            "dst_ip": dst_arr,
            "src_port": sp_arr,
            "dst_port": dp_arr,
            "protocol": proto_arr,
            "length": frame_len_s.values,
            "payload_size": payload_s.values,
            "tcp_flags": flags_s.values,
            "tcp_seq": seq_s.values,
            "tcp_ack": ack_s.values,
            "session_id": sids,
        })

        out_df.to_csv(out_csv, mode="a" if header_written else "w",
                      header=not header_written, index=False)
        header_written = True

        rows_total += len(out_df)
        chunk_min = float(ts_s.min()) if len(ts_s) > 0 else None
        chunk_max = float(ts_s.max()) if len(ts_s) > 0 else None
        if chunk_min is not None:
            if min_ts is None or chunk_min < min_ts:
                min_ts = chunk_min
            if max_ts is None or chunk_max > max_ts:
                max_ts = chunk_max

    if progress_cb:
        progress_cb(72, f"pandas 清洗完成：{rows_total} 条记录，即将导入数据库...")
    return rows_total, min_ts or 0, max_ts or 0


def _parse_with_tshark(
    filepath: str, upload_id: int,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> Tuple[bool, int, float, float]:
    tmpdir = tempfile.mkdtemp(prefix="tshark_")
    raw_csv = os.path.join(tmpdir, "raw.csv")
    pkt_csv = os.path.join(tmpdir, "packets.csv")
    try:
        if progress_cb:
            progress_cb(5, "启动 tshark 导出字段...")

        ok, msg, _ = _run_tshark_to_csv(filepath, raw_csv, progress_cb)
        if not ok:
            return False, 0, 0, 0

        rows, mn, mx = _transform_tshark_csv_to_packets(raw_csv, pkt_csv, progress_cb)
        if rows == 0:
            return False, 0, 0, 0

        if progress_cb:
            progress_cb(78, f"开始批量导入 {rows} 条 packets 到数据库...")

        imported = import_packets_from_csv(pkt_csv, upload_id)
        if imported == 0:
            imported = rows

        if progress_cb:
            progress_cb(90, f"packets 导入完成 ({imported})，正在聚合 sessions ...")

        cnt, mn2, mx2 = aggregate_sessions_from_db(upload_id)
        min_ts = mn if mn and not mn2 else mn2 or mn
        max_ts = mx if mx and not mx2 else mx2 or mx

        if progress_cb:
            progress_cb(100, f"✅ 解析完成！共 {cnt} 个包")

        return True, cnt, min_ts or 0, max_ts or 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ====== Scapy 回退方案 (兼容) ======
def parse_packet(pkt) -> Optional[Dict[str, Any]]:
    if not SCAPY_AVAILABLE:
        return None
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
        tl = pkt[TCP]
        result["src_port"] = int(tl.sport)
        result["dst_port"] = int(tl.dport)
        flags = []
        if tl.flags.F: flags.append("FIN")
        if tl.flags.S: flags.append("SYN")
        if tl.flags.R: flags.append("RST")
        if tl.flags.P: flags.append("PSH")
        if tl.flags.A: flags.append("ACK")
        if tl.flags.U: flags.append("URG")
        result["tcp_flags"] = ",".join(flags) if flags else None
        result["tcp_seq"] = int(tl.seq)
        result["tcp_ack"] = int(tl.ack)
        if not result["protocol"] or result["protocol"] == "OTHER":
            result["protocol"] = "TCP"
    elif UDP in pkt:
        ul = pkt[UDP]
        result["src_port"] = int(ul.sport)
        result["dst_port"] = int(ul.dport)
        if not result["protocol"] or result["protocol"] == "OTHER":
            result["protocol"] = "UDP"
    elif ICMP in pkt:
        if not result["protocol"] or result["protocol"] == "OTHER":
            result["protocol"] = "ICMP"

    result["length"] = len(pkt)
    result["payload_size"] = len(pkt[Raw].load) if Raw in pkt else 0
    try:
        result["timestamp"] = float(pkt.time)
    except Exception:
        result["timestamp"] = time.time()

    result["session_id"] = make_session_id(
        result.get("protocol", ""),
        result.get("src_ip", ""),
        result.get("dst_ip", ""),
        result.get("src_port"),
        result.get("dst_port"),
    )
    return result


def _parse_with_scapy(
    filepath: str, upload_id: int,
    progress_cb: Optional[Callable[[float, str], None]] = None,
) -> Tuple[bool, int, float, float]:
    if not SCAPY_AVAILABLE:
        return False, 0, 0, 0
    if progress_cb:
        progress_cb(10, "使用 Scapy 回退方案读取 pcap ...")
    tmpdir = tempfile.mkdtemp(prefix="scapy_")
    pkt_csv = os.path.join(tmpdir, "packets.csv")
    try:
        BATCH = 50000
        batch = []
        rows = 0
        min_ts = None
        max_ts = None
        with open(pkt_csv, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=PACKET_CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()

            try:
                from scapy.all import PcapReader
                reader = PcapReader(filepath)
            except Exception:
                try:
                    pkts = rdpcap(filepath)
                except Exception as e:
                    return False, 0, 0, 0
                reader = iter(pkts)

            total_est = max(1, os.path.getsize(filepath) // 700)
            idx = 0
            for pkt in reader:
                parsed = parse_packet(pkt)
                if parsed is None:
                    continue
                ts = parsed["timestamp"]
                if min_ts is None or ts < min_ts:
                    min_ts = ts
                if max_ts is None or ts > max_ts:
                    max_ts = ts
                row = {
                    "upload_id": 0,
                    "timestamp": f"{ts:.9f}",
                    "src_ip": parsed["src_ip"],
                    "dst_ip": parsed["dst_ip"],
                    "src_port": parsed.get("src_port") or "",
                    "dst_port": parsed.get("dst_port") or "",
                    "protocol": parsed["protocol"],
                    "length": parsed["length"],
                    "payload_size": parsed["payload_size"],
                    "tcp_flags": parsed.get("tcp_flags") or "",
                    "tcp_seq": parsed.get("tcp_seq") or "",
                    "tcp_ack": parsed.get("tcp_ack") or "",
                    "session_id": parsed["session_id"],
                }
                batch.append(row)
                rows += 1
                idx += 1
                if len(batch) >= BATCH:
                    writer.writerows(batch)
                    batch.clear()
                    if progress_cb:
                        pct = min(50, (idx / total_est) * 50)
                        progress_cb(pct, f"scapy 解析中... 已处理 {idx} 包")
            if batch:
                writer.writerows(batch)

        if rows == 0:
            return False, 0, 0, 0

        if progress_cb:
            progress_cb(60, "scapy 解析完成，开始批量导入...")
        imported = import_packets_from_csv(pkt_csv, upload_id)
        if imported == 0:
            imported = rows
        if progress_cb:
            progress_cb(90, f"packets 导入 ({imported})，聚合 sessions ...")
        cnt, mn2, mx2 = aggregate_sessions_from_db(upload_id)
        mn = min_ts if min_ts and not mn2 else mn2 or min_ts
        mx = max_ts if max_ts and not mx2 else mx2 or max_ts
        if progress_cb:
            progress_cb(100, f"✅ 解析完成！共 {cnt} 个包")
        return True, cnt, mn or 0, mx or 0
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def parse_pcap_file(filepath: str, upload_id: int) -> Tuple[int, float, float]:
    """同步解析入口：优先 tshark，失败回退 scapy。"""
    def cb(pct, msg):
        print(f"  [{pct:5.1f}%] {msg}")
    ok, cnt, mn, mx = _parse_with_tshark(filepath, upload_id, cb)
    if ok:
        return cnt, mn, mx
    ok, cnt, mn, mx = _parse_with_scapy(filepath, upload_id, cb)
    if ok:
        return cnt, mn, mx
    with get_db_sync() as conn:
        c = conn.cursor()
        c.execute("UPDATE uploads SET status='failed' WHERE id=?", (upload_id,))
    return 0, 0, 0


def parse_pcap_file_async(filepath: str, upload_id: int,
                          filename: str, task_id: str) -> Dict[str, Any]:
    """RQ Worker 调用入口：写入 Redis 进度。"""
    from task_queue import (
        update_task_progress, mark_task_failed, mark_task_completed,
    )
    try:
        def cb(pct: float, msg: str):
            try:
                update_task_progress(task_id, pct, msg, {"filename": filename})
            except Exception:
                pass

        ok, cnt, mn, mx = _parse_with_tshark(filepath, upload_id, cb)
        if not ok:
            ok, cnt, mn, mx = _parse_with_scapy(filepath, upload_id, cb)
        if not ok:
            raise RuntimeError("tshark 和 scapy 均解析失败")

        result = {
            "upload_id": upload_id,
            "filename": filename,
            "packet_count": cnt,
            "min_timestamp": mn,
            "max_timestamp": mx,
        }
        mark_task_completed(task_id, f"✅ 解析完成，共 {cnt} 个包", result)
        return result
    except Exception as e:
        tb = traceback.format_exc()
        mark_task_failed(task_id, f"{e}\n{tb}")
        raise
