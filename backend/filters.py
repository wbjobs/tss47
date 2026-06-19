from typing import List, Dict, Any, Tuple, Optional
import re

PACKET_ALLOWED_FIELDS = {
    "timestamp": {"type": "number", "sql_col": "p.timestamp", "table": "p"},
    "src_ip": {"type": "string", "sql_col": "p.src_ip", "table": "p"},
    "dst_ip": {"type": "string", "sql_col": "p.dst_ip", "table": "p"},
    "ip": {"type": "string", "sql_col": None, "special": "both_ips"},
    "src_port": {"type": "number", "sql_col": "p.src_port", "table": "p"},
    "dst_port": {"type": "number", "sql_col": "p.dst_port", "table": "p"},
    "port": {"type": "number", "sql_col": None, "special": "both_ports"},
    "protocol": {"type": "string", "sql_col": "p.protocol", "table": "p"},
    "length": {"type": "number", "sql_col": "p.length", "table": "p"},
    "payload_size": {"type": "number", "sql_col": "p.payload_size", "table": "p"},
    "tcp_flags": {"type": "string", "sql_col": "p.tcp_flags", "table": "p"},
    "session_id": {"type": "string", "sql_col": "p.session_id", "table": "p"},
}

SESSION_ALLOWED_FIELDS = {
    **PACKET_ALLOWED_FIELDS,
    "start_time": {"type": "number", "sql_col": "s.start_time", "table": "s"},
    "end_time": {"type": "number", "sql_col": "s.end_time", "table": "s"},
    "duration": {"type": "number", "sql_col": None, "special": "duration"},
    "packet_count": {"type": "number", "sql_col": "s.packet_count", "table": "s"},
    "total_bytes": {"type": "number", "sql_col": "s.total_bytes", "table": "s"},
}

ALLOWED_OPS = {
    "==": lambda col, _: f"{col} = ?",
    "!=": lambda col, _: f"{col} <> ?",
    ">": lambda col, _: f"{col} > ?",
    ">=": lambda col, _: f"{col} >= ?",
    "<": lambda col, _: f"{col} < ?",
    "<=": lambda col, _: f"{col} <= ?",
    "contains": lambda col, _: f"{col} LIKE ?",
    "not_contains": lambda col, _: f"{col} NOT LIKE ?",
    "startswith": lambda col, _: f"{col} LIKE ?",
    "endswith": lambda col, _: f"{col} LIKE ?",
    "in": lambda col, n: f"{col} IN ({','.join(['?'] * n)})",
    "not_in": lambda col, n: f"{col} NOT IN ({','.join(['?'] * n)})",
    "regex": lambda col, _: f"{col} REGEXP ?",
    "has_flag": lambda col, _: f"{col} LIKE ?",
}


_SAFE_STRING_RE = re.compile(r"^[\w\.\-:\*, /@#\$%\^&\+=~\|\\\[\]\(\){}<>\?!`';]+$")


def _parse_value_str(value_str: str, value_type: str, op: str) -> Any:
    """根据类型和操作符，将前端字符串值转换为 SQL 参数列表。"""
    if op in ("in", "not_in"):
        parts = [v.strip() for v in value_str.split(",") if v.strip()]
        if value_type == "number":
            return [float(v) for v in parts]
        return parts
    if value_type == "number":
        try:
            if "." in value_str:
                return [float(value_str)]
            return [int(value_str)]
        except (ValueError, TypeError):
            return [0]
    if op == "contains" or op == "not_contains":
        return [f"%{value_str}%"]
    if op == "startswith":
        return [f"{value_str}%"]
    if op == "endswith":
        return [f"%{value_str}"]
    if op == "has_flag":
        return [f"%{value_str}%"]
    return [value_str]


def parse_filters(filter_json: Optional[List[Dict[str, Any]]],
                  allowed_fields: Dict[str, Dict[str, Any]]) -> Tuple[str, List[Any]]:
    """
    解析前端 filter 数组，返回 (SQL条件片段, 参数列表)。
    所有条件用 AND 连接。
    filter 项示例: {"field": "protocol", "op": "==", "value": "TCP"}
                   {"field": "length", "op": ">=", "value": "1000"}
                   {"field": "src_ip", "op": "in", "value": "10.0.0.1,10.0.0.2"}
    """
    if not filter_json:
        return "", []

    conditions: List[str] = []
    params: List[Any] = []

    for idx, item in enumerate(filter_json):
        if not isinstance(item, dict):
            continue
        field = (item.get("field") or "").strip()
        op = (item.get("op") or "==").strip()
        value_raw = item.get("value")
        if field not in allowed_fields:
            continue
        if op not in ALLOWED_OPS:
            continue
        if value_raw is None or value_raw == "":
            continue

        value_str = str(value_raw)
        field_cfg = allowed_fields[field]
        value_type = field_cfg.get("type", "string")
        special = field_cfg.get("special")
        sql_col = field_cfg.get("sql_col")

        values = _parse_value_str(value_str, value_type, op)
        if not values:
            continue

        op_fn = ALLOWED_OPS[op]

        if special == "both_ips":
            # ip == X  => src_ip=X OR dst_ip=X
            if op in ("==", "contains", "startswith", "endswith"):
                sub1 = op_fn("p.src_ip", len(values))
                sub2 = op_fn("p.dst_ip", len(values))
                conditions.append(f"({sub1} OR {sub2})")
                params.extend(values)
                params.extend(values)
            elif op == "in":
                placeholders = ",".join(["?"] * len(values))
                conditions.append(
                    f"(p.src_ip IN ({placeholders}) OR p.dst_ip IN ({placeholders}))"
                )
                params.extend(values)
                params.extend(values)
            elif op in ("!=", "not_in", "not_contains"):
                if op in ("!=", "not_contains"):
                    sub1 = op_fn("p.src_ip", len(values))
                    sub2 = op_fn("p.dst_ip", len(values))
                    conditions.append(f"({sub1} AND {sub2})")
                    params.extend(values)
                    params.extend(values)
                else:
                    placeholders = ",".join(["?"] * len(values))
                    conditions.append(
                        f"(p.src_ip NOT IN ({placeholders}) AND p.dst_ip NOT IN ({placeholders}))"
                    )
                    params.extend(values)
                    params.extend(values)
            else:
                continue
        elif special == "both_ports":
            if op in ("==",):
                sub1 = op_fn("p.src_port", len(values))
                sub2 = op_fn("p.dst_port", len(values))
                conditions.append(f"({sub1} OR {sub2})")
                params.extend(values)
                params.extend(values)
            elif op in (">", ">=", "<", "<="):
                sub1 = op_fn("p.src_port", len(values))
                sub2 = op_fn("p.dst_port", len(values))
                conditions.append(f"({sub1} OR {sub2})")
                params.extend(values)
                params.extend(values)
            elif op in ("in",):
                placeholders = ",".join(["?"] * len(values))
                conditions.append(
                    f"(p.src_port IN ({placeholders}) OR p.dst_port IN ({placeholders}))"
                )
                params.extend(values)
                params.extend(values)
            else:
                continue
        elif special == "duration":
            # duration = end_time - start_time
            if op in (">", ">=", "<", "<=", "==", "!="):
                col = "(s.end_time - s.start_time)"
                conditions.append(op_fn(col, len(values)))
                params.extend(values)
            else:
                continue
        else:
            if not sql_col:
                continue
            if op in ("in", "not_in"):
                n = len(values)
                conditions.append(op_fn(sql_col, n))
                params.extend(values)
            else:
                conditions.append(op_fn(sql_col, 1))
                params.extend(values)

    if not conditions:
        return "", []

    return " AND " + " AND ".join(conditions), params


def filters_to_querystring(filter_json: Optional[List[Dict[str, Any]]]) -> Dict[str, str]:
    """将 filter 数组编码为 GET 请求参数（作为单个 JSON 字符串）。"""
    import json
    if not filter_json:
        return {}
    return {"filters": json.dumps(filter_json, ensure_ascii=False)}


def parse_filters_from_query(filters_param: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    """从 GET 查询字符串中的 filters=JSON 解析回数组。"""
    if not filters_param:
        return None
    try:
        import json
        parsed = json.loads(filters_param)
        if isinstance(parsed, list):
            return parsed
    except Exception:
        return None
    return None
