"""Hàm dùng chung của pipeline v2: quy tắc dẫn xuất (ip_scope, port_class), mã hóa một flow bằng Python thuần (dùng để minh họa và để S5 kiểm tra shards)."""
import math
import re

COMMON_PORTS = {20: "FTP_DATA", 21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP", 135: "RPC", 139: "NETBIOS", 143: "IMAP",
                389: "LDAP", 443: "HTTPS", 445: "SMB", 636: "LDAPS", 1433: "MSSQL", 3306: "MYSQL", 3389: "RDP", 5432: "POSTGRES", 5985: "WINRM_HTTP", 5986: "WINRM_HTTPS",
                8080: "HTTP_ALT", 8443: "HTTPS_ALT"}
CAT_ORDER = ["app_family", "direction", "proto", "service", "conn_state", "local_orig", "local_resp", "orig_ip_scope", "resp_ip_scope", "orig_port_class", "resp_port_class",
             "image_dir_class", "principal_class"]
HOST_DERIVED = ("app_family", "image_dir_class", "principal_class")  # các category lấy từ phía host (eCAR-Bro): tên tiến trình, nơi chạy, loại tài khoản chạy
NUM_ORDER = ["duration", "orig_bytes", "resp_bytes", "missed_bytes", "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
MIN_FREQ = {"app_family": 5, "service": 5}
MAX_VALUES = {"app_family": 5000, "service": 1000}
DEFAULT_MIN_FREQ, DEFAULT_MAX_VALUES = 1, 256
MISSING_TOKENS = ("", "-", "(empty)", "null", "none")


def ip_scope_sql(column):
    c = f"lower(trim(CAST({column} AS VARCHAR)))"
    return f"""CASE
      WHEN {column} IS NULL OR {c} IN ('', '-', '(empty)', 'null', 'none') THEN '<MISSING>'
      WHEN {c} = '::1' OR regexp_matches({c}, '^127\\.') THEN 'LOOPBACK'
      WHEN regexp_matches({c}, '^10\\.') OR regexp_matches({c}, '^192\\.168\\.') OR regexp_matches({c}, '^172\\.(1[6-9]|2[0-9]|3[0-1])\\.') THEN 'PRIVATE'
      WHEN regexp_matches({c}, '^169\\.254\\.') OR regexp_matches({c}, '^fe80:') THEN 'LINK_LOCAL'
      WHEN regexp_matches({c}, '^(fc|fd)') THEN 'PRIVATE_IPV6'
      WHEN regexp_matches({c}, '^(22[4-9]|23[0-9])\\.') OR regexp_matches({c}, '^ff') THEN 'MULTICAST'
      WHEN {c} = '255.255.255.255' THEN 'BROADCAST'
      WHEN regexp_matches({c}, '^([0-9]{{1,3}}\\.){{3}}[0-9]{{1,3}}$') THEN 'PUBLIC_IPV4'
      WHEN strpos({c}, ':') > 0 THEN 'PUBLIC_IPV6'
      ELSE 'OTHER' END"""


def port_class_sql(column):
    common = " ".join(f"WHEN {column} = {p} THEN 'PORT_{p}_{n}'" for p, n in sorted(COMMON_PORTS.items()))
    return (f"CASE WHEN {column} IS NULL THEN '<MISSING>' {common} WHEN {column} BETWEEN 0 AND 1023 THEN 'WELL_KNOWN_OTHER' "
            f"WHEN {column} BETWEEN 1024 AND 49151 THEN 'REGISTERED' WHEN {column} BETWEEN 49152 AND 65535 THEN 'EPHEMERAL' ELSE 'OTHER' END")


def text_cat_sql(column):
    return (f"CASE WHEN {column} IS NULL OR lower(trim(CAST({column} AS VARCHAR))) IN ('', '-', '(empty)', 'null', 'none') THEN '<MISSING>' "
            f"ELSE lower(trim(CAST({column} AS VARCHAR))) END")


def image_dir_class_sql(column="image_path"):
    c = f"lower({column})"
    return (f"CASE WHEN {column} IS NULL OR trim({column}) = '' THEN 'MISSING' "
            f"WHEN {column} NOT LIKE '%\\%' AND {column} NOT LIKE '%/%' THEN 'BARE_NAME' "
            f"WHEN {c} LIKE '%\\temp\\%' OR {c} LIKE '%\\appdata\\%' THEN 'TEMP_OR_APPDATA' "
            f"WHEN {c} LIKE '%\\windows\\system32\\%' OR {c} LIKE '%\\windows\\syswow64\\%' THEN 'SYSTEM32' "
            f"WHEN {c} LIKE '%\\windows\\%' THEN 'WINDOWS_OTHER' "
            f"WHEN {c} LIKE '%\\program files%' THEN 'PROGRAM_FILES' "
            f"WHEN {c} LIKE '%\\users\\%' THEN 'USERS_OTHER' ELSE 'OTHER' END")


def principal_class_sql(column="principal"):
    u, lo = f"upper({column})", f"lower({column})"
    return (f"CASE WHEN {column} IS NULL OR trim({column}) = '' THEN 'NONE' "
            f"WHEN {u} LIKE 'NT AUTHORITY\\%' OR {u} LIKE 'NT SERVICE\\%' OR {u} LIKE 'FONT DRIVER%' OR {u} LIKE 'WINDOW MANAGER%' OR {u} LIKE 'DWM-%' THEN 'SYSTEM_ACCOUNT' "
            f"WHEN {lo} LIKE '%\\administrator' THEN 'ADMINISTRATOR' "
            f"WHEN {lo} LIKE '%\\sysadmin' THEN 'SYSADMIN' ELSE 'DOMAIN_USER' END")


def image_dir_class(path):
    if path is None or str(path).strip() == "":
        return "MISSING"
    p = str(path)
    lo = p.lower()
    if "\\" not in p and "/" not in p:
        return "BARE_NAME"
    if "\\temp\\" in lo or "\\appdata\\" in lo:
        return "TEMP_OR_APPDATA"
    if "\\windows\\system32\\" in lo or "\\windows\\syswow64\\" in lo:
        return "SYSTEM32"
    if "\\windows\\" in lo:
        return "WINDOWS_OTHER"
    if "\\program files" in lo:
        return "PROGRAM_FILES"
    if "\\users\\" in lo:
        return "USERS_OTHER"
    return "OTHER"


def principal_class(v):
    if v is None or str(v).strip() == "":
        return "NONE"
    p = str(v)
    u, lo = p.upper(), p.lower()
    if u.startswith("NT AUTHORITY\\") or u.startswith("NT SERVICE\\") or u.startswith("FONT DRIVER") or u.startswith("WINDOW MANAGER") or u.startswith("DWM-"):
        return "SYSTEM_ACCOUNT"
    if lo.endswith("\\administrator"):
        return "ADMINISTRATOR"
    if lo.endswith("\\sysadmin"):
        return "SYSADMIN"
    return "DOMAIN_USER"


def cat_expr(field):
    """Biểu thức SQL cho giá trị category (chưa mã hóa thành id) của một trường."""
    if field == "image_dir_class":
        return image_dir_class_sql("image_path")
    if field == "principal_class":
        return principal_class_sql("principal")
    if field == "orig_ip_scope":
        return ip_scope_sql("orig_h")
    if field == "resp_ip_scope":
        return ip_scope_sql("resp_h")
    if field == "orig_port_class":
        return port_class_sql("orig_p")
    if field == "resp_port_class":
        return port_class_sql("resp_p")
    return text_cat_sql(field)


# ---- Python thuần (cùng quy tắc, để minh họa và kiểm tra) ----
def _text(v):
    if v is None:
        return "<MISSING>"
    s = str(v).strip().lower()
    return "<MISSING>" if s in MISSING_TOKENS else s


def ip_scope(v):
    if v is None:
        return "<MISSING>"
    c = str(v).strip().lower()
    if c in MISSING_TOKENS:
        return "<MISSING>"
    if c == "::1" or c.startswith("127."):
        return "LOOPBACK"
    if c.startswith("10.") or c.startswith("192.168.") or re.match(r"^172\.(1[6-9]|2[0-9]|3[0-1])\.", c):
        return "PRIVATE"
    if c.startswith("169.254.") or c.startswith("fe80:"):
        return "LINK_LOCAL"
    if c.startswith("fc") or c.startswith("fd"):
        return "PRIVATE_IPV6"
    if re.match(r"^(22[4-9]|23[0-9])\.", c) or c.startswith("ff"):
        return "MULTICAST"
    if c == "255.255.255.255":
        return "BROADCAST"
    if re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}$", c):
        return "PUBLIC_IPV4"
    if ":" in c:
        return "PUBLIC_IPV6"
    return "OTHER"


def port_class(p):
    if p is None:
        return "<MISSING>"
    p = int(p)
    if p in COMMON_PORTS:
        return f"PORT_{p}_{COMMON_PORTS[p]}"
    if 0 <= p <= 1023:
        return "WELL_KNOWN_OTHER"
    if 1024 <= p <= 49151:
        return "REGISTERED"
    if 49152 <= p <= 65535:
        return "EPHEMERAL"
    return "OTHER"


def cat_value(field, row):
    if field == "image_dir_class":
        return image_dir_class(row.get("image_path"))
    if field == "principal_class":
        return principal_class(row.get("principal"))
    if field == "orig_ip_scope":
        return ip_scope(row.get("orig_h"))
    if field == "resp_ip_scope":
        return ip_scope(row.get("resp_h"))
    if field == "orig_port_class":
        return port_class(row.get("orig_p"))
    if field == "resp_port_class":
        return port_class(row.get("resp_p"))
    return _text(row.get(field))


def encode_flow(row, spec):
    """Mã hóa một flow (dict các trường của flows_joined) theo preprocess_spec; trả về các bước trung gian để đọc được."""
    out = {"x_cat": {}, "x_num": {}, "x_bin": {}}
    for f in spec["model_input_layout"]["x_cat_columns"]:
        v = cat_value(f, row)
        fld = spec["categorical"]["fields"][f]
        vid = 1 if v == "<MISSING>" else {e["value"]: e["id"] for e in fld["vocab"]}.get(v, 0)
        out["x_cat"][f] = {"raw_value": v, "id": vid}
    for f in spec["model_input_layout"]["x_num_columns"]:
        st = spec["numeric"]["fields"][f]
        raw = row.get(f)
        if raw is None or (isinstance(raw, float) and math.isnan(raw)):
            out["x_num"][f] = {"raw": None, "log1p": None, "z": 0.0, "missing": 1}
        else:
            lg = math.log1p(max(float(raw), 0.0))
            z = (lg - st["log1p_mean"]) / st["log1p_std"]
            z = max(-spec["numeric"]["zscore_clip_abs"], min(spec["numeric"]["zscore_clip_abs"], z))
            out["x_num"][f] = {"raw": raw, "log1p": lg, "z": z, "missing": 0}
    mb = row.get("missed_bytes")
    out["x_bin"]["has_missed_bytes"] = {"raw": mb, "value": 1 if (mb is not None and mb > 0) else 0}
    return out
