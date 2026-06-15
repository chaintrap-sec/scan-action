"""Signal tier for content-scan rules: block vs review vs info (display-only)."""

from __future__ import annotations

SignalTier = str  # block | review | info

# Hard block — PR must fail when any of these fire (with fail_on_mal).
BLOCK_RULE_IDS: frozenset[str] = frozenset(
    {
        "CTC-KB001",
        "CTC-TTP002",
        "CTC-TTP010",
        "setup_py_install_hook",
        "exec_urllib_urlopen_chain",
        "eval_urllib_urlopen_chain",
        "marshal_zlib_chain",
        "marshal_loads",
        "builtins_dunder_import_exec",
        "exec_base64_decode",
        "eval_base64_decode",
        "exec_zlib_decompress",
        "pickle_loads",
        "dill_loads",
        "cloudpickle_loads",
        "subprocess_popen_shell_true",
        "discord_webhook_url",
        "pastebin_url",
        "tor_onion_url",
        "transfer_sh_url",
        "burp_collaborator_callback",
        "rundll32_invoke",
        "powershell_invoke_webrequest",
        "powershell_start_process_hidden",
        "wscript_invocation",
        "pe_dos_header_bytes_escape",
        "aliababcloud_dep",
        "typosquat_aliababcloud_dep",
    }
)

# Low-signal — hidden from TL;DR unless expanded.
INFO_RULE_IDS: frozenset[str] = frozenset(
    {
        "dynamic_import_dunder",
        "importlib_import_module",
        "importlib_find_spec",
        "getattr_import_chain",
        "requests_http",
        "httpx_http",
        "urllib_urlopen",
        "socket_network",
        "ftplib_ftp",
        "pycryptodome_publickey",
        "setup_console_scripts_entry_points",
        "codec_rot13",
        "dropbox_shared_content_url",
        "webhook_site_url",
        "http_url_literal_ipv4",
        "long_base64_string_literal",
        "cmd_forfiles_glob_mask",
        "unix_ls_command_substitution_glob",
    }
)

# Explicit review-tier (medium/high process noise that needs human eyes, not auto-block).
REVIEW_RULE_IDS: frozenset[str] = frozenset(
    {
        "os_system",
        "subprocess_spawn",
        "eval_call",
        "exec_call",
        "base64_b64decode",
        "compile_exec_mode",
        "compile_base64_decode",
        "runpy_run_path",
        "runpy_run_module",
        "os_execv",
        "os_startfile",
        "pty_spawn",
        "ctypes_native_load",
        "types_functiontype",
        "builtins_subscript_exec",
        "builtins_subscript_eval",
        "getattr_exec",
        "getattr_eval",
        "builtins_dunder_import_compile",
        "smtplib_smtp",
        "ssl_unverified_context",
        "yaml_load_open",
        "yaml_load_unsafe_generic",
        "powershell_expand_archive",
        "powershell_gcm_wildcard_obfuscation",
        "powershell_gal_wildcard_obfuscation",
        "powershell_getcommand_verb_noun_wildcard",
        "cmd_for_f_where_glob",
        "powershell_executioncontext_getcommand",
        "powershell_backtick_cmdlet_split",
        "loldisc_path_question_marks",
        "winreg_set_value",
    }
)

# npm rule ids that map to block (PE*, IH*, OBF critical paths) — prefix match in infer.
NPM_BLOCK_PREFIXES: tuple[str, ...] = ("CTC-",)
NPM_BLOCK_IDS: frozenset[str] = frozenset(
    {
        "CTC-KB001",
        "CTC-TTP002",
        "CTC-TTP010",
        "CTC-OBF020",
    }
)

THEME_LABELS: dict[str, str] = {
    "known_malware": "Known malware (OSV/IOC)",
    "credential_access": "Credential / secret access",
    "data_exfiltration": "Data exfiltration",
    "obfuscation": "Obfuscation",
    "install_time_risk": "Install-time execution",
    "shell_execution": "Shell / process execution",
    "suspicious_network": "Suspicious network",
}

RULE_TO_THEME: dict[str, str] = {
    "CTC-KB001": "known_malware",
    "exec_urllib_urlopen_chain": "install_time_risk",
    "eval_urllib_urlopen_chain": "install_time_risk",
    "setup_py_install_hook": "install_time_risk",
    "CTC-TTP010": "install_time_risk",
    "CTC-TTP002": "install_time_risk",
    "discord_webhook_url": "data_exfiltration",
    "pastebin_url": "data_exfiltration",
    "tor_onion_url": "data_exfiltration",
    "transfer_sh_url": "data_exfiltration",
    "burp_collaborator_callback": "data_exfiltration",
    "webhook_site_url": "data_exfiltration",
    "smtplib_smtp": "data_exfiltration",
    "marshal_loads": "obfuscation",
    "marshal_zlib_chain": "obfuscation",
    "builtins_dunder_import_exec": "obfuscation",
    "exec_base64_decode": "obfuscation",
    "eval_base64_decode": "obfuscation",
    "long_base64_string_literal": "obfuscation",
    "base64_b64decode": "obfuscation",
    "os_system": "shell_execution",
    "subprocess_spawn": "shell_execution",
    "subprocess_popen_shell_true": "shell_execution",
    "os_execv": "shell_execution",
    "pty_spawn": "shell_execution",
    "rundll32_invoke": "shell_execution",
    "requests_http": "suspicious_network",
    "httpx_http": "suspicious_network",
    "urllib_urlopen": "suspicious_network",
    "dynamic_import_dunder": "suspicious_network",
}

CATEGORY_TO_THEME: dict[str, str] = {
    "credential_theft": "credential_access",
    "CREDENTIAL_THEFT": "credential_access",
    "installer_hook": "install_time_risk",
    "INSTALL_HOOK": "install_time_risk",
    "network": "suspicious_network",
    "NETWORK_DOWNLOAD": "suspicious_network",
    "obfuscation": "obfuscation",
    "OBFUSCATION": "obfuscation",
    "process": "shell_execution",
    "PROCESS_EXECUTION": "shell_execution",
    "code_execution": "shell_execution",
    "deserialization": "obfuscation",
}


def infer_signal_tier(rule_id: str, severity: str = "", category: str = "") -> SignalTier:
    rid = (rule_id or "").strip()
    if rid in BLOCK_RULE_IDS or rid in NPM_BLOCK_IDS:
        return "block"
    if rid in INFO_RULE_IDS:
        return "info"
    if rid in REVIEW_RULE_IDS:
        return "review"
    sev = (severity or "").strip().lower()
    cat = (category or "").strip().lower()
    if sev == "critical":
        return "block"
    if rid.startswith("CTC-") and sev in ("critical", "high"):
        return "block"
    if cat in ("dynamic_import",) or rid.startswith("PE") and sev == "low":
        return "info"
    if cat in ("network",) and sev in ("low", "medium"):
        return "info"
    if sev == "high":
        return "review"
    if sev == "medium":
        return "review"
    return "info"


def theme_for_rule(rule_id: str, category: str = "") -> str:
    if rule_id in RULE_TO_THEME:
        return RULE_TO_THEME[rule_id]
    cat = (category or "").strip()
    if cat in CATEGORY_TO_THEME:
        return CATEGORY_TO_THEME[cat]
    return "shell_execution"
