import xml.etree.ElementTree as ET
import re
import os
import json
from datetime import datetime
from jinja2 import Template
from collections import defaultdict

# --------------------------------------
# Load service port mapping (optional)
# --------------------------------------
def load_service_map():
    try:
        with open("firewall_services.json", "r") as f:
            return json.load(f)
    except:
        return {}

service_map = load_service_map()

# --------------------------------------
# Normalize Fortinet config
# --------------------------------------
def parse_fortinet(txt_path):
    with open(txt_path) as f:
        lines = f.readlines()

    policies = []
    address_objects = set()
    used_objects = set()
    current = {}
    inside_policy = False
    vpns = []
    blacklisted_ips = []
    whitelisted_ips = []
    rule_index = 0

    for line in lines:
        line = line.strip()
        lline = line.lower()

        if "config vpn ipsec" in lline:
            vpns.append(line.strip())

        if line.lower().startswith("config firewall address"):
            current_addr = None
            continue
        if lline.startswith("edit "):
            current = {"id": line.split(" ")[1]}
            inside_policy = True
        elif lline == "next" and inside_policy:
            rule = {
                "name": current.get("name", f"policy-{current.get('id')}"),
                "source_zone": [current.get("srcintf", "unknown")],
                "dest_zone": [current.get("dstintf", "unknown")],
                "source": [current.get("srcaddr", "any")],
                "destination": [current.get("dstaddr", "any")],
                "service": [current.get("service", "any")],
                "application": ["any"],
                "action": current.get("action", "deny"),
                "log": current.get("logtraffic", "disable"),
                "index": rule_index
            }

            rule_index += 1

            # Collect usage
            used_objects.add(rule["source"][0])
            used_objects.add(rule["destination"][0])

            policies.append(rule)

            if rule["source"][0].lower() == "blacklist":
                blacklisted_ips.append(rule["source"][0])
            if rule["destination"][0].lower() == "whitelist":
                whitelisted_ips.append(rule["destination"][0])

            current = {}
            inside_policy = False
        elif inside_policy and lline.startswith("set "):
            parts = line.split()
            key = parts[1]
            val = " ".join(parts[2:])
            current[key] = val

        elif "edit " in lline and "config firewall address" in "".join(lines):
            address_objects.add(line.split(" ")[1].strip('"'))

    unused_objects = list(address_objects - used_objects)

    return {
        "rules": policies,
        "vpns": vpns,
        "blacklisted_ips": blacklisted_ips,
        "whitelisted_ips": whitelisted_ips,
        "unused_objects": unused_objects
    }

# --------------------------------------
# Normalize Palo Alto (Basic Support)
# --------------------------------------
def parse_paloalto(xml_path):
    tree = ET.parse(xml_path)
    root = tree.getroot()
    rules = []

    for rule in root.findall(".//rulebase/security/rules/entry"):
        r = {
            "name": rule.get("name"),
            "source_zone": [z.text for z in rule.findall("from/member")],
            "dest_zone": [z.text for z in rule.findall("to/member")],
            "source": [z.text for z in rule.findall("source/member")],
            "destination": [z.text for z in rule.findall("destination/member")],
            "application": [z.text for z in rule.findall("application/member")],
            "service": [z.text for z in rule.findall("service/member")],
            "action": rule.findtext("action", default=""),
            "log": rule.findtext("log-setting", default="none"),
            "index": 0
        }
        rules.append(r)

    ipsec_tunnels = [entry.get("name") for entry in root.findall(".//tunnel/ipsec/entry")]

    return {"rules": rules, "vpns": ipsec_tunnels, "unused_objects": []}

# --------------------------------------
# Classify + detect shadowed
# --------------------------------------
def classify_rules(rules):
    classified = {
        "internal": [],
        "inbound": [],
        "outbound": [],
        "url_whitelist": [],
        "blacklist_outbound": [],
        "whitelist_inbound": [],
        "shadowed": []
    }

    seen_flows = set()

    for r in rules:
        srcz = r.get("source_zone", [])
        dstz = r.get("dest_zone", [])
        action = r.get("action", "")
        src = r.get("source", [])
        dst = r.get("destination", [])
        flow_id = f"{','.join(srcz)}->{','.join(dstz)}:{','.join(src)}->{','.join(dst)}"

        # Shadowing detection
        if flow_id in seen_flows and action == "allow":
            classified["shadowed"].append(r)
        else:
            seen_flows.add(flow_id)

        if all(z in ["lan", "dmz", "internal"] for z in srcz + dstz):
            classified["internal"].append(r)
        elif any(z in ["wan", "outside", "internet"] for z in dstz):
            classified["outbound"].append(r)
        elif any(z in ["wan", "outside", "internet"] for z in srcz):
            classified["inbound"].append(r)

        if action == "allow" and src[0] != "any":
            classified["whitelist_inbound"].append(r)
        if action == "deny" and dst[0] != "any":
            classified["blacklist_outbound"].append(r)

    return classified

# --------------------------------------
# HTML Reporting
# --------------------------------------
def generate_html(data, outfile="firewall_report.html"):
    def format_rule(rule):
        if not rule.get("name"):
            return None

        srcz = rule.get("source_zone", [])
        dstz = rule.get("dest_zone", [])
        src = rule.get("source", [])
        dst = rule.get("destination", [])
        svc = rule.get("service", [])
        log = rule.get("log", "")
        action = rule.get("action", "")
        is_any_any = (src == ["any"] and dst == ["any"] and action == "allow")

        svc_port = ", ".join(service_map.get(s.upper(), s) for s in svc)

        style = "color:red;" if is_any_any else ""

        return f"""
        <li style="{style}">
            <strong>{rule.get('name')}</strong><br/>
            <b>Source Zone:</b> {', '.join(srcz)}<br/>
            <b>Destination Zone:</b> {', '.join(dstz)}<br/>
            <b>Source:</b> {', '.join(src)}<br/>
            <b>Destination:</b> {', '.join(dst)}<br/>
            <b>Service:</b> {svc_port}<br/>
            <b>Action:</b> {action.upper()}<br/>
            <b>Logging:</b> {log}<br/>
        </li>"""

    def section(title, rules):
        rendered = [format_rule(r) for r in rules if format_rule(r)]
        return f"<h2>{title}</h2><ul>{''.join(rendered) or '<li>No relevant rules found.</li>'}</ul>"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html = f"""
    <html>
    <head><meta charset="UTF-8">
    <title>Firewall Audit Report</title>
    <style>
        body {{ font-family: Arial; }}
        li {{ margin-bottom: 1em; }}
    </style>
    </head>
    <body>
    <h1>Firewall Audit Report</h1>
    <p><b>Generated on:</b> {now}</p>

    {section("Internal Rules", data['internal'])}
    {section("Outbound Rules", data['outbound'])}
    {section("Inbound Rules", data['inbound'])}
    {section("IP Whitelist (Inbound)", data['whitelist_inbound'])}
    {section("IP Blacklist (Outbound)", data['blacklist_outbound'])}
    {section("Shadowed Rules", data['shadowed'])}

    <h2>Site-to-Site VPNs</h2>
    <ul>{''.join(f"<li>{v}</li>" for v in data.get("vpns", []) or ["None found"])}</ul>

    <h2>Unused Address Objects</h2>
    <ul>{''.join(f"<li>{obj}</li>" for obj in data.get("unused_objects", []) or ["None found"])}</ul>

    </body></html>
    """

    with open(outfile, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Report written to: {outfile}")

# --------------------------------------
# Vendor Detection
# --------------------------------------
def detect_vendor(file_path):
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(10000).lower()
            if "<config>" in content or "<entry name=" in content:
                return "paloalto"
            if "config firewall policy" in content:
                return "fortinet"
    except:
        return "unknown"
    return "unknown"

# --------------------------------------
# Main
# --------------------------------------
if __name__ == "__main__":
    file_path = input("Enter firewall config file path: ").strip()

    if not os.path.isfile(file_path):
        print("[-] File not found.")
        exit(1)

    vendor = detect_vendor(file_path)
    print(f"[+] Detected vendor: {vendor.upper()}")

    if vendor == "fortinet":
        parsed = parse_fortinet(file_path)
    elif vendor == "paloalto":
        parsed = parse_paloalto(file_path)
    else:
        print("[-] Unsupported or undetected vendor.")
        exit(1)

    rules = parsed.get("rules", [])
    classified = classify_rules(rules)
    classified["vpns"] = parsed.get("vpns", [])
    classified["unused_objects"] = parsed.get("unused_objects", [])

    base = os.path.splitext(os.path.basename(file_path))[0]
    dt = datetime.now().strftime("%Y%m%d_%H%M%S")
    outfile = f"{base}_{vendor}_report_{dt}.html"

    generate_html(classified, outfile=outfile)
