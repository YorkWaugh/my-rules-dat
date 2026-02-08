import os
import re
import glob
import subprocess
import requests
import sys
import json
import ipaddress
import shutil

# --- Configuration ---

URLS = {
    "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    "dlc": "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
}

REJECT_SOURCES = [
    {
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "type": "adblock",
    },
    {
        "url": "https://ublockorigin.github.io/uAssetsCDN/filters/filters.min.txt",
        "type": "adblock",
    },
    {
        "url": "https://filters.adtidy.org/extension/ublock/filters/224_optimized.txt",
        "type": "adblock",
    },
    {
        "url": "https://easylist-downloads.adblockplus.org/easylistchina.txt",
        "type": "adblock",
    },
    {
        "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "type": "adblock",
    },
    {
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
        "type": "hosts",
    },
    {
        "url": "https://someonewhocares.org/hosts/hosts",
        "type": "hosts",
    },
    {
        "url": "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        "type": "hosts",
    },
]

# --- Helper Functions ---


def download_file(url, target_path=None):
    """Downloads a file from a URL. Returns content if no target_path, else saves to file."""
    try:
        print(f"Downloading: {url}")
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()

        if target_path:
            with open(target_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            print(f"Saved to {target_path}")
            return True
        else:
            return resp.text
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return None if not target_path else False


def unpack_geosite(file_path, output_dir):
    """Unpacks a geosite/dlc dat file using the binary tool."""
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        return False

    # Clean output directory
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    print(f"Unpacking {file_path} to {output_dir}...")
    try:
        subprocess.run(
            ["./bin/geo", "unpack", "site", file_path, "-d", output_dir], check=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"Error unpacking {file_path}: {e}")
        return False


def is_ip_address(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def remove_with_subdomains(domain_set, remove_domains):
    for remove_domain in remove_domains:
        domain_set.discard(remove_domain)
        suffix = "." + remove_domain
        to_remove = {d for d in domain_set if d.endswith(suffix)}
        domain_set -= to_remove
    return domain_set


def clean_full_from_domains(full_set, domain_set):
    clean_full = set()
    for f in full_set:
        parts = f.split(".")
        is_covered = False
        for i in range(len(parts)):
            suffix = ".".join(parts[i:])
            if suffix in domain_set:
                is_covered = True
                break

        if not is_covered:
            clean_full.add(f)
    return clean_full


# --- Parsing Logic ---


def parse_adblock_rule(line):
    line = line.strip()

    if not line or line.startswith("!") or line.startswith("["):
        return None, False

    is_whitelist = line.startswith("@@")
    if is_whitelist:
        line = line[2:]

    if "##" in line or "#@#" in line or "#?#" in line or "#$#" in line:
        return None, False

    if "$" in line:
        modifier_part = line.split("$", 1)[1].lower()
        if any(
            mod in modifier_part
            for mod in [
                "domain=",
                "third-party",
                "3p",
                "badfilter",
                "all",
                "popup",
                "denyallow",
                "denlyallow",
                "removeparam",
                "uritransform",
                "urlskip",
                "replace",
                "redirect",
                "rewrite",
                "popunder",
                "cname",
                "frame",
                "from=",
                "to=",
                "csp",
                "elemhide",
                "generichide",
                "genericblock",
                "header",
                "permissions",
                "ping",
                "inline-script",
                "inline-font",
                "document",
                "doc",
                "app=",
                "script",
                "image",
                "img",
                "stylesheet",
                "css",
                "xmlhttprequest",
                "xhr",
                "font",
                "media",
                "object",
                "subdocument",
                "websocket",
                "webrtc",
                "other",
            ]
        ):
            return None, False

    domain = ""
    # Simple extraction logic for adblock syntax
    if line.startswith("||") and "^" in line:
        caret_pos = line.index("^")
        domain = line[2:caret_pos]
        remainder = line[caret_pos + 1 :]
        if "$" in remainder:
            remainder = remainder.split("$")[0]
        if remainder:
            return None, False
        if "/" in domain:
            return None, False

    elif line.startswith("|http://") or line.startswith("|https://"):
        line = line[1:]
        if "://" in line:
            line = line.split("://", 1)[1]
        if "/" in line:
            return None, False
        if "^" in line:
            domain = line.split("^")[0]
        else:
            domain = line
        if "$" in domain:
            domain = domain.split("$")[0]

    elif line.startswith("://"):
        domain = line[3:]
        if "/" in domain:
            return None, False
        if "^" in domain:
            domain = domain.split("^")[0]
        if "$" in domain:
            domain = domain.split("$")[0]
    else:
        return None, False

    domain = domain.strip(".")
    if not domain or "." not in domain:
        return None, False
    if is_ip_address(domain):
        return None, False
    if not re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*$",
        domain,
    ):
        return None, False

    return domain.lower(), is_whitelist


def parse_hosts_rule(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    match = re.match(
        r"^(?:0\.0\.0\.0|127\.0\.0\.1)\s+([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+)$",
        line,
    )
    if match:
        domain = match.group(1).lower()
        if (
            domain != "localhost"
            and domain != "localhost.localdomain"
            and not is_ip_address(domain)
        ):
            return domain
    return None


def process_reject_upstream():
    blacklist_domains = set()
    blacklist_full = set()

    for source in REJECT_SOURCES:
        content = download_file(source["url"])
        if not content:
            continue

        s_black = set()
        s_full = set()
        s_white = set()

        for line in content.splitlines():
            if source["type"] == "adblock":
                domain, is_white = parse_adblock_rule(line)
                if domain:
                    if is_white:
                        s_white.add(domain)
                    else:
                        s_black.add(domain)
            elif source["type"] == "hosts":
                domain = parse_hosts_rule(line)
                if domain:
                    s_full.add(domain)

        s_black = remove_with_subdomains(s_black, s_white)
        s_full = remove_with_subdomains(s_full, s_white)
        blacklist_domains.update(s_black)
        blacklist_full.update(s_full)
        print(
            f"  -> Extracted from {source['url']}: {len(s_black)} domains, {len(s_full)} full"
        )

    print(
        f"\n  -> Total Reject: {len(blacklist_domains)} domains, {len(blacklist_full)} full"
    )
    return blacklist_domains, [f"full:{d}" for d in blacklist_full]


def extract_cn_from_geosite(base_dir):
    """
    Extracts foreign services in CN (e.g., google@cn) from unpacked MetaCubeX geosite.
    This preserves your original logic for 'geolocation-cn' exactly.
    """
    if not os.path.exists(base_dir):
        print(f"Directory not found: {base_dir}")
        return set(), []

    cn_domains = set()
    cn_specials = []

    for filepath in glob.glob(os.path.join(base_dir, "*")):
        filename = os.path.basename(filepath)

        # Skip standard CN files to focus on foreign services tagged with @cn
        if (
            filename == "cn"
            or filename == "geolocation-cn"
            or "category" in filename
            or "google" in filename
        ):
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.endswith("@cn"):
                    rule_body = line.rsplit("@cn", 1)[0].strip()
                    # Your logic: Only keep 'full' and 'domain' prefixes explicitly.
                    if rule_body.startswith("full:"):
                        cn_specials.append(rule_body)
                    elif rule_body.startswith("domain:"):
                        domain = rule_body.replace("domain:", "")
                        if not domain.endswith(".cn"):
                            cn_domains.add(domain)

    return cn_domains, cn_specials


def read_upstream_list(filename, base_dir):
    """
    Reads a standard upstream list (e.g., cn, geolocation-!cn) from unpacked directory.
    Strictly keeps only 'domain', 'full' and implicit domains (no prefix).
    Discards any other line containing ':' (e.g. regex:, keyword:, include:).
    """
    path = os.path.join(base_dir, filename)
    domains = set()
    specials = []

    if os.path.exists(path):
        print(f"Reading upstream list: {filename} from {base_dir}")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                # Strip attributes (e.g. @attr)
                if "@" in line:
                    line = line.split("@")[0].strip()

                if line.startswith("full:"):
                    specials.append(line)
                    continue

                if line.startswith("domain:"):
                    domains.add(line[7:])
                    continue

                if ":" in line:
                    continue

                domains.add(line)

    else:
        print(f"Warning: Upstream list {filename} not found in {base_dir}")

    return domains, specials


def read_local_list(path):
    domains = set()
    specials = []
    if os.path.exists(path):
        print(f"Reading local rules from: {path}")
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("full:"):
                    content = line[5:]
                    if not is_ip_address(content):
                        specials.append(line)
                elif line.startswith("domain:"):
                    domain = line[7:]
                    if not is_ip_address(domain):
                        domains.add(domain)
    return domains, specials


def deduplicate_and_merge(name, domains, specials):
    print(f"Deduplicating {name}...")
    temp_unsorted = f"{name}_unsorted.txt"
    temp_redundant = f"{name}_redundant.txt"
    temp_clean = f"{name}_clean.txt"
    temp_deleted = f"{name}_deleted_sorted.txt"

    # Write domains to file for the python script helper
    with open(temp_redundant, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(domains))))

    open(temp_unsorted, "w", encoding="utf-8").close()

    # Call external script to find redundancies
    subprocess.run(
        [
            sys.executable,
            "scripts/findRedundantDomain.py",
            temp_redundant,
            temp_unsorted,
        ],
        check=True,
    )

    redundant = []
    if os.path.exists(temp_unsorted):
        with open(temp_unsorted, "r", encoding="utf-8") as f:
            redundant = [line.strip() for line in f if line.strip()]
    redundant.sort()

    with open(temp_deleted, "w", encoding="utf-8") as f:
        f.write("\n".join(redundant))

    # Remove redundant domains
    subprocess.run(
        [
            sys.executable,
            "scripts/removeFrom.py",
            "-remove",
            temp_deleted,
            "-from",
            temp_redundant,
            "-out",
            temp_clean,
        ],
        check=True,
    )

    final_rules = []
    with open(temp_clean, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                final_rules.append(f"domain:{line.strip()}")

    unique_specials = sorted(list(set(specials)))
    final_rules.extend(unique_specials)
    final_rules.sort()

    for f in [temp_unsorted, temp_redundant, temp_clean, temp_deleted]:
        if os.path.exists(f):
            os.remove(f)

    return final_rules


def generate_files(name, rules, output_meta, output_sing):
    print(f"Generating files for {name}...")
    os.makedirs(output_meta, exist_ok=True)
    os.makedirs(output_sing, exist_ok=True)

    # Meta List
    with open(os.path.join(output_meta, f"{name}.list"), "w", encoding="utf-8") as f:
        lines = []
        for r in rules:
            if r.startswith("full:"):
                lines.append(r[5:])
            elif r.startswith("domain:"):
                lines.append("+." + r[7:])
            else:
                lines.append(r)
        lines.sort()
        f.write("\n".join(lines))

    # Meta YAML
    yaml_path = os.path.join(output_meta, f"{name}.yaml")
    with open(yaml_path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for rule in rules:
            if rule.startswith("domain:"):
                f.write(f"  - '+.{rule[7:]}'\n")
            elif rule.startswith("full:"):
                f.write(f"  - '{rule[5:]}'\n")
            else:
                f.write(f"  - '+.{rule}'\n")

    # Sing JSON
    srs_json = {"version": 1, "rules": [{"domain": [], "domain_suffix": []}]}
    for rule in rules:
        if rule.startswith("domain:"):
            srs_json["rules"][0]["domain_suffix"].append(rule[7:])
        elif rule.startswith("full:"):
            srs_json["rules"][0]["domain"].append(rule[5:])

    srs_json["rules"][0]["domain_suffix"].sort()
    srs_json["rules"][0]["domain"].sort()

    json_path = os.path.join(output_sing, f"{name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(srs_json, f, indent=2)

    return json_path, yaml_path


def compile_rules(name, json_path, yaml_path, sing_dir, meta_dir):
    print(f"Compiling rules for {name}...")
    subprocess.run(
        [
            "./bin/sing-box",
            "rule-set",
            "compile",
            json_path,
            "-o",
            os.path.join(sing_dir, f"{name}.srs"),
        ],
        check=True,
    )
    subprocess.run(
        [
            "./bin/mihomo",
            "convert-ruleset",
            "domain",
            "yaml",
            yaml_path,
            os.path.join(meta_dir, f"{name}.mrs"),
        ],
        check=True,
    )


# --- Main Execution ---


def main():
    print(">>> Starting Update Process...")

    # 1. Download Upstream DAT files (In Python now)
    print("\n>>> Phase 1: Downloading upstream resources...")
    download_file(URLS["geosite"], "geosite.dat")
    download_file(URLS["dlc"], "dlc.dat")

    # 2. Unpack DAT files
    print("\n>>> Phase 2: Unpacking resources...")
    # unpack geosite.dat for geolocation-cn (MetaCubeX source)
    unpack_geosite("geosite.dat", "temp_geosite")
    # unpack dlc.dat for cn/!cn (V2Fly source)
    unpack_geosite("dlc.dat", "temp_dlc")

    # 3. Process geolocation-cn (Foreign Services in CN)
    # Source: MetaCubeX (temp_geosite) + Local Lists
    print("\n>>> Phase 3: Processing geolocation-cn (Foreign Services in CN)...")
    cn_repo_domains, cn_repo_specials = extract_cn_from_geosite("temp_geosite")
    cn_local_domains, cn_local_specials = read_local_list("rules/my-cn.list")
    cn_remove_domains, cn_remove_specials = read_local_list("rules/my-cn-remove.list")

    final_cn_foreign = deduplicate_and_merge(
        "geolocation-cn",
        cn_repo_domains.union(cn_local_domains),
        cn_repo_specials + cn_local_specials,
    )

    # Post-process for geolocation-cn
    cn_f_domains = {rule[7:] for rule in final_cn_foreign if rule.startswith("domain:")}
    cn_f_full = {rule[5:] for rule in final_cn_foreign if rule.startswith("full:")}

    cn_f_domains = remove_with_subdomains(cn_f_domains, cn_remove_domains)
    cn_f_full = cn_f_full - set(cn_remove_specials)
    for remove in cn_remove_domains:
        cn_f_full = {
            d for d in cn_f_full if d != remove and not d.endswith("." + remove)
        }
    cn_f_full = clean_full_from_domains(cn_f_full, cn_f_domains)

    final_cn_output = [f"domain:{d}" for d in sorted(cn_f_domains)] + [
        f"full:{f}" for f in sorted(cn_f_full)
    ]

    # 4. Process CN (Standard Domestic + domain:cn)
    # Source: V2Fly (temp_dlc)
    print("\n>>> Phase 4: Processing CN (Standard Domestic + domain:cn)...")
    # Reading from dlc.dat which contains the standard CN list
    std_cn_domains, std_cn_specials = read_upstream_list("cn", "temp_dlc")

    # Force Add 'cn' domain (deduplication will handle redundant children)
    std_cn_domains.add("cn")

    final_cn_full_raw = deduplicate_and_merge("cn", std_cn_domains, std_cn_specials)

    # Cleanup (remove full domains that are covered by wildcard domains)
    cn_full_d = {rule[7:] for rule in final_cn_full_raw if rule.startswith("domain:")}
    cn_full_f = {rule[5:] for rule in final_cn_full_raw if rule.startswith("full:")}
    cn_full_f = clean_full_from_domains(cn_full_f, cn_full_d)

    final_cn_full_output = [f"domain:{d}" for d in sorted(cn_full_d)] + [
        f"full:{f}" for f in sorted(cn_full_f)
    ]

    # 5. Process geolocation-!cn
    # Source: V2Fly (temp_dlc)
    print("\n>>> Phase 5: Processing geolocation-!cn...")
    not_cn_domains, not_cn_specials = read_upstream_list("geolocation-!cn", "temp_dlc")

    final_not_cn_raw = deduplicate_and_merge(
        "geolocation-!cn", not_cn_domains, not_cn_specials
    )

    # Cleanup
    not_cn_d = {rule[7:] for rule in final_not_cn_raw if rule.startswith("domain:")}
    not_cn_f = {rule[5:] for rule in final_not_cn_raw if rule.startswith("full:")}
    not_cn_f = clean_full_from_domains(not_cn_f, not_cn_d)

    final_not_cn_output = [f"domain:{d}" for d in sorted(not_cn_d)] + [
        f"full:{f}" for f in sorted(not_cn_f)
    ]

    # 6. Process Reject Rules
    print("\n>>> Phase 6: Processing Reject rules...")
    reject_repo_domains, reject_repo_specials = process_reject_upstream()
    reject_local_domains, reject_local_specials = read_local_list(
        "rules/my-reject.list"
    )
    reject_remove_domains, reject_remove_specials = read_local_list(
        "rules/my-reject-remove.list"
    )

    final_reject = deduplicate_and_merge(
        "reject",
        reject_repo_domains.union(reject_local_domains),
        reject_repo_specials + reject_local_specials,
    )

    rej_d = {rule[7:] for rule in final_reject if rule.startswith("domain:")}
    rej_f = {rule[5:] for rule in final_reject if rule.startswith("full:")}

    rej_d = remove_with_subdomains(rej_d, reject_remove_domains)
    rej_f = rej_f - set(reject_remove_specials)
    for remove in reject_remove_domains:
        rej_f = {d for d in rej_f if d != remove and not d.endswith("." + remove)}
    rej_f = clean_full_from_domains(rej_f, rej_d)

    final_reject_output = [f"domain:{d}" for d in sorted(rej_d)] + [
        f"full:{f}" for f in sorted(rej_f)
    ]

    # 7. Output and Compile
    meta_dir = "dist/meta/site"
    sing_dir = "dist/sing/site"

    print("\n>>> Phase 7: Writing and Compiling...")

    # geolocation-cn
    cn_json, cn_yaml = generate_files(
        "geolocation-cn", final_cn_output, meta_dir, sing_dir
    )
    compile_rules("geolocation-cn", cn_json, cn_yaml, sing_dir, meta_dir)

    # cn (Full)
    cn_tag_json, cn_tag_yaml = generate_files(
        "cn", final_cn_full_output, meta_dir, sing_dir
    )
    compile_rules("cn", cn_tag_json, cn_tag_yaml, sing_dir, meta_dir)

    # geolocation-!cn
    not_cn_json, not_cn_yaml = generate_files(
        "geolocation-!cn", final_not_cn_output, meta_dir, sing_dir
    )
    compile_rules("geolocation-!cn", not_cn_json, not_cn_yaml, sing_dir, meta_dir)

    # reject
    reject_json, reject_yaml = generate_files(
        "reject", final_reject_output, meta_dir, sing_dir
    )
    compile_rules("reject", reject_json, reject_yaml, sing_dir, meta_dir)

    # Clean up temp files
    if os.path.exists("temp_geosite"):
        shutil.rmtree("temp_geosite")
    if os.path.exists("temp_dlc"):
        shutil.rmtree("temp_dlc")
    if os.path.exists("geosite.dat"):
        os.remove("geosite.dat")
    if os.path.exists("dlc.dat"):
        os.remove("dlc.dat")

    print("\n>>> All done!")


if __name__ == "__main__":
    main()
