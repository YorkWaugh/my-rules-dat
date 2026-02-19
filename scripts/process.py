import os
import re
import glob
import subprocess
import requests
import sys
import json
import ipaddress
import shutil

URLS = {
    "geosite": "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
    "dnsmasq_china": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf",
    "bogus_nxdomain": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/bogus-nxdomain.china.conf",
    "gfw_ip": "https://raw.githubusercontent.com/pmkol/easymosdns/main/rules/gfw_ip_list.txt",
    "hijacking": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Hijacking/Hijacking.list",
    "google_china": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf",
    "apple_china": "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf",
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
        "url": "https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt",
        "type": "adblock",
    },
    {
        "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "type": "adblock",
    },
    {
        "url": "https://ublockorigin.github.io/uAssetsCDN/filters//badware.min.txt",
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


def download_file(url, target_path=None):
    try:
        resp = requests.get(url, timeout=60, stream=True)
        resp.raise_for_status()
        if target_path:
            with open(target_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    f.write(chunk)
            return True
        else:
            return resp.text
    except Exception:
        return None if not target_path else False


def unpack_geosite(file_path, output_dir):
    if not os.path.exists(file_path):
        return False
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    os.makedirs(output_dir, exist_ok=True)
    try:
        subprocess.run(
            ["./bin/geo", "unpack", "site", file_path, "-d", output_dir], check=True
        )
        return True
    except subprocess.CalledProcessError:
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


def parse_dnsmasq_rule(line):
    line = line.strip()
    if not line or not line.startswith("server=/"):
        return None
    parts = line.split("/")
    if len(parts) >= 2:
        domain = parts[1]
        if domain and not is_ip_address(domain):
            return domain
    return None


def parse_bogus_nxdomain(line):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("bogus-nxdomain="):
        parts = line.split("=")
        if len(parts) == 2:
            return parts[1].strip()
    return None


def parse_clash_list(content):
    domains = set()
    ips = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        type_ = parts[0].strip().upper()
        value = parts[1].strip()

        if type_ in ["DOMAIN", "DOMAIN-SUFFIX"]:
            domains.add(value)
        elif type_ in ["IP-CIDR", "IP-CIDR6"]:
            try:
                ipaddress.ip_network(value, strict=False)
                ips.add(value)
            except ValueError:
                pass
    return domains, ips


def process_reject_upstream():
    blacklist_domains = set()
    blacklist_full = set()
    print("Processing Reject Sources...")
    for source in REJECT_SOURCES:
        content = download_file(source["url"])
        if not content:
            print(f"  [X] Failed to download: {source['url']}")
            continue
        s_black = set()
        s_full = set()
        s_white = set()
        line_count = 0
        for line in content.splitlines():
            line_count += 1
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

        print(f"  [OK] {source['url']}")
        print(
            f"       Rules Parsed: {line_count}, Block Domains: {len(s_black)}, Hosts: {len(s_full)}, Whitelist: {len(s_white)}"
        )

        blacklist_domains.update(s_black)
        blacklist_full.update(s_full)
    return blacklist_domains, [f"full:{d}" for d in blacklist_full]


def extract_geocn_from_geosite(base_dir):
    if not os.path.exists(base_dir):
        return set(), []
    geocn_domains = set()
    geocn_specials = []
    for filepath in glob.glob(os.path.join(base_dir, "*")):
        filename = os.path.basename(filepath)
        if (
            filename == "cn"
            or filename == "geolocation-cn"
            or "category" in filename
            or "google" in filename
            or "apple" in filename
        ):
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.endswith("@cn"):
                    rule_body = line.rsplit("@cn", 1)[0].strip()
                    if rule_body.startswith("full:"):
                        geocn_specials.append(rule_body)
                    elif rule_body.startswith("domain:"):
                        domain = rule_body.replace("domain:", "")
                        if not domain.endswith(".cn"):
                            geocn_domains.add(domain)
    return geocn_domains, geocn_specials


def extract_tagged_domains(base_dir, tag):
    if not os.path.exists(base_dir):
        return set(), []
    tagged_domains = set()
    tagged_specials = []
    tag_suffix = f"@{tag}"
    for filepath in glob.glob(os.path.join(base_dir, "*")):
        if not os.path.isfile(filepath):
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.endswith(tag_suffix):
                    rule_body = line.rsplit(tag_suffix, 1)[0].strip()
                    if rule_body.startswith("full:"):
                        tagged_specials.append(rule_body)
                    elif rule_body.startswith("domain:"):
                        tagged_domains.add(rule_body[7:])
                    elif ":" not in rule_body:
                        tagged_domains.add(rule_body)
    return tagged_domains, tagged_specials


def read_upstream_list(filename, base_dir):
    path = os.path.join(base_dir, filename)
    domains = set()
    specials = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
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
    return domains, specials


def read_local_list(path):
    domains = set()
    specials = []
    if os.path.exists(path):
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
    temp_unsorted = f"{name}_unsorted.txt"
    temp_redundant = f"{name}_redundant.txt"
    temp_clean = f"{name}_clean.txt"
    temp_deleted = f"{name}_deleted_sorted.txt"
    with open(temp_redundant, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(list(domains))))
    open(temp_unsorted, "w", encoding="utf-8").close()
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
    os.makedirs(output_meta, exist_ok=True)
    os.makedirs(output_sing, exist_ok=True)
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


def process_pollution_upstream():
    pollution_ips = set()
    content = download_file(URLS["bogus_nxdomain"])
    if content:
        for line in content.splitlines():
            ip = parse_bogus_nxdomain(line)
            if ip:
                try:
                    ipaddress.ip_address(ip)
                    pollution_ips.add(ip)
                except ValueError:
                    pass
    content = download_file(URLS["gfw_ip"])
    if content:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_network(line, strict=False)
                pollution_ips.add(line)
            except ValueError:
                pass
    return pollution_ips


def simplify_ip_rules(ip_set):
    ipv4_nets = []
    ipv6_nets = []
    for ip_str in ip_set:
        try:
            net = ipaddress.ip_network(ip_str, strict=False)
            if net.version == 4:
                ipv4_nets.append(net)
            else:
                ipv6_nets.append(net)
        except ValueError:
            continue
    collapsed_v4 = ipaddress.collapse_addresses(ipv4_nets)
    collapsed_v6 = ipaddress.collapse_addresses(ipv6_nets)
    return [str(n) for n in collapsed_v4] + [str(n) for n in collapsed_v6]


def generate_ip_files(name, rules, output_meta, output_sing):
    os.makedirs(output_meta, exist_ok=True)
    os.makedirs(output_sing, exist_ok=True)
    with open(os.path.join(output_meta, f"{name}.list"), "w", encoding="utf-8") as f:
        f.write("\n".join(rules))
    yaml_path = os.path.join(output_meta, f"{name}.yaml")
    with open(yaml_path, "w", encoding="utf-8") as f:
        f.write("payload:\n")
        for rule in rules:
            f.write(f"  - '{rule}'\n")
    srs_json = {"version": 2, "rules": [{"ip_cidr": rules}]}
    json_path = os.path.join(output_sing, f"{name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(srs_json, f, indent=2)
    return json_path, yaml_path


def compile_ip_rules(name, json_path, yaml_path, sing_dir, meta_dir):
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
            "ipcidr",
            "yaml",
            yaml_path,
            os.path.join(meta_dir, f"{name}.mrs"),
        ],
        check=True,
    )


def apply_removal_and_clean_specials(
    upstream_domains, upstream_specials, remove_domains, remove_specials
):
    upstream_domains = remove_with_subdomains(upstream_domains, remove_domains)

    upstream_specials_set = set(upstream_specials) - set(remove_specials)
    final_specials = []
    for s in upstream_specials_set:
        if s.startswith("full:"):
            domain = s[5:]
            if not any(
                domain == rm or domain.endswith("." + rm) for rm in remove_domains
            ):
                final_specials.append(s)
        else:
            final_specials.append(s)
    return upstream_domains, final_specials


def main():
    print("Downloading geosite.dat...")
    download_file(URLS["geosite"], "geosite.dat")
    unpack_geosite("geosite.dat", "temp_geosite")

    print("Downloading Hijacking list...")
    hijacking_content = download_file(URLS["hijacking"])
    hijacking_domains = set()
    hijacking_ips = set()
    if hijacking_content:
        hijacking_domains, hijacking_ips = parse_clash_list(hijacking_content)
        print(
            f"  [OK] Hijacking List Parsed: Domains: {len(hijacking_domains)}, IPs: {len(hijacking_ips)}"
        )
    else:
        print("  [X] Failed to download Hijacking list")

    print("Processing geolocation-cn...")
    geocn_upstream_domains, geocn_upstream_specials = extract_geocn_from_geosite(
        "temp_geosite"
    )

    # google_content = download_file(URLS["google_china"])
    # if google_content:
    #     for line in google_content.splitlines():
    #         d = parse_dnsmasq_rule(line)
    #         if d:
    #             geocn_upstream_domains.add(d)

    apple_content = download_file(URLS["apple_china"])
    if apple_content:
        for line in apple_content.splitlines():
            d = parse_dnsmasq_rule(line)
            if d:
                geocn_upstream_domains.add(d)

    geocn_local_domains, geocn_local_specials = read_local_list(
        "rules/my-geolocation-cn.list"
    )
    geocn_remove_domains, geocn_remove_specials = read_local_list(
        "rules/my-geolocation-cn-remove.list"
    )

    geocn_upstream_domains, geocn_upstream_specials = apply_removal_and_clean_specials(
        geocn_upstream_domains,
        geocn_upstream_specials,
        geocn_remove_domains,
        geocn_remove_specials,
    )

    geocn_final_raw = deduplicate_and_merge(
        "geolocation-cn",
        geocn_upstream_domains.union(geocn_local_domains),
        geocn_upstream_specials + geocn_local_specials,
    )
    geocn_final_d = {rule[7:] for rule in geocn_final_raw if rule.startswith("domain:")}
    geocn_final_f = {rule[5:] for rule in geocn_final_raw if rule.startswith("full:")}
    geocn_final_f = clean_full_from_domains(geocn_final_f, geocn_final_d)

    geocn_output = [f"domain:{d}" for d in sorted(geocn_final_d)] + [
        f"full:{f}" for f in sorted(geocn_final_f)
    ]

    print("Processing cn...")
    cn_upstream_domains = {"cn"}
    cn_punycode_tlds = [
        "xn--fiqs8s",  # .中国
        "xn--fiqz9s",  # .中國
        # "xn--j6w193g",  # .香港
        # "xn--kprw13d",  # .台湾
        # "xn--kpry57d",  # .台灣
        # "xn--mix891f",  # .澳門
        # "xn--yfro4i67o",  # .新加坡
        "xn--1qqw23a",  # .佛山
        "xn--xhq521b",  # .广东
        "xn--55qx5d",  # .公司
        "xn--io0a7i",  # .网络
        "xn--3bst00m",  # .集团
        "xn--czru2d",  # .商城
        "xn--czrs0t",  # .商店
        "xn--g2xx48c",  # .购物
        "xn--hxt814e",  # .网店
        "xn--czr694b",  # .商标
        "xn--ses554g",  # .网址
        "xn--5tzm5g",  # .网站
        "xn--fiq228c5hs",  # .中文网
        "xn--vuq861b",  # .信息
        "xn--rhqv96g",  # .世界
        "xn--vhquv",  # .企业
        "xn--unup4y",  # .游戏
        "xn--fjq720a",  # .娱乐
        "xn--kput3i",  # .手机
        "xn--6frz82g",  # .移动
        "xn--3ds443g",  # .在线
        "xn--nyqy26a",  # .健康
        "xn--otu796d",  # .招聘
        "xn--9et52u",  # .时尚
        "xn--efvy88h",  # .新闻
        "xn--imr513n",  # .餐厅
        "xn--6qq986b3xl",  # .我爱你
        "xn--45q11c",  # .八卦
        "xn--55qw42g",  # .公益
        "xn--30rr7y",  # .慈善
        "xn--zfr164b",  # .政务
        "xn--mxtq1m",  # .政府
        "xn--nqv7f",  # .机构
        "xn--nqv7fs00ema",  # .组织机构
        # "xn--tiq49xqyj",  # .天主教
        "xn--jvr189m",  # .食品
        "xn--pbt977c",  # .珠宝
        "xn--kpu716f",  # .手表
        # "xn--3pxu8k",  # .点看
        # "xn--pssy2u",  # .大拿
        "xn--fiq64b",  # .中信
        "xn--8y0a063a",  # .联通
        "xn--estv75g",  # .工行
        "xn--9krt00a",  # .微博
        # "xn--flw351e",  # .谷歌
        # "xn--jlq480n2rg",  # .亚马逊
        # "xn--kcrx77d1x4a",  # .飞利浦
        # "xn--jlq61u9w7b",  # .诺基亚
        # "xn--3oq18vl8pn36a",  # .大众汽车
        # "xn--b4w605ferd",  # .淡马锡
        # "xn--fzys8d69uvgm",  # .電訊盈科
        # "xn--5su34j936bgsg",  # .香格里拉
        # "xn--w4r85el8fhu5dnra",  # .嘉里大酒店
        # "xn--w4rs40l",  # .嘉里
        # "xn--4gq48lf9j",  # .一号店
        # "xn--0zwm56d",  # .测试
        # "xn--g6w251d",  # .測試
    ]
    cn_upstream_domains.update(cn_punycode_tlds)
    cn_upstream_specials = []

    acc_content = download_file(URLS["dnsmasq_china"])
    if acc_content:
        for line in acc_content.splitlines():
            d = parse_dnsmasq_rule(line)
            if d:
                cn_upstream_domains.add(d)

    cn_local_domains, cn_local_specials = read_local_list("rules/my-cn.list")
    cn_remove_domains, cn_remove_specials = read_local_list("rules/my-cn-remove.list")

    cn_upstream_domains, cn_upstream_specials = apply_removal_and_clean_specials(
        cn_upstream_domains, cn_upstream_specials, cn_remove_domains, cn_remove_specials
    )

    cn_final_raw = deduplicate_and_merge(
        "cn",
        cn_upstream_domains.union(cn_local_domains),
        cn_upstream_specials + cn_local_specials,
    )
    cn_final_d = {rule[7:] for rule in cn_final_raw if rule.startswith("domain:")}
    cn_final_f = {rule[5:] for rule in cn_final_raw if rule.startswith("full:")}
    cn_final_f = clean_full_from_domains(cn_final_f, cn_final_d)

    cn_output = [f"domain:{d}" for d in sorted(cn_final_d)] + [
        f"full:{f}" for f in sorted(cn_final_f)
    ]

    print("Processing geolocation-!cn...")
    notcn_upstream_domains, notcn_upstream_specials = read_upstream_list(
        "geolocation-!cn", "temp_geosite"
    )
    extra_notcn_domains, extra_notcn_specials = extract_tagged_domains(
        "temp_geosite", "!cn"
    )
    notcn_upstream_domains.update(extra_notcn_domains)
    notcn_upstream_specials.extend(extra_notcn_specials)

    notcn_local_domains, notcn_local_specials = read_local_list(
        "rules/my-geolocation-!cn.list"
    )
    notcn_remove_domains, notcn_remove_specials = read_local_list(
        "rules/my-geolocation-!cn-remove.list"
    )

    notcn_upstream_domains, notcn_upstream_specials = apply_removal_and_clean_specials(
        notcn_upstream_domains,
        notcn_upstream_specials,
        notcn_remove_domains,
        notcn_remove_specials,
    )

    notcn_final_raw = deduplicate_and_merge(
        "geolocation-!cn",
        notcn_upstream_domains.union(notcn_local_domains),
        notcn_upstream_specials + notcn_local_specials,
    )
    notcn_final_d = {rule[7:] for rule in notcn_final_raw if rule.startswith("domain:")}
    notcn_final_f = {rule[5:] for rule in notcn_final_raw if rule.startswith("full:")}
    notcn_final_f = clean_full_from_domains(notcn_final_f, notcn_final_d)

    notcn_output = [f"domain:{d}" for d in sorted(notcn_final_d)] + [
        f"full:{f}" for f in sorted(notcn_final_f)
    ]

    print("Processing private...")
    private_upstream_domains, private_upstream_specials = read_upstream_list(
        "private", "temp_geosite"
    )
    private_local_domains, private_local_specials = read_local_list(
        "rules/my-private.list"
    )
    private_remove_domains, private_remove_specials = read_local_list(
        "rules/my-private-remove.list"
    )

    private_upstream_domains, private_upstream_specials = (
        apply_removal_and_clean_specials(
            private_upstream_domains,
            private_upstream_specials,
            private_remove_domains,
            private_remove_specials,
        )
    )

    private_final_raw = deduplicate_and_merge(
        "private",
        private_upstream_domains.union(private_local_domains),
        private_upstream_specials + private_local_specials,
    )
    private_final_d = {
        rule[7:] for rule in private_final_raw if rule.startswith("domain:")
    }
    private_final_f = {
        rule[5:] for rule in private_final_raw if rule.startswith("full:")
    }
    private_final_f = clean_full_from_domains(private_final_f, private_final_d)

    private_output = [f"domain:{d}" for d in sorted(private_final_d)] + [
        f"full:{f}" for f in sorted(private_final_f)
    ]

    print("Processing reject...")
    reject_upstream_domains, reject_upstream_specials = process_reject_upstream()

    reject_upstream_domains.update(hijacking_domains)

    reject_local_domains, reject_local_specials = read_local_list(
        "rules/my-reject.list"
    )
    reject_remove_domains, reject_remove_specials = read_local_list(
        "rules/my-reject-remove.list"
    )

    reject_upstream_domains, reject_upstream_specials = (
        apply_removal_and_clean_specials(
            reject_upstream_domains,
            reject_upstream_specials,
            reject_remove_domains,
            reject_remove_specials,
        )
    )

    reject_final_raw = deduplicate_and_merge(
        "reject",
        reject_upstream_domains.union(reject_local_domains),
        reject_upstream_specials + reject_local_specials,
    )
    reject_final_d = {
        rule[7:] for rule in reject_final_raw if rule.startswith("domain:")
    }
    reject_final_f = {rule[5:] for rule in reject_final_raw if rule.startswith("full:")}
    reject_final_f = clean_full_from_domains(reject_final_f, reject_final_d)

    reject_output = [f"domain:{d}" for d in sorted(reject_final_d)] + [
        f"full:{f}" for f in sorted(reject_final_f)
    ]

    meta_dir = "dist/meta/site"
    sing_dir = "dist/sing/site"

    geocn_json, geocn_yaml = generate_files(
        "geolocation-cn", geocn_output, meta_dir, sing_dir
    )
    compile_rules("geolocation-cn", geocn_json, geocn_yaml, sing_dir, meta_dir)

    cn_json, cn_yaml = generate_files("cn", cn_output, meta_dir, sing_dir)
    compile_rules("cn", cn_json, cn_yaml, sing_dir, meta_dir)

    notcn_json, notcn_yaml = generate_files(
        "geolocation-!cn", notcn_output, meta_dir, sing_dir
    )
    compile_rules("geolocation-!cn", notcn_json, notcn_yaml, sing_dir, meta_dir)

    private_json, private_yaml = generate_files(
        "private", private_output, meta_dir, sing_dir
    )
    compile_rules("private", private_json, private_yaml, sing_dir, meta_dir)

    reject_json, reject_yaml = generate_files(
        "reject", reject_output, meta_dir, sing_dir
    )
    compile_rules("reject", reject_json, reject_yaml, sing_dir, meta_dir)

    print("Processing pollution IP...")
    pollution_upstream_ips = process_pollution_upstream()
    pollution_local_ips = set()
    if os.path.exists("rules/my-pollution-ip.list"):
        with open("rules/my-pollution-ip.list", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    pollution_local_ips.add(line)

    pollution_remove_ips = set()
    if os.path.exists("rules/my-pollution-ip-remove.list"):
        with open("rules/my-pollution-ip-remove.list", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    pollution_remove_ips.add(line)

    pollution_final_ips = (
        pollution_upstream_ips.union(pollution_local_ips) - pollution_remove_ips
    )
    pollution_output = simplify_ip_rules(pollution_final_ips)

    print("Processing reject IP...")

    reject_ip_upstream = hijacking_ips

    reject_ip_local = set()
    if os.path.exists("rules/my-reject-ip.list"):
        with open("rules/my-reject-ip.list", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    reject_ip_local.add(line)

    reject_ip_remove = set()
    if os.path.exists("rules/my-reject-ip-remove.list"):
        with open("rules/my-reject-ip-remove.list", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    reject_ip_remove.add(line)

    reject_ip_final = reject_ip_upstream.union(reject_ip_local) - reject_ip_remove
    reject_ip_output = simplify_ip_rules(reject_ip_final)

    ip_meta_dir = "dist/meta/ip"
    ip_sing_dir = "dist/sing/ip"

    pollution_json, pollution_yaml = generate_ip_files(
        "pollution", pollution_output, ip_meta_dir, ip_sing_dir
    )
    compile_ip_rules(
        "pollution", pollution_json, pollution_yaml, ip_sing_dir, ip_meta_dir
    )

    reject_ip_json, reject_ip_yaml = generate_ip_files(
        "reject", reject_ip_output, ip_meta_dir, ip_sing_dir
    )
    compile_ip_rules("reject", reject_ip_json, reject_ip_yaml, ip_sing_dir, ip_meta_dir)

    if os.path.exists("temp_geosite"):
        shutil.rmtree("temp_geosite")
    if os.path.exists("geosite.dat"):
        os.remove("geosite.dat")


if __name__ == "__main__":
    main()
