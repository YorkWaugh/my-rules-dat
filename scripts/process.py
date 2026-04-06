import os
import re
import glob
import subprocess
import requests
import sys
import json
import ipaddress
import shutil


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

    if any(tag in line for tag in ["##", "#@#", "#?#", "#$#"]):
        return None, False

    if "$" in line:
        modifier_part = line.split("$", 1)[1].lower()
        mods = [
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
        if any(mod in modifier_part for mod in mods):
            return None, False

    domain = ""
    if line.startswith("||") and "^" in line:
        caret_pos = line.index("^")
        domain = line[2:caret_pos]
        remainder = line[caret_pos + 1 :]
        if "$" in remainder:
            remainder = remainder.split("$")[0]
        if remainder or "/" in domain:
            return None, False
    elif line.startswith("|http://") or line.startswith("|https://"):
        line = line[1:]
        if "://" in line:
            line = line.split("://", 1)[1]
        if "/" in line:
            return None, False
        domain = line.split("^")[0] if "^" in line else line
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
    if not domain or "." not in domain or is_ip_address(domain):
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
        if domain not in ["localhost", "localhost.localdomain"] and not is_ip_address(
            domain
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


def parse_clash_list(content):
    domains, ips = set(), set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(",")
        if len(parts) < 2:
            continue
        type_, value = parts[0].strip().upper(), parts[1].strip()
        if type_ in ["DOMAIN", "DOMAIN-SUFFIX"]:
            domains.add(value)
        elif type_ in ["IP-CIDR", "IP-CIDR6"]:
            try:
                ipaddress.ip_network(value, strict=False)
                ips.add(value)
            except ValueError:
                pass
    return domains, ips


def extract_geocn_from_geosite(base_dir):
    if not os.path.exists(base_dir):
        return set(), []
    domains, specials = set(), []
    for filepath in glob.glob(os.path.join(base_dir, "*")):
        filename = os.path.basename(filepath)
        if filename in ["cn", "geolocation-cn"] or any(
            x in filename for x in ["category", "google", "apple"]
        ):
            continue
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.endswith("@cn"):
                    rule_body = line.rsplit("@cn", 1)[0].strip()
                    if rule_body.startswith("full:"):
                        specials.append(rule_body)
                    elif rule_body.startswith("domain:"):
                        domain = rule_body.replace("domain:", "")
                        if not domain.endswith(".cn"):
                            domains.add(domain)
    return domains, specials


def extract_tagged_domains(base_dir, tag):
    if not os.path.exists(base_dir):
        return set(), []
    domains, specials = set(), []
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
                        specials.append(rule_body)
                    elif rule_body.startswith("domain:"):
                        domains.add(rule_body[7:])
                    elif ":" not in rule_body:
                        domains.add(rule_body)
    return domains, specials


def read_upstream_list(filename, base_dir):
    path = os.path.join(base_dir, filename)
    domains, specials = set(), []
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
    domains, specials = set(), []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith("full:") and not is_ip_address(line[5:]):
                    specials.append(line)
                elif line.startswith("domain:") and not is_ip_address(line[7:]):
                    domains.add(line[7:])
    return domains, specials


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

    final_rules.extend(sorted(list(set(specials))))
    final_rules.sort()

    for f in [temp_unsorted, temp_redundant, temp_clean, temp_deleted]:
        if os.path.exists(f):
            os.remove(f)

    return final_rules


def simplify_ip_rules(ip_set):
    ipv4_nets, ipv6_nets = [], []
    for ip_str in ip_set:
        try:
            net = ipaddress.ip_network(ip_str, strict=False)
            if net.version == 4:
                ipv4_nets.append(net)
            else:
                ipv6_nets.append(net)
        except ValueError:
            continue

    return [str(n) for n in ipaddress.collapse_addresses(ipv4_nets)] + [
        str(n) for n in ipaddress.collapse_addresses(ipv6_nets)
    ]


def generate_files(name, rules, output_meta, output_sing):
    os.makedirs(output_meta, exist_ok=True)
    os.makedirs(output_sing, exist_ok=True)

    with open(os.path.join(output_meta, f"{name}.list"), "w", encoding="utf-8") as f:
        lines = [
            (
                r[5:]
                if r.startswith("full:")
                else "+." + r[7:] if r.startswith("domain:") else r
            )
            for r in rules
        ]
        f.write("\n".join(sorted(lines)))

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


def process_domain_rules(name, upstream_domains, upstream_specials, meta_dir, sing_dir):
    local_domains, local_specials = read_local_list(f"rules/my-{name}.list")
    remove_domains, remove_specials = read_local_list(f"rules/my-{name}-remove.list")

    upstream_domains, upstream_specials = apply_removal_and_clean_specials(
        upstream_domains, upstream_specials, remove_domains, remove_specials
    )

    final_raw = deduplicate_and_merge(
        name,
        upstream_domains.union(local_domains),
        upstream_specials + local_specials,
    )

    final_d = {rule[7:] for rule in final_raw if rule.startswith("domain:")}
    final_f = {rule[5:] for rule in final_raw if rule.startswith("full:")}
    final_f = clean_full_from_domains(final_f, final_d)

    output = [f"domain:{d}" for d in sorted(final_d)] + [
        f"full:{f}" for f in sorted(final_f)
    ]

    json_path, yaml_path = generate_files(name, output, meta_dir, sing_dir)
    compile_rules(name, json_path, yaml_path, sing_dir, meta_dir)


def process_ip_rules(output_name, local_file_suffix, upstream_ips, meta_dir, sing_dir):
    local_ips, remove_ips = set(), set()

    local_file = f"rules/my-{local_file_suffix}.list"
    if os.path.exists(local_file):
        with open(local_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.strip().startswith("#"):
                    local_ips.add(line.strip())

    remove_file = f"rules/my-{local_file_suffix}-remove.list"
    if os.path.exists(remove_file):
        with open(remove_file, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() and not line.strip().startswith("#"):
                    remove_ips.add(line.strip())

    final_ips = upstream_ips.union(local_ips) - remove_ips
    output = simplify_ip_rules(final_ips)

    json_path, yaml_path = generate_ip_files(output_name, output, meta_dir, sing_dir)
    compile_ip_rules(output_name, json_path, yaml_path, sing_dir, meta_dir)


def build_geolocation_cn(geosite_dir, meta_dir, sing_dir):
    print("Building geolocation-cn...")

    UPSTREAM_APPLE = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/apple.china.conf"
    # UPSTREAM_GOOGLE = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/google.china.conf"

    domains, specials = extract_geocn_from_geosite(geosite_dir)
    content = download_file(UPSTREAM_APPLE)
    if content:
        for line in content.splitlines():
            d = parse_dnsmasq_rule(line)
            if d:
                domains.add(d)
    # content = download_file(UPSTREAM_GOOGLE)
    # if content:
    #     for line in content.splitlines():
    #         d = parse_dnsmasq_rule(line)
    #         if d:
    #             domains.add(d)

    process_domain_rules("geolocation-cn", domains, specials, meta_dir, sing_dir)


def build_cn(meta_dir, sing_dir):
    print("Building cn...")

    UPSTREAM_DNSMASQ = "https://raw.githubusercontent.com/felixonmars/dnsmasq-china-list/master/accelerated-domains.china.conf"
    UPSTREAM_PUNYCODE = [
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

    domains = {"cn"}
    domains.update(UPSTREAM_PUNYCODE)
    specials = []

    content = download_file(UPSTREAM_DNSMASQ)
    if content:
        for line in content.splitlines():
            d = parse_dnsmasq_rule(line)
            if d:
                domains.add(d)

    process_domain_rules("cn", domains, specials, meta_dir, sing_dir)


def build_geolocation_not_cn(geosite_dir, meta_dir, sing_dir):
    print("Building geolocation-!cn...")

    domains, specials = read_upstream_list("geolocation-!cn", geosite_dir)
    extra_domains, extra_specials = extract_tagged_domains(geosite_dir, "!cn")
    domains.update(extra_domains)
    specials.extend(extra_specials)

    process_domain_rules("geolocation-!cn", domains, specials, meta_dir, sing_dir)


def build_private(geosite_dir, meta_dir, sing_dir):
    print("Building private...")

    domains, specials = read_upstream_list("private", geosite_dir)
    process_domain_rules("private", domains, specials, meta_dir, sing_dir)


def build_reject_and_ip(meta_dir, sing_dir, ip_meta_dir, ip_sing_dir):
    print("Building reject and reject-ip...")

    UPSTREAM_ADBLOCK = [
        "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "https://ublockorigin.github.io/uAssetsCDN/filters/filters.min.txt",
        "https://filters.adtidy.org/extension/ublock/filters/224_optimized.txt",
        "https://easylist-downloads.adblockplus.org/easylistchina+easylist.txt",
        "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "https://ublockorigin.github.io/uAssetsCDN/filters//badware.min.txt",
    ]
    UPSTREAM_HOSTS = [
        "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
        "https://someonewhocares.org/hosts/hosts",
        "https://malware-filter.gitlab.io/malware-filter/phishing-filter-hosts.txt",
        "https://a.dove.isdumb.one/list.txt",
    ]
    UPSTREAM_HIJACKING = "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Hijacking/Hijacking.list"

    reject_domains, reject_specials = set(), []

    for url in UPSTREAM_ADBLOCK:
        content = download_file(url)
        if not content:
            continue
        s_black, s_white = set(), set()
        for line in content.splitlines():
            domain, is_white = parse_adblock_rule(line)
            if domain:
                if is_white:
                    s_white.add(domain)
                else:
                    s_black.add(domain)
        s_black = remove_with_subdomains(s_black, s_white)
        reject_domains.update(s_black)

    for url in UPSTREAM_HOSTS:
        content = download_file(url)
        if not content:
            continue
        s_full = set()
        for line in content.splitlines():
            domain = parse_hosts_rule(line)
            if domain:
                s_full.add(domain)
        reject_specials.extend([f"full:{d}" for d in s_full])

    hijacking_domains, hijacking_ips = set(), set()
    hijacking_content = download_file(UPSTREAM_HIJACKING)
    if hijacking_content:
        hijacking_domains, hijacking_ips = parse_clash_list(hijacking_content)
    reject_domains.update(hijacking_domains)

    process_domain_rules("reject", reject_domains, reject_specials, meta_dir, sing_dir)
    process_ip_rules("reject", "reject-ip", hijacking_ips, ip_meta_dir, ip_sing_dir)


def build_pollution_ip(meta_dir, sing_dir):
    print("Building pollution-ip...")

    UPSTREAM_GFW_IP = (
        "https://raw.githubusercontent.com/pmkol/easymosdns/main/rules/gfw_ip_list.txt"
    )

    upstream_ips = set()
    content = download_file(UPSTREAM_GFW_IP)
    if content:
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                ipaddress.ip_network(line, strict=False)
                upstream_ips.add(line)
            except ValueError:
                pass

    process_ip_rules("pollution", "pollution-ip", upstream_ips, meta_dir, sing_dir)


def main():
    GEOSITE_URL = "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"
    print("Downloading and unpacking geosite.dat...")

    download_file(GEOSITE_URL, "geosite.dat")
    unpack_geosite("geosite.dat", "temp_geosite")

    DOMAIN_META_DIR, DOMAIN_SING_DIR = "dist/meta/site", "dist/sing/site"
    IP_META_DIR, IP_SING_DIR = "dist/meta/ip", "dist/sing/ip"

    build_geolocation_cn("temp_geosite", DOMAIN_META_DIR, DOMAIN_SING_DIR)
    build_cn(DOMAIN_META_DIR, DOMAIN_SING_DIR)
    build_geolocation_not_cn("temp_geosite", DOMAIN_META_DIR, DOMAIN_SING_DIR)
    build_private("temp_geosite", DOMAIN_META_DIR, DOMAIN_SING_DIR)
    build_reject_and_ip(DOMAIN_META_DIR, DOMAIN_SING_DIR, IP_META_DIR, IP_SING_DIR)
    build_pollution_ip(IP_META_DIR, IP_SING_DIR)

    if os.path.exists("temp_geosite"):
        shutil.rmtree("temp_geosite")
    if os.path.exists("geosite.dat"):
        os.remove("geosite.dat")


if __name__ == "__main__":
    main()
