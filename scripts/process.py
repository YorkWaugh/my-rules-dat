import os
import re
import glob
import subprocess
import requests
import sys
import json

REJECT_SOURCES = [
    {
        "url": "https://filters.adtidy.org/extension/ublock/filters/224_optimized.txt",
        "regex": r"^\|\|([-_0-9a-zA-Z]+(\.[-_0-9a-zA-Z]+){1,64})\^",
    },
    {
        "url": "https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt",
        "regex": r"^\|\|([-_0-9a-zA-Z]+(\.[-_0-9a-zA-Z]+){1,64})\^$",
    },
    {
        "url": "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/AWAvenue-Ads-Rule.txt",
        "regex": r"^\|\|([-_0-9a-zA-Z]+(\.[-_0-9a-zA-Z]+){1,64})\^$",
    },
    {
        "url": "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts-online.txt",
        "regex": r"^0\.0\.0\.0\s([-_0-9a-zA-Z]+(\.[-_0-9a-zA-Z]+){1,64})",
    },
]


def download_file(url):
    try:
        print(f"Downloading: {url}")
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.text
    except Exception as e:
        print(f"Error downloading {url}: {e}")
        return ""


def process_reject_upstream():
    domains = set()
    for source in REJECT_SOURCES:
        url = source["url"]
        regex = source["regex"]
        content = download_file(url)
        if not content:
            continue

        count = 0
        for match in re.findall(regex, content, re.M):
            if isinstance(match, tuple):
                domains.add(match[0])
            else:
                domains.add(match)
            count += 1
        print(f"  -> Extracted {count} domains from {url}")
    return domains


def extract_cn_from_geosite():
    if not os.path.exists("geosite.dat"):
        print("geosite.dat not found!")
        return set(), []

    os.makedirs("temp_unpack", exist_ok=True)
    subprocess.run(
        ["./bin/geo", "unpack", "site", "geosite.dat", "-d", "temp_unpack"], check=True
    )

    cn_domains = set()
    cn_specials = []

    for filepath in glob.glob("temp_unpack/*"):
        filename = os.path.basename(filepath)
        if filename == "geosite_cn.txt" or filename == "cn.txt":
            continue

        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line.endswith("@cn"):
                    rule_body = line.rsplit("@cn", 1)[0].strip()
                    if (
                        rule_body.startswith("full:")
                        or rule_body.startswith("regexp:")
                        or rule_body.startswith("keyword:")
                    ):
                        cn_specials.append(rule_body)
                    elif rule_body.startswith("domain:"):
                        cn_domains.add(rule_body.replace("domain:", ""))
                    else:
                        cn_domains.add(rule_body)

    return cn_domains, cn_specials


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
                    specials.append(line)
                elif line.startswith("regexp:") or line.startswith("keyword:"):
                    specials.append(line)
                elif line.startswith("domain:"):
                    domains.add(line[7:])
                elif line.startswith("+."):
                    domains.add(line[2:])
                else:
                    domains.add(line)
    return domains, specials


def deduplicate_and_merge(name, domains, specials):
    print(f"Deduplicating {name}...")
    temp_unsorted = f"{name}_unsorted.txt"
    temp_with_redundant = f"{name}_redundant.txt"
    temp_clean = f"{name}_clean.txt"
    temp_deleted_sorted = f"{name}_deleted_sorted.txt"

    sorted_domains = sorted(list(domains))
    with open(temp_with_redundant, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted_domains))

    open(temp_unsorted, "w", encoding="utf-8").close()

    subprocess.run(
        [
            sys.executable,
            "scripts/findRedundantDomain.py",
            temp_with_redundant,
            temp_unsorted,
        ],
        check=True,
    )

    redundant_domains = []
    if os.path.exists(temp_unsorted):
        with open(temp_unsorted, "r", encoding="utf-8") as f:
            redundant_domains = [line.strip() for line in f if line.strip()]

    redundant_domains.sort()

    with open(temp_deleted_sorted, "w", encoding="utf-8") as f:
        f.write("\n".join(redundant_domains))

    subprocess.run(
        [
            sys.executable,
            "scripts/removeFrom.py",
            "-remove",
            temp_deleted_sorted,
            "-from",
            temp_with_redundant,
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

    for f in [temp_unsorted, temp_with_redundant, temp_clean, temp_deleted_sorted]:
        if os.path.exists(f):
            os.remove(f)

    return final_rules


def generate_files(name, rules, output_meta, output_sing):
    print(f"Generating files for {name}...")

    os.makedirs(output_meta, exist_ok=True)
    with open(os.path.join(output_meta, f"{name}.list"), "w", encoding="utf-8") as f:
        lines = []
        for r in rules:
            if r.startswith("regexp:") or r.startswith("keyword:"):
                continue

            if r.startswith("full:"):
                lines.append(r[5:])
            elif r.startswith("domain:"):
                lines.append("+." + r[7:])
            else:
                lines.append("+." + r)

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
            elif rule.startswith("keyword:"):
                f.write(f"  - DOMAIN-KEYWORD,{rule[8:]}\n")
            elif rule.startswith("regexp:"):
                f.write(f"  - DOMAIN-REGEX,{rule[7:]}\n")
            else:
                f.write(f"  - '+.{rule}'\n")

    os.makedirs(output_sing, exist_ok=True)
    srs_json = {
        "version": 1,
        "rules": [
            {
                "domain": [],
                "domain_suffix": [],
                "domain_keyword": [],
                "domain_regex": [],
            }
        ],
    }

    for rule in rules:
        if rule.startswith("domain:"):
            srs_json["rules"][0]["domain_suffix"].append(rule[7:])
        elif rule.startswith("full:"):
            srs_json["rules"][0]["domain"].append(rule[5:])
        elif rule.startswith("keyword:"):
            srs_json["rules"][0]["domain_keyword"].append(rule[8:])
        elif rule.startswith("regexp:"):
            srs_json["rules"][0]["domain_regex"].append(rule[7:])

    srs_json["rules"][0]["domain_suffix"].sort()
    srs_json["rules"][0]["domain"].sort()
    srs_json["rules"][0]["domain_keyword"].sort()
    srs_json["rules"][0]["domain_regex"].sort()

    json_path = os.path.join(output_sing, f"{name}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(srs_json, f, indent=2)

    return json_path, yaml_path


def compile_rules(name, json_path, yaml_path, sing_dir, meta_dir):
    print(f"Compiling Sing-box rules for {name}...")
    srs_path = os.path.join(sing_dir, f"{name}.srs")
    subprocess.run(
        ["./bin/sing-box", "rule-set", "compile", json_path, "-o", srs_path], check=True
    )

    print(f"Compiling Mihomo rules for {name}...")
    mrs_path = os.path.join(meta_dir, f"{name}.mrs")
    subprocess.run(
        ["./bin/mihomo", "convert-ruleset", "domain", "yaml", yaml_path, mrs_path],
        check=True,
    )


def main():
    print(">>> Processing CN rules...")
    cn_repo_domains, cn_repo_specials = extract_cn_from_geosite()
    cn_local_domains, cn_local_specials = read_local_list("rules/my-cn.list")

    final_cn = deduplicate_and_merge(
        "geolocation-cn",
        cn_repo_domains.union(cn_local_domains),
        cn_repo_specials + cn_local_specials,
    )

    print("\n>>> Processing Reject rules...")
    reject_repo_domains = process_reject_upstream()
    reject_local_domains, reject_local_specials = read_local_list(
        "rules/my-reject.list"
    )
    final_reject = deduplicate_and_merge(
        "reject", reject_repo_domains.union(reject_local_domains), reject_local_specials
    )

    meta_dir = "dist/meta/site"
    sing_dir = "dist/sing/site"

    print("\n>>> Writing output files...")
    cn_json, cn_yaml = generate_files("geolocation-cn", final_cn, meta_dir, sing_dir)
    reject_json, reject_yaml = generate_files(
        "reject", final_reject, meta_dir, sing_dir
    )

    print("\n>>> Compiling binary rules...")
    compile_rules("geolocation-cn", cn_json, cn_yaml, sing_dir, meta_dir)
    compile_rules("reject", reject_json, reject_yaml, sing_dir, meta_dir)

    print("\n>>> All done!")


if __name__ == "__main__":
    main()
