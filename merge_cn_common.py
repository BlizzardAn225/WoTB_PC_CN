#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
merge_cn_common — 把 APK 原版国服 regions 的 Common/CN1 配置合并进下发的 yaml
================================================================================
免责声明 / Disclaimer: 仅供个人学习与研究使用,使用风险自负。

作用:PC 国际服 regions 的 Common 段缺少国服专属键(商店配置源、公告、活动、
CN 本地化、CN 资产 CDN 等),导致游戏内商店/公告/活动无数据。本脚本以
jadx 反编译产物里的 APK regions_publish.yaml 为准,把 CN 值合并进
下发给 PC 客户端的 regions yaml(不动 realm/flag,避免登录回归)。

用法:
  python merge_cn_common.py [--apk <APK反编译的regions_publish.yaml>] [--target <yaml>]...
默认:--apk 取脚本旁 ../app/src/main/assets/Data/regions_publish.yaml(不存在则报错)
      --targets 取 本机游戏 region_cache 最新 yaml + 脚本旁 regions.yaml
游戏版本更新后重跑一次即可。
"""
import yaml, shutil, os, sys, glob, argparse

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_APK_CANDIDATES = [
    os.path.normpath(os.path.join(SCRIPT_DIR, "..", "app", "src", "main", "assets", "Data", "regions_publish.yaml")),
    os.path.join(SCRIPT_DIR, "app_src_regions_publish.yaml"),
]
REGION_APPDATA_DIR = os.path.join(os.environ.get("LOCALAPPDATA", ""),
                                  "wotblitz", "DAVAProject", "region_cache")

def default_targets():
    t = []
    yamls = sorted(glob.glob(os.path.join(REGION_APPDATA_DIR, "regions_*.yaml")),
                   key=os.path.getmtime)
    if yamls:
        t.append(yamls[-1])
    bundle = os.path.join(SCRIPT_DIR, "regions.yaml")
    if os.path.exists(bundle) and bundle not in t:
        t.append(bundle)
    return t

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apk", default=None, help="APK 反编译的 regions_publish.yaml 路径")
    ap.add_argument("--target", action="append", default=[], help="要合并的 yaml(可多次)")
    args = ap.parse_args()

    apk_path = args.apk
    if not apk_path:
        for c in DEFAULT_APK_CANDIDATES:
            if os.path.exists(c):
                apk_path = c
                break
    if not apk_path or not os.path.exists(apk_path):
        print("[!] 未找到 APK regions_publish.yaml,请用 --apk 指定(jadx 反编译产物)")
        sys.exit(1)
    targets = args.target or default_targets()
    if not targets:
        print("[!] 未找到目标 yaml(先让游戏跑一次,或用 --target 指定)")
        sys.exit(1)

    apk = yaml.safe_load(open(apk_path, encoding="utf-8"))
    cn_common = apk["Common"]
    cn1_apk = apk["Regions"]["CN1"]
    print("APK:", apk_path)
    print("APK CN Common 键数:", len(cn_common))

    for t in targets:
        doc = yaml.safe_load(open(t, encoding="utf-8"))
        before = set(doc.get("Common", {}).keys())
        doc.setdefault("Common", {}).update(cn_common)
        cn1 = doc.setdefault("Regions", {}).setdefault("CN1", {})
        added_cn1 = [k for k in cn1_apk if k not in cn1]
        for k, v in cn1_apk.items():
            if k not in cn1:
                cn1[k] = v
        added_common = sorted(set(doc["Common"]) - before)
        shutil.copy(t, t + ".bak_common_merge")
        with open(t, "w", encoding="utf-8") as f:
            yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False, width=4096)
        print("[ok]", t)
        print("     Common 覆盖/新增 %d 键%s" % (len(added_common), (": " + ", ".join(added_common[:6]) + "...") if added_common else ""))
        print("     CN1 补键:", added_cn1)
        print("     校验: chinaStoresConfigBaseUrl =", doc["Common"].get("chinaStoresConfigBaseUrl"))
        print("            neteaseAnnouncementUrl =", doc["Common"].get("neteaseAnnouncementUrl"))
    print("\n完成。重启 regions 服务器后生效(realm/flag 未改动,避免登录回归)。")

if __name__ == "__main__":
    main()
