import json
import os
from datetime import datetime
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import requests

SCRIPT_DIR = Path(__file__).parent

BUILTIN_CVE_DATA = [
    {"cve_id": "CVE-2025-21298", "description": "Windows OLE RCE via Outlook Preview", "cvss_score": 9.8, "product": "windows"},
    {"cve_id": "CVE-2025-0282", "description": "Ivanti Connect Secure Stack Buffer Overflow", "cvss_score": 9.0, "product": "ivanti"},
    {"cve_id": "CVE-2024-47575", "description": "FortiManager Missing Authentication (FortiJump)", "cvss_score": 9.8, "product": "fortinet"},
    {"cve_id": "CVE-2024-55591", "description": "FortiOS Authentication Bypass via WebSocket", "cvss_score": 9.6, "product": "fortinet"},
    {"cve_id": "CVE-2024-50623", "description": "Cleo Harmony/VLTrader Unrestricted File Upload", "cvss_score": 8.8, "product": "cleo"},
    {"cve_id": "CVE-2025-24472", "description": "FortiOS CSF Proxy Auth Bypass", "cvss_score": 8.1, "product": "fortinet"},
    {"cve_id": "CVE-2024-49113", "description": "Windows LDAP Client DoS (LDAPNightmare)", "cvss_score": 7.5, "product": "windows"},
    {"cve_id": "CVE-2025-22224", "description": "VMware ESXi TOCTOU RCE", "cvss_score": 9.3, "product": "vmware"},
    {"cve_id": "CVE-2025-23006", "description": "SonicWall SMA1000 Deserialization RCE", "cvss_score": 9.8, "product": "sonicwall"},
    {"cve_id": "CVE-2024-53677", "description": "Apache Struts Path Traversal File Upload", "cvss_score": 9.5, "product": "apache"},
    {"cve_id": "CVE-2025-0411", "description": "7-Zip Mark-of-the-Web Bypass", "cvss_score": 7.0, "product": "7zip"},
    {"cve_id": "CVE-2024-12356", "description": "BeyondTrust PRA Command Injection", "cvss_score": 9.8, "product": "beyondtrust"},
]

PRODUCTS_TO_QUERY = ["fortinet", "vmware", "windows", "apache"]

def parse_suricata_events(filepath: Path) -> pd.DataFrame:
    with open(filepath, encoding="utf-8") as fh:
        raw = json.load(fh)

    records = []
    for evt in raw:
        alert = evt["alert"]
        records.append({
            "ts": evt["timestamp"],
            "src": evt["src_ip"],
            "dst": evt["dest_ip"],
            "sig": alert["signature"],
            "sev": alert["severity"],
            "cat": alert.get("category", "Unknown"),
            "proto": evt["proto"],
            "dport": evt["dest_port"],
        })
    df = pd.DataFrame(records)
    df["ts"] = pd.to_datetime(df["ts"])
    return df


def query_vulners_api(products: list[str]) -> list[dict]:
    api_key = os.environ.get("VULNERS_API_KEY")
    if not api_key:
        print("[INFO] VULNERS_API_KEY не установлен — берём встроенные CVE-данные")
        return BUILTIN_CVE_DATA

    collected = []
    for prod in products:
        try:
            resp = requests.get(
                "https://vulners.com/api/v3/burp/software/",
                params={"software": prod, "version": "any", "type": "cpe", "apiKey": api_key},
                timeout=10,
            )
            resp.raise_for_status()
            body = resp.json()
            if body.get("result") != "OK":
                continue
            for hit in body.get("data", {}).get("search", []):
                src = hit.get("_source", {})
                collected.append({
                    "cve_id": src.get("id", "N/A"),
                    "description": src.get("title", "N/A"),
                    "cvss_score": src.get("cvss", {}).get("score", 0.0),
                    "product": prod,
                })
        except Exception as err:
            print(f"[WARN] Vulners ошибка для {prod}: {err}")

    if not collected:
        print("[INFO] API не вернул данных — используем встроенные CVE")
        return BUILTIN_CVE_DATA
    return collected

def compute_alert_stats(df: pd.DataFrame) -> dict:
    by_src = (
        df.groupby("src")
        .size()
        .reset_index(name="total_alerts")
        .sort_values("total_alerts", ascending=False)
    )
    by_cat = (
        df.groupby("cat")
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    by_sev = (
        df.groupby("sev")
        .size()
        .reset_index(name="count")
    )
    flagged_ips = by_src[by_src["total_alerts"] >= 4].copy()
    return {
        "by_src": by_src,
        "by_cat": by_cat,
        "by_sev": by_sev,
        "flagged_ips": flagged_ips,
    }


def get_critical_cves(cve_list: list[dict], threshold: float = 7.0) -> pd.DataFrame:
    df = pd.DataFrame(cve_list)
    return df[df["cvss_score"] >= threshold].sort_values("cvss_score", ascending=False).reset_index(drop=True)

def simulate_incident_response(flagged_ips: pd.DataFrame, critical_cves: pd.DataFrame) -> list[dict]:
    actions = []

    print("\n" + "=" * 65)
    print("  INCIDENT RESPONSE — Реагирование на инциденты")
    print("=" * 65)

    for _, row in flagged_ips.iterrows():
        ip = row["src"]
        cnt = row["total_alerts"]
        rule = f"ufw deny from {ip} to any"
        print(f"  [FIREWALL] Блокируем {ip} ({cnt} алертов) -> {rule}")
        actions.append({"action": "firewall_block", "target_ip": ip, "alert_count": cnt, "rule": rule})

    urgent = critical_cves[critical_cves["cvss_score"] >= 9.0]
    for _, row in urgent.iterrows():
        notice = f"URGENT: {row['cve_id']} (CVSS {row['cvss_score']}) — {row['description']}"
        print(f"  [EMAIL] Уведомление SOC-команде: {notice}")
        actions.append({"action": "email_soc", "cve": row["cve_id"], "notice": notice})

    print(f"\n  Всего ответных действий: {len(actions)}")
    return actions

def create_dashboard(stats: dict, critical_cves: pd.DataFrame, output_path: Path) -> None:
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle("Security Monitoring Dashboard", fontsize=15, fontweight="bold")

    cat_df = stats["by_cat"]
    colors = plt.cm.Set2(range(len(cat_df)))
    axes[0, 0].pie(
        cat_df["count"], labels=cat_df["cat"], autopct="%1.0f%%",
        colors=colors, startangle=140, textprops={"fontsize": 8},
    )
    axes[0, 0].set_title("Алерты по категориям")

    if not critical_cves.empty:
        products = critical_cves["product"].astype("category")
        scatter = axes[0, 1].scatter(
            products.cat.codes, critical_cves["cvss_score"],
            c=critical_cves["cvss_score"], cmap="RdYlGn_r", s=120, edgecolors="black", linewidths=0.5,
        )
        axes[0, 1].set_xticks(range(len(products.cat.categories)))
        axes[0, 1].set_xticklabels(products.cat.categories, rotation=30, fontsize=8)
        axes[0, 1].set_ylabel("CVSS")
        axes[0, 1].set_ylim(6, 10.5)
        axes[0, 1].axhline(y=9.0, color="red", linestyle="--", alpha=0.6, label="Critical (9.0)")
        axes[0, 1].legend(fontsize=8)
        fig.colorbar(scatter, ax=axes[0, 1], label="CVSS")
    else:
        axes[0, 1].text(0.5, 0.5, "Нет данных", ha="center", va="center")
    axes[0, 1].set_title("CVSS уязвимостей по продуктам")

    sev_df = stats["by_sev"]
    sev_labels = {1: "High", 2: "Medium", 3: "Low"}
    sev_colors = {1: "#e74c3c", 2: "#f39c12", 3: "#2ecc71"}
    bar_labels = [sev_labels.get(s, str(s)) for s in sev_df["sev"]]
    bar_colors = [sev_colors.get(s, "#95a5a6") for s in sev_df["sev"]]
    axes[1, 0].barh(bar_labels, sev_df["count"], color=bar_colors, edgecolor="black", linewidth=0.5)
    axes[1, 0].set_xlabel("Количество")
    axes[1, 0].set_title("Алерты по уровню severity")

    top_ips = stats["by_src"].head(6)
    axes[1, 1].bar(top_ips["src"], top_ips["total_alerts"], color="#3498db", edgecolor="black", linewidth=0.5)
    axes[1, 1].set_ylabel("Алерты")
    axes[1, 1].set_title("Топ-6 IP-адресов")
    axes[1, 1].tick_params(axis="x", rotation=25, labelsize=8)

    fig.tight_layout(rect=[0, 0, 1, 0.95])
    fig.savefig(output_path, dpi=150)
    plt.close(fig)
    print(f"  [OK] Dashboard сохранён: {output_path}")


def export_report(stats: dict, critical_cves: pd.DataFrame, actions: list[dict]) -> None:
    report = {
        "generated_at": datetime.now().isoformat(),
        "flagged_ips": stats["flagged_ips"].to_dict(orient="records"),
        "alert_categories": stats["by_cat"].to_dict(orient="records"),
        "critical_cves": critical_cves.to_dict(orient="records"),
        "response_actions": actions,
    }
    json_path = SCRIPT_DIR / "security_report.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2, default=str)
    print(f"  [OK] JSON-отчёт: {json_path}")

    rows = []
    for _, r in stats["flagged_ips"].iterrows():
        rows.append({"type": "flagged_ip", "identifier": r["src"], "value": r["total_alerts"], "detail": "alert count"})
    for _, r in critical_cves.iterrows():
        rows.append({"type": "critical_cve", "identifier": r["cve_id"], "value": r["cvss_score"], "detail": r["description"]})
    csv_path = SCRIPT_DIR / "security_report.csv"
    pd.DataFrame(rows).to_csv(csv_path, index=False, encoding="utf-8-sig")
    print(f"  [OK] CSV-отчёт:  {csv_path}")


def run_pipeline() -> None:
    print("=" * 65)
    print("  SECURITY MONITOR — Анализ угроз сетевой безопасности")
    print("=" * 65)

    log_file = SCRIPT_DIR / "suricata_events.json"
    events_df = parse_suricata_events(log_file)
    print(f"\n  [STEP 1] Загружено {len(events_df)} событий из Suricata")

    cve_data = query_vulners_api(PRODUCTS_TO_QUERY)
    print(f"  [STEP 1] Получено {len(cve_data)} записей об уязвимостях")

    stats = compute_alert_stats(events_df)
    critical_cves = get_critical_cves(cve_data)
    print(f"\n  [STEP 2] Уникальных IP-источников: {len(stats['by_src'])}")
    print(f"  [STEP 2] Помечено подозрительных IP (>=4 алертов): {len(stats['flagged_ips'])}")
    print(f"  [STEP 2] CVE с CVSS >= 7.0: {len(critical_cves)}")

    if not stats["flagged_ips"].empty:
        print("\n  Подозрительные IP:")
        print(stats["flagged_ips"].to_string(index=False))

    if not critical_cves.empty:
        print("\n  Критические уязвимости:")
        print(critical_cves[["cve_id", "description", "cvss_score"]].to_string(index=False))

    actions = simulate_incident_response(stats["flagged_ips"], critical_cves)

    print("\n" + "=" * 65)
    print("  ФОРМИРОВАНИЕ ОТЧЁТА")
    print("=" * 65)
    create_dashboard(stats, critical_cves, SCRIPT_DIR / "dashboard.png")
    export_report(stats, critical_cves, actions)

    print("\n" + "=" * 65)
    print("  МОНИТОРИНГ ЗАВЕРШЁН")
    print("=" * 65)


if __name__ == "__main__":
    run_pipeline()
