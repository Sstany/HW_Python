import json
import os
import sys

import requests

API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")
BASE_URL = "https://api.abuseipdb.com/api/v2"
HEADERS = {
    "Key": API_KEY,
    "Accept": "application/json",
}

# Категории угроз AbuseIPDB
ABUSE_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}


def check_ip(ip_address: str, max_age_days: int = 90) -> dict:
    """Проверить репутацию IP-адреса."""
    url = f"{BASE_URL}/check"
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": max_age_days,
    }
    response = requests.get(url, headers=HEADERS, params=params)
    response.raise_for_status()
    return response.json()


def get_blacklist(confidence_minimum: int = 90, limit: int = 10) -> dict:
    """Получить список заблокированных IP (правила фильтрации)."""
    url = f"{BASE_URL}/blacklist"
    params = {
        "confidenceMinimum": confidence_minimum,
        "limit": limit,
    }
    response = requests.get(url, headers=HEADERS, params=params)
    response.raise_for_status()
    return response.json()


def print_ip_report(report: dict) -> None:
    """Вывести отчёт о проверке IP-адреса."""
    data = report.get("data", {})

    print("=" * 60)
    print("Отчёт AbuseIPDB")
    print("=" * 60)
    print(f"  IP-адрес:          {data.get('ipAddress', 'N/A')}")
    print(f"  Публичный:         {'Да' if data.get('isPublic') else 'Нет'}")
    print(f"  Версия IP:         {data.get('ipVersion', 'N/A')}")
    print(f"  Белый список:      {'Да' if data.get('isWhitelisted') else 'Нет'}")
    print(f"  Оценка угрозы:     {data.get('abuseConfidenceScore', 'N/A')}%")
    print(f"  Страна:            {data.get('countryCode', 'N/A')}")
    print(f"  Провайдер (ISP):   {data.get('isp', 'N/A')}")
    print(f"  Домен:             {data.get('domain', 'N/A')}")
    print(f"  Всего жалоб:       {data.get('totalReports', 'N/A')}")
    print(f"  Последняя жалоба:  {data.get('lastReportedAt', 'Нет жалоб')}")

    categories = data.get("reports", [])
    if categories:
        all_cats = set()
        for r in categories:
            all_cats.update(r.get("categories", []))
        if all_cats:
            print("\n  Категории угроз:")
            for cat_id in sorted(all_cats):
                name = ABUSE_CATEGORIES.get(cat_id, f"Unknown ({cat_id})")
                print(f"    - {name}")

    print("=" * 60)
    print("\nПолный JSON-ответ:")
    print(json.dumps(report, indent=2, ensure_ascii=False))


def print_blacklist(blacklist: dict) -> None:
    """Вывести правила фильтрации (чёрный список IP)."""
    data = blacklist.get("data", [])

    print("=" * 60)
    print("Правила фильтрации (чёрный список)")
    print("=" * 60)
    for entry in data:
        ip = entry.get("ipAddress", "N/A")
        score = entry.get("abuseConfidenceScore", "N/A")
        print(f"  BLOCK  {ip:<20s}  (угроза: {score}%)")
    print("=" * 60)
    print(f"  Всего правил: {len(data)}")

    print("\nПолный JSON-ответ:")
    print(json.dumps(blacklist, indent=2, ensure_ascii=False))


def main():
    if not API_KEY:
        print("Ошибка: не задана переменная окружения ABUSEIPDB_API_KEY.")
        print('Установите её командой: export ABUSEIPDB_API_KEY="ваш_ключ"')
        sys.exit(1)

    ip_address = sys.argv[1] if len(sys.argv) > 1 else "118.25.6.39"
    print(f"Проверка IP-адреса: {ip_address}\n")

    try:
        report = check_ip(ip_address)
        print_ip_report(report)

        print("\n")
        print("Запрос чёрного списка (топ-10 опасных IP)...\n")
        blacklist = get_blacklist(confidence_minimum=100, limit=10)
        print_blacklist(blacklist)

    except requests.exceptions.HTTPError as e:
        print(f"HTTP ошибка: {e}")
        print(f"Ответ сервера: {e.response.text}")
    except requests.exceptions.ConnectionError:
        print("Ошибка подключения к AbuseIPDB API.")


if __name__ == "__main__":
    main()