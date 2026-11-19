# -*- coding: utf-8 -*-
"""Геолокация exit-IP через https://2ip.io/ (основной) + запасные API.
Всё идёт ЧЕРЕЗ ТОТ ЖЕ прокси-сеанс, поэтому видим именно страну сервера."""
import re
from html import unescape

# code: (русское имя, английское имя, алиасы)
COUNTRIES = {
    "US": ("США", "United States", ["usa", "u.s.", "america", "united states of america"]),
    "CA": ("Канада", "Canada", []),
    "GB": ("Великобритания", "United Kingdom", ["uk", "u.k.", "great britain", "britain", "england"]),
    "DE": ("Германия", "Germany", ["deutschland"]),
    "NL": ("Нидерланды", "Netherlands", ["the netherlands", "holland"]),
    "FR": ("Франция", "France", []), "FI": ("Финляндия", "Finland", []),
    "SE": ("Швеция", "Sweden", []), "NO": ("Норвегия", "Norway", []),
    "DK": ("Дания", "Denmark", []), "IS": ("Исландия", "Iceland", []),
    "IE": ("Ирландия", "Ireland", []), "AT": ("Австрия", "Austria", []),
    "CH": ("Швейцария", "Switzerland", []), "BE": ("Бельгия", "Belgium", []),
    "LU": ("Люксембург", "Luxembourg", []), "ES": ("Испания", "Spain", []),
    "PT": ("Португалия", "Portugal", []), "IT": ("Италия", "Italy", []),
    "GR": ("Греция", "Greece", []), "PL": ("Польша", "Poland", []),
    "CZ": ("Чехия", "Czech Republic", ["czechia", "czech"]),
    "SK": ("Словакия", "Slovakia", ["slovak republic"]),
    "HU": ("Венгрия", "Hungary", []), "RO": ("Румыния", "Romania", []),
    "BG": ("Болгария", "Bulgaria", []), "RS": ("Сербия", "Serbia", []),
    "HR": ("Хорватия", "Croatia", []), "SI": ("Словения", "Slovenia", []),
    "BA": ("Босния и Герцеговина", "Bosnia and Herzegovina", ["bosnia"]),
    "MK": ("Северная Македония", "North Macedonia", ["macedonia"]),
    "AL": ("Албания", "Albania", []), "ME": ("Черногория", "Montenegro", []),
    "EE": ("Эстония", "Estonia", []), "LV": ("Латвия", "Latvia", []),
    "LT": ("Литва", "Lithuania", []), "UA": ("Украина", "Ukraine", []),
    "BY": ("Беларусь", "Belarus", ["byelorussia"]),
    "MD": ("Молдова", "Moldova", ["republic of moldova"]),
    "RU": ("Россия", "Russia", ["russian federation"]),
    "TR": ("Турция", "Turkey", ["türkiye", "turkiye"]),
    "GE": ("Грузия", "Georgia", []), "AM": ("Армения", "Armenia", []),
    "AZ": ("Азербайджан", "Azerbaijan", []), "KZ": ("Казахстан", "Kazakhstan", []),
    "UZ": ("Узбекистан", "Uzbekistan", []), "KG": ("Киргизия", "Kyrgyzstan", ["kyrgyz republic"]),
    "IL": ("Израиль", "Israel", []),
    "AE": ("ОАЭ", "United Arab Emirates", ["uae", "emirates"]),
    "SA": ("Саудовская Аравия", "Saudi Arabia", []), "QA": ("Катар", "Qatar", []),
    "BH": ("Бахрейн", "Bahrain", []), "OM": ("Оман", "Oman", []), "KW": ("Кувейт", "Kuwait", []),
    "JO": ("Иордания", "Jordan", []), "LB": ("Ливан", "Lebanon", []), "IQ": ("Ирак", "Iraq", []),
    "IR": ("Иран", "Iran", ["islamic republic of iran"]),
    "IN": ("Индия", "India", []), "PK": ("Пакистан", "Pakistan", []),
    "BD": ("Бангладеш", "Bangladesh", []), "LK": ("Шри-Ланка", "Sri Lanka", []),
    "NP": ("Непал", "Nepal", []), "CN": ("Китай", "China", []),
    "HK": ("Гонконг", "Hong Kong", ["hong kong sar"]),
    "TW": ("Тайвань", "Taiwan", ["taiwan, province of china"]),
    "JP": ("Япония", "Japan", []),
    "KR": ("Южная Корея", "South Korea", ["korea, republic of", "republic of korea", "korea"]),
    "SG": ("Сингапур", "Singapore", []), "MY": ("Малайзия", "Malaysia", []),
    "TH": ("Таиланд", "Thailand", []), "VN": ("Вьетнам", "Vietnam", ["viet nam"]),
    "ID": ("Индонезия", "Indonesia", []), "PH": ("Филиппины", "Philippines", []),
    "KH": ("Камбоджа", "Cambodia", []), "MM": ("Мьянма", "Myanmar", ["burma"]),
    "MN": ("Монголия", "Mongolia", []), "AU": ("Австралия", "Australia", []),
    "NZ": ("Новая Зеландия", "New Zealand", []), "ZA": ("ЮАР", "South Africa", []),
    "NG": ("Нигерия", "Nigeria", []), "NE": ("Нигер", "Niger", []),
    "KE": ("Кения", "Kenya", []), "EG": ("Египет", "Egypt", []),
    "MA": ("Марокко", "Morocco", []), "DZ": ("Алжир", "Algeria", []),
    "TN": ("Тунис", "Tunisia", []), "SC": ("Сейшелы", "Seychelles", []),
    "MU": ("Маврикий", "Mauritius", []), "BR": ("Бразилия", "Brazil", []),
    "AR": ("Аргентина", "Argentina", []), "CL": ("Чили", "Chile", []),
    "CO": ("Колумбия", "Colombia", []), "PE": ("Перу", "Peru", []),
    "VE": ("Венесуэла", "Venezuela", []), "EC": ("Эквадор", "Ecuador", []),
    "UY": ("Уругвай", "Uruguay", []), "PY": ("Парагвай", "Paraguay", []),
    "BO": ("Боливия", "Bolivia", []), "MX": ("Мексика", "Mexico", []),
    "CR": ("Коста-Рика", "Costa Rica", []), "PA": ("Панама", "Panama", []),
    "GT": ("Гватемала", "Guatemala", []),
    "DO": ("Доминикана", "Dominican Republic", ["dominican"]),
    "JM": ("Ямайка", "Jamaica", []), "CY": ("Кипр", "Cyprus", []),
    "MT": ("Мальта", "Malta", []), "LI": ("Лихтенштейн", "Liechtenstein", []),
    "MC": ("Монако", "Monaco", []), "AD": ("Андорра", "Andorra", []),
    "GI": ("Гибралтар", "Gibraltar", []), "FO": ("Фарерские острова", "Faroe Islands", []),
    "GL": ("Гренландия", "Greenland", []), "MO": ("Макао", "Macao", ["macau"]),
}

NAME2CODE = {}
for _cc, (_ru, _en, _al) in COUNTRIES.items():
    for _n in [_ru, _en] + _al:
        NAME2CODE[_n.lower()] = _cc


def flag(cc):
    if not cc or cc not in COUNTRIES:
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in cc.upper())


def ru_name(cc):
    return COUNTRIES.get(cc, (cc or "Unknown",))[0]


def en_name(cc):
    return COUNTRIES.get(cc, (None, cc or "Unknown"))[1]


def _norm(s):
    return re.sub(r"\s+", " ", s).strip(" .,;:")


def parse_2ip(html_text):
    """-> (country_code|None, city|None, ip|None)"""
    txt = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", html_text)
    txt = re.sub(r"(?s)<[^>]+>", "\n", txt)
    txt = unescape(txt)
    lines = [_norm(l) for l in txt.split("\n")]
    lines = [l for l in lines if l]

    ip = None
    m = re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", txt)
    if m:
        ip = m.group(0)

    for i, l in enumerate(lines):
        low = l.lower()
        if "you are from" in low or "вы из" in low or "ваше местоположение" in low:
            window = []
            if ":" in l:
                window.append(l.split(":", 1)[1])
            window += lines[i + 1:i + 8]
            for w in window:
                w = _norm(w.replace("Make it plain?", "").replace("Сделать обычным?", ""))
                if not w or len(w) > 80:
                    continue
                parts = [p.strip() for p in w.split(",")]
                code = NAME2CODE.get(parts[-1].lower())
                if code:
                    return code, (parts[0] if len(parts) > 1 else None), ip
                code = NAME2CODE.get(w.lower())
                if code:
                    return code, None, ip
            break

    m = re.search(r"(?:flags?|country)[/-]([a-z]{2})\.(?:svg|png|gif|webp)", html_text, re.I)
    if m and m.group(1).upper() in COUNTRIES:
        return m.group(1).upper(), None, ip
    m = re.search(r'data-country(?:-code)?="([a-zA-Z]{2})"', html_text)
    if m and m.group(1).upper() in COUNTRIES:
        return m.group(1).upper(), None, ip
    return None, None, ip


def _via_apis(session):
    try:
        r = session.get("http://ip-api.com/json/?fields=status,country,countryCode,city,query", timeout=10)
        j = r.json()
        if j.get("status") == "success":
            cc = (j.get("countryCode") or "").upper()
            if cc in COUNTRIES:
                return cc, j.get("city"), j.get("query")
            return NAME2CODE.get((j.get("country") or "").lower()), j.get("city"), j.get("query")
    except Exception:
        pass
    try:
        r = session.get("https://ipwho.is/?fields=success,country_code,country,city,ip", timeout=10)
        j = r.json()
        if j.get("success"):
            cc = (j.get("country_code") or "").upper()
            if cc in COUNTRIES:
                return cc, j.get("city"), j.get("ip")
            return NAME2CODE.get((j.get("country") or "").lower()), j.get("city"), j.get("ip")
    except Exception:
        pass
    return None, None, None


def detect_geo(session, geo_url, fallback=True):
    """-> (cc, city, ip, source). Сначала 2ip.io, потом запасные (если разрешено)."""
    try:
        r = session.get(geo_url, timeout=15)
        if r.status_code == 200:
            cc, city, ip = parse_2ip(r.text)
            if cc:
                return cc, city, ip, "2ip.io"
    except Exception:
        pass
    if fallback:
        cc, city, ip = _via_apis(session)
        if cc:
            return cc, city, ip, "fallback"
    return None, None, None, None
