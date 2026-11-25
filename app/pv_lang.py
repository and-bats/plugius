# -*- coding: utf-8 -*-
"""Англійська для текстів сервера. База лишається українською: збережені фрази перекладаються при видачі в API.
Ручні поля й назви сюди не потрапляють ніколи."""
import re
from urllib.parse import parse_qs

LANGS = ("uk", "en")

# Точні фрази: те, що скан пише в базу, і повідомлення API
EN = {
    # платформа й архітектура
    "Невідомо": "Unknown",
    "Універсально (LV2)": "Universal (LV2)",
    "Лише Intel (на M-чипах — через Rosetta)": "Intel only (Rosetta on Apple Silicon)",
    # категорії AU і опис
    "Інструмент": "Instrument", "Ефект": "Effect", "Ефект з MIDI-входом": "Effect with MIDI input",
    "MIDI-процесор": "MIDI processor", "Генератор": "Generator", "Конвертер": "Converter",
    "Мікшер": "Mixer", "Вивід": "Output", "Панорамер": "Panner", "Аудіоплагін": "Audio plugin",
    # звідки взято виробника
    "AU-метадані": "AU metadata", "ID пакета (припущення)": "bundle ID (guess)",
    "тека (припущення)": "folder (guess)", "ID інсталятора (припущення)": "installer ID (guess)",
    # дата встановлення
    "дата створення файлу": "file creation date", "дата зміни файлу": "file modification date",
    "дата встановлення пакета (pkgutil)": "package install date (pkgutil)",
    "журнал встановлень macOS": "macOS install log", "дата появи в теці (Spotlight)": "date added to folder (Spotlight)",
    # штатні
    "Виробник AU: Apple": "AU manufacturer: Apple", "Штатний плагін Pro Tools (за назвою)": "Pro Tools stock plugin (by name)",
    # історія змін
    "версія невідома": "version unknown", "знову з'явився": "reappeared", "файл більше не існує": "file no longer exists",
    # ліцензія, знайдена лише за назвою файлу
    "Схожий файл": "Similar file",
    "Назва схожа на ліцензію, але вміст не перевірявся": "The name looks like a license, but the contents were not checked",
    # скан
    "Пошук": "Searching", "Аналіз": "Analyzing", "Збереження": "Saving",
    "Сканування вже триває": "A scan is already running",
    # API
    "потрібен application/json": "application/json required", "некоректний JSON": "invalid JSON",
    "невідомий режим": "unknown mode", "не знайдено": "not found",
    "Показ у Finder працює лише на macOS": "Show in Finder works only on macOS",
    "Розклад (launchd) доступний лише на macOS": "Scheduling (launchd) is available only on macOS",
    "Plugius запущено з тимчасової копії, тож автоскан зламається після перезапуску Mac. "
    "Перемістіть Plugius.app у Програми, відкрийте звідти й увімкніть автоскан знову.":
        "Plugius is running from a temporary copy, so the weekly scan would break after the Mac restarts. "
        "Move Plugius.app to Applications, open it from there and turn the weekly scan on again.",
}

# Фрази зі вставками: (шаблон, англійською). Вставки \1, \2 не перекладаються, крім позначених у TR_GROUPS
PATTERNS = [(re.compile(p, re.S), en) for p, en in (
    (r"Імовірно: інсталятор «(.+)» у Downloads \(URL невідомий\)", r"Probably: installer “\1” in Downloads (URL unknown)"),
    (r"Імовірно: (.+) \(з інсталятора «(.+)»\)", r"Probably: \1 (from installer “\2”)"),
    (r"Імовірно: (.+)", r"Probably: \1"),
    (r"Встановлено пакетом (.+)", r"Installed by package \1"),
    (r"Застарілий \((.+)\) — не працює на сучасному macOS", r"Legacy (\1) — does not run on modern macOS"),
    (r"ID пакета починається з (.+)", r"Bundle ID starts with \1"),
    (r"Системний шлях (.+)", r"System path \1"),
    (r"Виробник: (.+)", r"Vendor: \1"),
    (r"версія (.+)", r"version \1"),
    (r"з (/.+)", r"from \1"),
    (r"Немає доступу: (.+)", r"No access: \1"),
)]
# «Ефект (AU)»: категорія перекладається, формат лишається
_WITH_FORMAT = re.compile(r"(.+) \((\S+)\)")
SEP = " · "


def lang_of(query):
    """Мова із рядка запиту (?lang=en). Будь-що інше означає українську."""
    v = (parse_qs(query or "").get("lang") or [""])[0]
    return v if v in LANGS else "uk"


def _words(s):
    """Точна фраза або перелік точних фраз через кому («Ефект, Ефект з MIDI-входом»)."""
    if s in EN:
        return EN[s]
    parts = s.split(", ")
    return ", ".join(EN[x] for x in parts) if all(x in EN for x in parts) else None


def _one(s):
    w = _words(s)
    if w is not None:
        return w
    for rx, en in PATTERNS:
        m = rx.fullmatch(s)
        if m:
            return m.expand(en)
    m = _WITH_FORMAT.fullmatch(s)
    w = m and _words(m.group(1))
    if w:
        return w + " (" + m.group(2) + ")"
    return None


def tr(s, lang, extra=None):
    """Перекладає збережену фразу. Невідоме лишається як є (зокрема текст із метаданих плагіна)."""
    if lang != "en" or not s or not isinstance(s, str):
        return s
    if extra and s in extra:
        return extra[s]
    one = _one(s)
    if one is not None:
        return one
    if SEP in s:  # опис і категорія складаються з частин: «Ефект · Reverb · версія 1.2»
        return SEP.join(tr(x, lang, extra) for x in s.split(SEP))
    if "\n" in s:  # попередження скану, по рядку
        return "\n".join(tr(x, lang, extra) for x in s.split("\n"))
    return s
