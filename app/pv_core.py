# -*- coding: utf-8 -*-
"""PluginVault: сканер, база даних та логіка. Лише стандартна бібліотека Python 3.8+."""
import json
import mmap
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import threading
import time
import plistlib
from datetime import datetime, timezone

from pv_lang import lang_of, tr  # noqa: F401  (lang_of потрібен API)

APP_DIR = os.path.dirname(os.path.abspath(__file__))
VERSION = "0.9.0"
IS_MAC = sys.platform == "darwin"


def data_home():
    env = os.environ.get("PLUGINVAULT_HOME")
    if env:
        return env
    if IS_MAC:
        return os.path.expanduser("~/Library/Application Support/PluginVault")
    return os.path.expanduser("~/.pluginvault")


HOME = data_home()
DB_PATH = os.path.join(HOME, "pluginvault.sqlite")


class Ctx(object):
    """Дозволяє підмінити «корінь» системи та домашню теку (для тестів)."""

    def __init__(self, root="/", home=None):
        self.root = root.rstrip("/") if root != "/" else ""
        self.home = home or os.path.expanduser("~")

    def abs(self, p):
        if p.startswith("~/"):
            return os.path.join(self.home, p[2:])
        return self.root + p if self.root else p

    def rel(self, path):
        if self.root and path.startswith(self.root):
            return path[len(self.root):] or "/"
        if path.startswith(self.home + "/"):
            return "~/" + path[len(self.home) + 1:]
        return path


# ---------------------------------------------------------------- утиліти

def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def ts_iso(ts):
    try:
        return datetime.fromtimestamp(ts).isoformat(timespec="seconds")
    except Exception:
        return ""


def vkey(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


RULE_FILES = ("stock_rules.json", "license_rules.json", "vendor_rules.json")
_rules_synced = False


def merge_rules(base, new, user):
    """Тристоронне злиття: додає зміни типових правил (base → new), не чіпаючи правок користувача (user)."""
    if isinstance(new, dict) and isinstance(user, dict):
        base = base if isinstance(base, dict) else {}
        out = dict(user)
        for k, v in new.items():
            if k in user:
                out[k] = merge_rules(base.get(k), v, user[k])
            elif k not in base:  # ключ, який є в базі, але не в user, користувач видалив сам
                out[k] = v
        return out
    if isinstance(new, list) and isinstance(user, list):
        base = base if isinstance(base, list) else []
        if all(isinstance(x, dict) and "label" in x for x in new + user):
            labelled = lambda rows: dict((x["label"], x) for x in rows)
            old_by, new_by = labelled(base), labelled(new)
            out = [merge_rules(old_by.get(x["label"]), new_by[x["label"]], x) if x["label"] in new_by else x for x in user]
            have = set(x["label"] for x in user)
            return out + [x for x in new if x["label"] not in have and x["label"] not in old_by]
        out = [x for x in user if x in new or x not in base]
        return out + [x for x in new if x not in user and x not in base]
    return new if user == base else user


def sync_rules(home, defaults):
    """Копіює правила при першому запуску, а далі доносить оновлення зі застосунку до теки даних."""
    snap_dir = os.path.join(home, "rules_base")
    os.makedirs(snap_dir, exist_ok=True)
    for fn in RULE_FILES:
        src, dst, snap = os.path.join(defaults, fn), os.path.join(home, fn), os.path.join(snap_dir, fn)
        if not os.path.exists(src):
            continue
        if os.path.exists(dst):
            try:
                with open(src, "r", encoding="utf-8") as f:
                    new = json.load(f)
                with open(dst, "r", encoding="utf-8") as f:
                    user = json.load(f)
                base = {}
                if os.path.exists(snap):
                    with open(snap, "r", encoding="utf-8") as f:
                        base = json.load(f)
            except (OSError, ValueError):  # файл із помилкою не перезаписуємо, користувач міг його редагувати
                continue
            merged = merge_rules(base, new, user)
            if merged != user:
                tmp = dst + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(merged, f, ensure_ascii=False, indent=1)
                os.replace(tmp, dst)
        else:
            shutil.copyfile(src, dst)
        shutil.copyfile(src, snap)


def ensure_home():
    global _rules_synced
    os.makedirs(HOME, exist_ok=True)
    if not _rules_synced:
        sync_rules(HOME, os.path.join(APP_DIR, "rules"))
        _rules_synced = True


def load_rules(name):
    for base in (HOME, os.path.join(APP_DIR, "rules")):
        p = os.path.join(base, name)
        if os.path.exists(p):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                continue
    return {}


# ---------------------------------------------------------------- база даних

SCHEMA = """
CREATE TABLE IF NOT EXISTS plugins(
 id INTEGER PRIMARY KEY,
 path TEXT UNIQUE NOT NULL,
 name TEXT, vendor TEXT, vendor_src TEXT, format TEXT, platform TEXT,
 confidence TEXT DEFAULT 'high', category TEXT, version TEXT, bundle_id TEXT,
 arch TEXT, au_code TEXT,
 size_bytes INTEGER DEFAULT 0,
 installed_at TEXT, installed_src TEXT, pkg_id TEXT,
 source_auto TEXT DEFAULT '', license_auto TEXT DEFAULT '[]', description_auto TEXT DEFAULT '',
 is_stock INTEGER DEFAULT 0, stock_reason TEXT DEFAULT '',
 first_seen TEXT, last_seen TEXT, present INTEGER DEFAULT 1,
 source_manual TEXT DEFAULT '', license_manual TEXT DEFAULT '',
 description_manual TEXT DEFAULT '', vendor_manual TEXT DEFAULT '',
 notes TEXT DEFAULT '', stock_override INTEGER
);
CREATE TABLE IF NOT EXISTS scans(
 id INTEGER PRIMARY KEY, started_at TEXT, finished_at TEXT, mode TEXT, roots TEXT,
 found INTEGER DEFAULT 0, new_count INTEGER DEFAULT 0, updated_count INTEGER DEFAULT 0,
 removed_count INTEGER DEFAULT 0, errors TEXT DEFAULT '', trigger TEXT DEFAULT 'manual'
);
CREATE TABLE IF NOT EXISTS changes(
 id INTEGER PRIMARY KEY, scan_id INTEGER, plugin_id INTEGER, at TEXT,
 kind TEXT, detail TEXT, name TEXT, path TEXT
);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
"""


def connect():
    ensure_home()
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(SCHEMA)
    have = set(r[1] for r in con.execute("PRAGMA table_info(plugins)"))
    for col, ddl in (("file_created_at", "TEXT DEFAULT ''"), ("installed_flag", "TEXT DEFAULT ''"), ("is_new", "INTEGER DEFAULT 0"),
                     ("au_components", "TEXT DEFAULT '[]'")):
        if col not in have:
            con.execute("ALTER TABLE plugins ADD COLUMN %s %s" % (col, ddl))
    con.commit()
    return con


def get_setting(con, key, default=None):
    r = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(con, key, value):
    con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)", (key, str(value)))
    con.commit()


# ---------------------------------------------------------------- формати

DIR_EXT = {".component": "AU", ".vst": "VST2", ".vst3": "VST3", ".aaxplugin": "AAX",
           ".clap": "CLAP", ".lv2": "LV2", ".dpm": "RTAS", ".rtas": "RTAS"}
FILE_EXT = set(DIR_EXT) | {".dll", ".so"}
SYMBOLS = [  # (байтовий рядок, формат)
    (b"VSTPluginMain", "VST2"),
    (b"GetPluginFactory", "VST3"),
    (b"clap_entry", "CLAP"),
    (b"lv2_descriptor", "LV2"),
    (b"lv2_lib_descriptor", "LV2"),
]
SKIP_APP_EXT = {".app", ".framework", ".photoslibrary", ".imovielibrary", ".fcpbundle",
                ".sparsebundle", ".backupdb", ".xcarchive", ".lproj", ".kext", ".appex",
                ".xcodeproj", ".noindex"}
PRUNE_NAMES = {".git", "node_modules", "site-packages", ".trash", ".spotlight-v100",
               ".fseventsd", ".documentrevisions-v100", ".temporaryitems", "caches",
               ".cache", ".npm", "deriveddata", "coresimulator", ".pyenv", ".cargo",
               ".rustup", ".gradle", ".m2", "__pycache__", "system32", "syswow64",
               "winsxs", "cloudstorage", "backups.backupdb", ".docker", "dist-packages"}
PRUNE_ABS = {"/System", "/dev", "/proc", "/sys", "/private", "/cores", "/bin", "/sbin",
             "/usr/bin", "/usr/lib", "/usr/libexec", "/usr/sbin", "/usr/share",
             "/usr/standalone", "/Library/Caches", "/Library/Developer",
             "/Library/Apple", "/Library/Frameworks", "/Volumes/.timemachine",
             "/opt/homebrew/Cellar", "/snap", "/run", "/var"}

STANDARD_ROOTS = [
    "/Library/Audio/Plug-Ins", "~/Library/Audio/Plug-Ins",
    "/Library/Application Support/Avid/Audio/Plug-Ins",
    "/Library/Application Support/Avid/Audio/Plug-Ins (Unused)",
    "~/Library/Application Support/Avid/Audio/Plug-Ins",
    "~/Library/Application Support/Avid/Audio/Plug-Ins (Unused)",
    "/Library/Application Support/Digidesign/Plug-Ins",
    "/Library/Application Support/Steinberg",
    "~/.vst", "~/.vst3", "~/.lv2", "~/.clap",
    "/usr/local/lib/vst", "/usr/local/lib/vst3", "/usr/local/lib/lv2", "/usr/local/lib/clap",
    "~/.wine/drive_c/Program Files", "~/.wine/drive_c/Program Files (x86)",
    "~/Library/Application Support/CrossOver/Bottles",
]


# ---------------------------------------------------------------- низькорівневий аналіз файлів

def read_head(path, n=4096):
    with open(path, "rb") as f:
        return f.read(n)


def sniff_platform(head):
    if head[:2] == b"MZ":
        return "Windows"
    if head[:4] == b"\x7fELF":
        return "Linux"
    if head[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xcf\xfa\xed\xfe",
                    b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        return "macOS"
    return "Невідомо"


def pe_arch(head):
    try:
        off = struct.unpack("<I", head[0x3C:0x40])[0]
        if off + 6 > len(head):
            return ""
        m = struct.unpack("<H", head[off + 4:off + 6])[0]
        return {0x8664: "x64", 0x14c: "x86 (32-bit)", 0xaa64: "ARM64"}.get(m, "")
    except Exception:
        return ""


def elf_arch(head):
    try:
        m = struct.unpack("<H", head[0x12:0x14])[0]
        return {0x3e: "x86_64", 0xb7: "aarch64", 3: "x86 (32-bit)", 0x28: "arm"}.get(m, "")
    except Exception:
        return ""


_CPU = {7: "i386", 0x01000007: "x86_64", 12: "arm", 0x0100000c: "arm64",
        0x0200000c: "arm64_32", 18: "ppc", 0x01000012: "ppc64"}


def macho_archs(path):
    try:
        with open(path, "rb") as f:
            h = f.read(8)
            m = h[:4]
            if m in (b"\xca\xfe\xba\xbe",):
                n = struct.unpack(">I", h[4:8])[0]
                if n > 16:
                    return []
                out = []
                for _ in range(n):
                    e = f.read(20)
                    if len(e) < 20:
                        break
                    out.append(_CPU.get(struct.unpack(">I", e[:4])[0], "?"))
                return out
            if m in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
                return [_CPU.get(struct.unpack("<I", h[4:8])[0], "?")]
    except Exception:
        pass
    return []


def mac_arch_label(archs):
    if not archs:
        return ""
    s = set(archs)
    if "arm64" in s and "x86_64" in s:
        return "Universal (Apple Silicon + Intel)"
    if "arm64" in s:
        return "Apple Silicon (arm64)"
    if "x86_64" in s:
        return "Лише Intel (на M-чипах — через Rosetta)"
    if s & {"i386", "ppc", "ppc64"}:
        return "Застарілий (" + ", ".join(sorted(s)) + ") — не працює на сучасному macOS"
    return ", ".join(sorted(s))


def find_symbols(path, max_size=400 * 1024 * 1024):
    """Повертає множину форматів за експортованими символами."""
    res = set()
    try:
        size = os.path.getsize(path)
        if size == 0 or size > max_size:
            return res
        with open(path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                for sym, fmt in SYMBOLS:
                    if mm.find(sym) != -1:
                        res.add(fmt)
            finally:
                mm.close()
    except (OSError, ValueError):
        pass
    return res


def pe_string(path, key, max_size=200 * 1024 * 1024):
    """Мінімальне читання рядка з VERSIONINFO у PE (UTF-16LE)."""
    try:
        if os.path.getsize(path) > max_size:
            return ""
        needle = key.encode("utf-16-le")
        with open(path, "rb") as f:
            mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                pos = mm.find(needle)
                while pos != -1 and pos % 2 == 1:
                    pos = mm.find(needle, pos + 1)
                if pos == -1:
                    return ""
                start = pos + len(needle)
                chunk = mm[start:start + 600]
            finally:
                mm.close()
        i = 0
        while i + 1 < len(chunk) and chunk[i:i + 2] == b"\x00\x00":
            i += 2
        j = i
        while j + 1 < len(chunk) and chunk[j:j + 2] != b"\x00\x00":
            j += 2
        val = chunk[i:j].decode("utf-16-le", "ignore").strip()
        return val if 0 < len(val) < 200 and val.isprintable() else ""
    except (OSError, ValueError):
        return ""


def dir_size(path):
    total = 0
    stack = [path]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for e in it:
                    try:
                        if e.is_symlink():
                            continue
                        if e.is_dir(follow_symlinks=False):
                            stack.append(e.path)
                        else:
                            total += e.stat(follow_symlinks=False).st_size
                    except OSError:
                        pass
        except OSError:
            pass
    return total


def read_plist(p):
    try:
        with open(p, "rb") as f:
            d = plistlib.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def read_json_loose(p):
    try:
        with open(p, "r", encoding="utf-8") as f:
            txt = f.read()
        try:
            return json.loads(txt)
        except ValueError:
            txt = re.sub(r"^\s*//.*$", "", txt, flags=re.M)
            return json.loads(txt)
    except Exception:
        return {}


def clean_vendor(v):
    v = (v or "").strip()
    v = re.sub(r"(?i)[,.]?\s*(all rights reserved.*)$", "", v).strip(" .,;")
    v = re.sub(r"(?i)^(©|\(c\)|copyright)\s*", "", v).strip()
    v = re.sub(r"^[\d\s,\-–]+", "", v).strip(" .,;")
    return v if 1 < len(v) < 80 else ""


_VENDOR_TAIL = re.compile(r"(?i)[,\s]+(?:\d{4}(?:\s*[-–,]\s*\d{4})*|gmbh(?:\s*&\s*co\.?(?:\s*kg)?)?|inc\.?|incorporated|llc\.?|l\.l\.c\.?"
                          r"|ltd\.?|limited|ab|ag|bv|b\.v\.|oy|kg|srl|sas|corp\.?|corporation)$")


def normalize_vendor(v, aliases):
    """Одна назва для одного виробника: без року й юридичної форми, із заміною зі словника."""
    v = (v or "").strip()
    while True:
        short = _VENDOR_TAIL.sub("", v).strip(" .,;")
        if short == v or not short:
            break
        v = short
    return aliases.get(vkey(v), v)


def vendor_from_copyright(s):
    if not s:
        return ""
    m = re.search(r"(?i)(?:©|\(c\)|copyright)\s*(?:\d{4}(?:\s*[-–,]\s*\d{4})*)?\s*[,.]?\s*(.+)", s)
    return clean_vendor(m.group(1)) if m else ""


def vendor_from_bundle_id(bid):
    parts = (bid or "").split(".")
    if len(parts) >= 2 and parts[0].lower() in ("com", "org", "net", "io", "de", "fr", "uk", "co", "se", "nl", "fi", "ru", "us", "audio"):
        v = parts[1]
        return v if v.lower() != v else v.capitalize()
    return ""


AU_TYPES = {"aumu": "Інструмент", "aufx": "Ефект", "aumf": "Ефект з MIDI-входом",
            "aumi": "MIDI-процесор", "augn": "Генератор", "aufc": "Конвертер",
            "aumx": "Мікшер", "auou": "Вивід", "aupn": "Панорамер"}


def vst3_category(info):
    try:
        for c in info.get("Classes", []):
            if c.get("Category") == "Audio Module Class":
                sub = c.get("Sub Categories") or []
                if not sub:
                    continue
                if "Instrument" in sub:
                    return "Інструмент" + (" · " + "/".join(s for s in sub if s != "Instrument") if len(sub) > 1 else "")
                if "Fx" in sub:
                    return "Ефект" + (" · " + "/".join(s for s in sub if s != "Fx") if len(sub) > 1 else "")
                return "/".join(sub)
    except Exception:
        pass
    return ""


# ---------------------------------------------------------------- побудова запису про плагін

def analyze(path, kind, ext, ctx):
    """Повертає dict з полями плагіна або None, якщо це не плагін."""
    rec = {"path": path, "name": "", "vendor": "", "vendor_src": "", "format": "", "platform": "",
           "confidence": "high", "category": "", "version": "", "bundle_id": "", "arch": "",
           "au_code": "", "au_components": [], "size_bytes": 0, "desc_bits": []}
    base = os.path.basename(path)
    stem = os.path.splitext(base)[0]
    rec["name"] = stem
    fmt = DIR_EXT.get(ext, "")

    if kind == "bundle":
        rec["format"] = fmt
        contents = os.path.join(path, "Contents")
        info = read_plist(os.path.join(contents, "Info.plist"))
        subdirs = []
        try:
            subdirs = os.listdir(contents)
        except OSError:
            pass
        lower = [s.lower() for s in subdirs]
        plat = ""
        exe_path = None
        if "macos" in lower:
            plat = "macOS"
            mdir = os.path.join(contents, subdirs[lower.index("macos")])
            exe = info.get("CFBundleExecutable")
            cand = os.path.join(mdir, exe) if exe else None
            if cand and os.path.isfile(cand):
                exe_path = cand
            else:
                try:
                    fs = [x for x in sorted(os.listdir(mdir)) if os.path.isfile(os.path.join(mdir, x))]
                    exe_path = os.path.join(mdir, fs[0]) if fs else None
                except OSError:
                    pass
        elif any(s.endswith("-win") or s in ("x64", "x86", "win32", "win64") for s in lower):
            plat = "Windows"
            for s in subdirs:
                if s.lower().endswith("-win") or s.lower() in ("x64", "x86", "win32", "win64"):
                    sd = os.path.join(contents, s)
                    try:
                        for x in os.listdir(sd):
                            exe_path = os.path.join(sd, x)
                            break
                    except OSError:
                        pass
                    break
            if exe_path and os.path.isfile(exe_path):
                rec["arch"] = pe_arch(read_head(exe_path))
        elif any(s.endswith("-linux") for s in lower):
            plat = "Linux"
        elif info or ext in (".component",):
            plat = "macOS"
        elif ext == ".lv2":
            plat = "Універсально (LV2)"
        else:
            plat = "Невідомо"
        rec["platform"] = plat
        if plat == "macOS" and exe_path:
            rec["arch"] = mac_arch_label(macho_archs(exe_path))
        elif plat == "Windows" and exe_path and os.path.isfile(exe_path):
            rec["vendor_pe"] = pe_string(exe_path, "CompanyName")
        rec["bundle_id"] = str(info.get("CFBundleIdentifier") or "")
        rec["version"] = str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "")
        copy = str(info.get("NSHumanReadableCopyright") or info.get("CFBundleGetInfoString") or "")
        # AU
        comps = info.get("AudioComponents") or []
        comps = [c for c in comps if isinstance(c, dict)] if isinstance(comps, list) else []
        if comps:
            c = comps[0]
            rec["au_code"] = str(c.get("manufacturer") or "")
            cats, names = [], []
            for x in comps:  # один файл може містити кілька плагінів (напр. Guitar Rig 7 FX і MFX)
                cat = AU_TYPES.get(str(x.get("type") or ""), "")
                if cat and cat not in cats:
                    cats.append(cat)
                n = str(x.get("name") or "")
                n = (n.split(": ", 1)[1] if ": " in n else n).strip()
                if n and n not in names:
                    names.append(n)
            rec["category"] = ", ".join(cats)
            rec["au_components"] = names
            cname = str(c.get("name") or "")
            if ": " in cname:
                rec["vendor"], rec["vendor_src"] = cname.split(": ", 1)[0].strip(), "AU-метадані"
            if len(names) == 1:
                rec["name"] = names[0]
            if not rec["version"]:
                rec["version"] = str(c.get("version") or "")
        # VST3 moduleinfo.json
        mi = os.path.join(contents, "Resources", "moduleinfo.json")
        if os.path.exists(mi):
            j = read_json_loose(mi)
            if j:
                if j.get("Name") and not rec["name"]:
                    rec["name"] = str(j["Name"])
                if j.get("Vendor") and not rec["vendor"]:
                    rec["vendor"], rec["vendor_src"] = str(j["Vendor"]), "moduleinfo.json"
                if j.get("Version") and not rec["version"]:
                    rec["version"] = str(j["Version"])
                cat = vst3_category(j)
                if cat and not rec["category"]:
                    rec["category"] = cat
        if not rec["vendor"]:
            v = vendor_from_copyright(copy)
            if v:
                rec["vendor"], rec["vendor_src"] = v, "copyright"
        if not rec["vendor"] and rec.get("vendor_pe"):
            rec["vendor"], rec["vendor_src"] = rec["vendor_pe"], "PE VersionInfo"
        if not rec["vendor"]:
            v = vendor_from_bundle_id(rec["bundle_id"])
            if v:
                rec["vendor"], rec["vendor_src"] = v, "ID пакета (припущення)"
        if copy:
            rec["desc_bits"].append(copy[:200])
        rec["size_bytes"] = dir_size(path)
        if not info and not rec["format"]:
            return None
    else:  # одиночний файл
        try:
            head = read_head(path)
        except OSError:
            return None
        plat = sniff_platform(head)
        fmts = None
        if ext in (".dll", ".so"):
            fmts = find_symbols(path)
            if not fmts:
                # нечіткий варіант: .dll у теці, де є «vst»
                low = path.lower()
                if ext == ".dll" and plat == "Windows" and ("vst" in low or "plug-in" in low or "plugins" in low) \
                        and os.path.getsize(path) > 50 * 1024:
                    fmts = {"VST2"}
                    rec["confidence"] = "low"
                else:
                    return None
            fmt = sorted(fmts)[0]
            # VST3 має пріоритет, якщо є кілька
            for pref in ("VST3", "CLAP", "VST2", "LV2"):
                if pref in fmts:
                    fmt = pref
                    break
        rec["format"] = fmt
        rec["platform"] = plat
        if plat == "Windows":
            rec["arch"] = pe_arch(head)
            ven = pe_string(path, "CompanyName")
            pn = pe_string(path, "ProductName")
            ver = pe_string(path, "FileVersion") or pe_string(path, "ProductVersion")
            cp = pe_string(path, "LegalCopyright")
            fd = pe_string(path, "FileDescription")
            if ven:
                rec["vendor"], rec["vendor_src"] = clean_vendor(ven), "PE VersionInfo"
            if pn and ext == ".dll":
                pass  # назву з файлу залишаємо — вона знайоміша
            if ver:
                rec["version"] = ver.replace(", ", ".")
            if not rec["vendor"] and cp:
                v = vendor_from_copyright(cp)
                if v:
                    rec["vendor"], rec["vendor_src"] = v, "PE copyright"
            if fd and fd.lower() != stem.lower():
                rec["desc_bits"].append(fd)
            if cp:
                rec["desc_bits"].append(cp[:200])
        elif plat == "Linux":
            rec["arch"] = elf_arch(head)
        elif plat == "macOS":
            rec["arch"] = mac_arch_label(macho_archs(path))
        rec["size_bytes"] = os.path.getsize(path)
    if not rec["vendor"]:
        # «Виробник/Плагін» за структурою тек: …/Vendor/plugin.vst3
        parent = os.path.basename(os.path.dirname(path))
        if parent and parent.lower() not in ("components", "vst", "vst2", "vst3", "plug-ins", "plugins", "clap",
                                              "lv2", "audio", "vstplugins", "common files", "program files",
                                              "program files (x86)", "avid", "library", "steinberg"):
            if not parent.startswith("."):
                rec["vendor"], rec["vendor_src"] = parent, "тека (припущення)"
    return rec


# ---------------------------------------------------------------- довідкові (macOS-специфічні) джерела

def run_cmd(args, timeout=10):
    try:
        r = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout)
        return r.stdout.decode("utf-8", "ignore")
    except Exception:
        return ""


def pkg_info(path):
    """pkgutil --file-info → (pkg_id, install_time_iso)"""
    if not (IS_MAC and shutil.which("pkgutil")):
        return "", ""
    out = run_cmd(["pkgutil", "--file-info", path])
    pid, it = "", ""
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("pkgid:") and not pid:
            pid = line.split(":", 1)[1].strip()
        elif line.startswith("install-time:") and not it:
            try:
                it = ts_iso(int(line.split(":", 1)[1].strip()))
            except ValueError:
                pass
    return pid, it


def where_froms(path):
    if not (IS_MAC and shutil.which("mdls")):
        return []
    out = run_cmd(["mdls", "-raw", "-name", "kMDItemWhereFroms", path])
    if "(null)" in out:
        return []
    return re.findall(r'"([^"]+)"', out)


def birth_time(path):
    try:
        st = os.stat(path)
        return getattr(st, "st_birthtime", None) or min(st.st_ctime, st.st_mtime), (
            "дата створення файлу" if hasattr(st, "st_birthtime") else "дата зміни файлу")
    except OSError:
        return None, ""


def parse_mdls_date(s):
    """«2026-09-30 12:14:35 +0000» → час у секундах або None."""
    try:
        return datetime.strptime(s.strip(), "%Y-%m-%d %H:%M:%S %z").timestamp()
    except ValueError:
        return None


def date_added(path):
    """Коли файл з'явився в теці (Spotlight). Дата створення часто є датою збірки у виробника."""
    if not (IS_MAC and shutil.which("mdls")):
        return None
    return parse_mdls_date(run_cmd(["mdls", "-raw", "-name", "kMDItemDateAdded", path]))


class InstallHistory(object):
    """Журнал встановлень macOS: дати пакетів, файли яких pkgutil не може зв'язати зі шляхом (напр. Native Instruments)."""
    PATH = "/Library/Receipts/InstallHistory.plist"
    FORMAT_PARTS = {"AU": {"au", "component"}, "VST2": {"vst", "vst2"}, "VST3": {"vst3"}, "AAX": {"aax"},
                    "CLAP": {"clap"}, "LV2": {"lv2"}, "RTAS": {"rtas", "dpm"}}

    def __init__(self, ctx):
        self.dates = {}  # ID пакета → час останнього встановлення
        try:
            with open(ctx.abs(self.PATH), "rb") as f:
                entries = plistlib.load(f)
        except Exception:
            return
        for e in entries if isinstance(entries, list) else []:
            d = e.get("date") if isinstance(e, dict) else None
            if not isinstance(d, datetime):
                continue
            ts = d.replace(tzinfo=timezone.utc).timestamp()  # plistlib віддає час UTC без поясу
            for pid in e.get("packageIdentifiers") or []:
                self.dates[pid] = max(ts, self.dates.get(pid, 0))

    def match(self, rec):
        """→ (ID пакета, час) для плагіна: той самий виробник, назва продукту й формат."""
        names = {vkey(os.path.splitext(os.path.basename(rec["path"]))[0]), vkey(rec["name"])}
        owner = vkey(rec["vendor"]) + " " + vkey(rec["bundle_id"])
        fmt_parts = self.FORMAT_PARTS.get(rec["format"], set())
        for_format, plain = [], []
        for pid, ts in self.dates.items():
            parts = [vkey(x) for x in pid.split(".")]
            if len(parts) < 3 or len(parts[1]) < 3 or parts[1] not in owner:
                continue
            rest = parts[2:]
            if not names & set(rest):
                continue
            if fmt_parts & set(rest):
                for_format.append((ts, pid))
            elif rest[-1] in names:  # ID без суфікса; .Documentation, .VST3 для AU тощо не підходять
                plain.append((ts, pid))
        best = max(for_format or plain or [(None, "")])
        return best[1], best[0]


def mac_setup_time(ctx):
    """Коли було вперше налаштовано цей Mac (створення .AppleSetupDone)."""
    for p in ("/var/db/.AppleSetupDone", "/private/var/db/.AppleSetupDone"):
        fp = ctx.abs(p)
        if os.path.exists(fp):
            t, _ = birth_time(fp)
            if t:
                return t
    return None


class Downloads(object):
    """Індекс інсталяторів у ~/Downloads для припущення про джерело."""
    EXT = {".dmg", ".pkg", ".zip", ".exe", ".rar", ".7z", ".msi", ".iso"}

    def __init__(self, ctx):
        self.items = []
        base = ctx.abs("~/Downloads")
        for dirpath, dirs, files in os.walk(base):
            depth = dirpath[len(base):].count(os.sep)
            if depth >= 2:
                dirs[:] = []
            for f in files:
                if os.path.splitext(f.lower())[1] in self.EXT:
                    self.items.append((vkey(f), os.path.join(dirpath, f), f))

    def guess(self, vendor, name):
        vk, nk = vkey(vendor), vkey(name)
        best = None
        for key, p, f in self.items:
            score = 0
            if len(nk) >= 5 and nk in key:
                score += 2
            if len(vk) >= 4 and vk in key:
                score += 1
            if score and (not best or score > best[0]):
                best = (score, p, f)
        if not best:
            return ""
        urls = where_froms(best[1])
        if urls:
            return "Імовірно: " + urls[0] + " (з інсталятора «" + best[2] + "»)"
        return "Імовірно: інсталятор «" + best[2] + "» у Downloads (URL невідомий)"


# Текст угоди чи перелік сторонніх ліцензій є майже в кожному інсталяторі, але нічого не каже про ліцензію власника
_LICENSE_DOC = re.compile(r"(?i)^(?:.*eula.*|.*licen[cs]e[ _-]?agreement.*|licen[cs]es?|.*third[ _-]?party.*|.*open[ _-]?source.*)\.(?:txt|rtf|html?|pdf|md)$")


def is_license_doc(path):
    return bool(_LICENSE_DOC.match(os.path.basename(path)))


class LicenseIndex(object):
    EXT = {".lic", ".wlic", ".license", ".licence", ".key", ".nicnt", ".u-he-act", ".vstkey",
           ".reg", ".keyfile", ".ilok", ".lickey"}
    DIRS = ["/Library/Application Support", "~/Library/Application Support", "/Library/Preferences",
            "~/Library/Preferences", "/Users/Shared"]

    def __init__(self, ctx, rules):
        self.items = []
        self.rules = rules.get("rules", [])
        self.ctx = ctx
        import glob
        self.glob = glob
        for d in self.DIRS:
            base = ctx.abs(d)
            if not os.path.isdir(base):
                continue
            for dirpath, dirs, files in os.walk(base):
                depth = dirpath[len(base):].count(os.sep)
                dirs[:] = [x for x in dirs if x.lower() not in PRUNE_NAMES and not x.endswith(".app")]
                if depth >= 3:
                    dirs[:] = []
                for f in files:
                    fl = f.lower()
                    if (os.path.splitext(fl)[1] in self.EXT or "licen" in fl or "serial" in fl) and not is_license_doc(f):
                        full = os.path.join(dirpath, f)
                        self.items.append((vkey(full), full))

    def find(self, vendor, name):
        """→ список {kind,label,text,paths}"""
        vk, nk = vkey(vendor), vkey(name)
        out = []
        for r in self.rules:
            toks = r.get("vendors", [])
            hit = False
            for t in toks:
                if len(t) >= 5:
                    hit = t in vk
                else:
                    hit = vk == t or vk.startswith(t)
                if hit:
                    break
            if not hit:
                continue
            only, skip = r.get("products"), r.get("except_products", [])
            if (only and not any(t in nk for t in only)) or any(t in nk for t in skip):
                continue
            paths = []
            for pat in r.get("paths", []):
                for p in sorted(self.glob.glob(self.ctx.abs(pat))):
                    if os.path.isfile(p) and not is_license_doc(p):
                        paths.append(p)
            out.append({"kind": r.get("kind", "account"), "label": r.get("label", ""), "short": r.get("short", r.get("label", "")),
                        "text": r.get("hint", ""), "paths": paths[:5]})
        # універсальний пошук за назвою/виробником у шляхах файлів ліцензій
        gen = []
        for key, p in self.items:
            if (len(vk) >= 4 and vk in key) or (len(nk) >= 5 and nk in key):
                if not any(p in o["paths"] for o in out):
                    gen.append(p)
        if gen:
            # Збіг лише за назвою файлу нічого не доводить: це підказка, а не знайдена ліцензія
            out.append({"kind": "guess", "label": "Схожий файл", "short": "Схожий файл", "text": "Назва схожа на ліцензію, але вміст не перевірявся", "paths": gen[:5]})
        return out


def stock_check(rec, rules, ctx):
    bid = (rec.get("bundle_id") or "").lower()
    for pre in rules.get("bundle_id_prefixes", []):
        if bid.startswith(pre.lower()):
            return "ID пакета починається з " + pre
    if rec.get("au_code") and rec["au_code"] in rules.get("au_manufacturer_codes", []):
        return "Виробник AU: Apple"
    rel = ctx.rel(rec["path"])
    for pp in rules.get("path_prefixes", []):
        if rel.startswith(pp):
            return "Системний шлях " + pp
    vk = vkey(rec.get("vendor"))
    exc = [vkey(x) for x in rules.get("vendors_except_names", [])]
    if vk and vk in [vkey(v) for v in rules.get("vendors", [])] and vkey(rec.get("name")) not in exc:
        return "Виробник: " + rec["vendor"]
    for fold in rules.get("avid_folders", []):
        if rel.startswith(fold):
            for pat in rules.get("avid_stock_name_patterns", []):
                if re.search(pat, rec.get("name", ""), re.I) or re.search(pat, os.path.splitext(os.path.basename(rec["path"]))[0], re.I):
                    return "Штатний плагін Pro Tools (за назвою)"
    return ""


def build_description(rec):
    bits = []
    cat = rec.get("category")
    head = (cat if cat else "Аудіоплагін") + " (" + (rec.get("format") or "?") + ")"
    bits.append(head)
    if rec.get("version"):
        bits.append("версія " + rec["version"])
    bits.extend(b for b in rec.get("desc_bits", []) if b)
    return " · ".join(bits)[:500]


# ---------------------------------------------------------------- сканування

STATE = {"running": False, "phase": "", "dirs": 0, "candidates": 0, "analyzed": 0,
         "found": 0, "current": "", "last_result": None, "error": "", "cancel": False}
_lock = threading.Lock()


def _prune(path, low, ctx):
    rel = ctx.rel(path)
    if rel in PRUNE_ABS or low in PRUNE_NAMES:
        return True
    if low == "windows" and os.path.basename(os.path.dirname(path)).lower() == "drive_c":
        return True
    return False


def walk_roots(roots, ctx, st, errors):
    cands = []
    seen = set()
    for root in roots:
        stack = [root]
        while stack:
            if st["cancel"]:
                return cands
            d = stack.pop()
            try:
                with os.scandir(d) as it:
                    entries = list(it)
            except OSError as e:
                if len(errors) < 50 and d == root:
                    errors.append("Немає доступу: %s (%s)" % (d, e.strerror))
                continue
            st["dirs"] += 1
            if st["dirs"] % 200 == 0:
                st["current"] = d
            for e in entries:
                low = e.name.lower()
                ext = os.path.splitext(low)[1]
                try:
                    isdir = e.is_dir(follow_symlinks=False)
                    isfile = e.is_file(follow_symlinks=False)
                except OSError:
                    continue
                if isdir:
                    if ext in DIR_EXT:
                        if e.path not in seen:
                            seen.add(e.path)
                            cands.append((e.path, "bundle", ext))
                        continue
                    if ext in SKIP_APP_EXT or _prune(e.path, low, ctx):
                        continue
                    stack.append(e.path)
                elif isfile and ext in FILE_EXT:
                    if e.path not in seen:
                        seen.add(e.path)
                        cands.append((e.path, "file", ext))
            st["candidates"] = len(cands)
    return cands


def scan(mode="standard", roots=None, ctx=None, trigger="manual", skip_pkg=False):
    """Повне сканування. Повертає підсумок. Безпечно викликати з потоку."""
    ctx = ctx or Ctx()
    if not _lock.acquire(False):
        return {"error": "Сканування вже триває"}
    st = STATE
    st.update({"running": True, "phase": "Пошук", "dirs": 0, "candidates": 0, "analyzed": 0,
               "found": 0, "current": "", "error": "", "cancel": False})
    con = connect()
    started = now_iso()
    errors = []
    try:
        if roots is None:
            if mode == "full":
                roots = [ctx.abs("/")]
            else:
                roots = [ctx.abs(r) for r in STANDARD_ROOTS]
        roots = [r for r in roots if os.path.isdir(r)]
        cur = con.execute("INSERT INTO scans(started_at,mode,roots,trigger) VALUES(?,?,?,?)",
                          (started, mode, json.dumps(roots, ensure_ascii=False), trigger))
        scan_id = cur.lastrowid
        had_scan_before = con.execute("SELECT COUNT(*) FROM scans WHERE finished_at IS NOT NULL AND id<?", (scan_id,)).fetchone()[0] > 0
        con.commit()

        cands = walk_roots(roots, ctx, st, errors)
        st["phase"] = "Аналіз"
        stock_rules = load_rules("stock_rules.json")
        aliases = load_rules("vendor_rules.json").get("aliases", {})
        lic =LicenseIndex(ctx, load_rules("license_rules.json"))
        dl = Downloads(ctx)
        hist = InstallHistory(ctx)
        setup_ts = mac_setup_time(ctx)
        if setup_ts:
            set_setting(con, "mac_setup_at", ts_iso(setup_ts))

        found = []
        for path, kind, ext in cands:
            if st["cancel"]:
                break
            st["analyzed"] += 1
            st["current"] = path
            try:
                rec = analyze(path, kind, ext, ctx)
            except Exception as ex:  # один поламаний плагін не має зупиняти все
                errors.append("%s: %s" % (path, ex))
                continue
            if rec:
                found.append(rec)
                st["found"] = len(found)

        st["phase"] = "Збереження"
        new = upd = rem = 0
        t = now_iso()
        found_paths = set(r["path"] for r in found)
        for rec in found:
            row = con.execute("SELECT * FROM plugins WHERE path=?", (rec["path"],)).fetchone()
            rec["vendor"] = normalize_vendor(rec["vendor"], aliases)
            reason = stock_check(rec, stock_rules, ctx)
            desc = build_description(rec)
            if row is None:
                # можливо, плагін перемістили?
                mv = None
                for cand in con.execute("SELECT * FROM plugins WHERE name=? AND format=? AND present=1", (rec["name"], rec["format"])):
                    if cand["path"] not in found_paths and not os.path.exists(cand["path"]):
                        mv = cand
                        break
                if mv is not None:
                    con.execute("UPDATE plugins SET path=?, last_seen=?, present=1 WHERE id=?", (rec["path"], t, mv["id"]))
                    con.execute("INSERT INTO changes(scan_id,plugin_id,at,kind,detail,name,path) VALUES(?,?,?,?,?,?,?)",
                                (scan_id, mv["id"], t, "moved", "з " + mv["path"], rec["name"], rec["path"]))
                    row = con.execute("SELECT * FROM plugins WHERE id=?", (mv["id"],)).fetchone()
            pkg_id, pkg_time = (row["pkg_id"] or "", "") if row else ("", "")
            if (row is None or not row["pkg_id"]) and not skip_pkg:
                pkg_id, pkg_time = pkg_info(rec["path"])
            hist_ts = None
            if not pkg_time:
                hist_ts = hist.dates.get(pkg_id)
                if hist_ts is None and not pkg_id:
                    pkg_id, hist_ts = hist.match(rec)
            if not rec["vendor"] and pkg_id:
                v = vendor_from_bundle_id(pkg_id)
                if v:
                    rec["vendor"], rec["vendor_src"] = normalize_vendor(v, aliases), "ID інсталятора (припущення)"
            birth, bsrc = birth_time(rec["path"])
            if pkg_time:
                inst_at, inst_src = pkg_time, "дата встановлення пакета (pkgutil)"
            elif hist_ts:
                inst_at, inst_src = ts_iso(hist_ts), "журнал встановлень macOS"
            elif row is not None and row["installed_src"] and row["installed_src"].startswith(("дата встановлення пакета", "журнал встановлень")):
                inst_at, inst_src = row["installed_at"], row["installed_src"]
            else:
                added = date_added(rec["path"])
                if added:
                    inst_at, inst_src = ts_iso(added), "дата появи в теці (Spotlight)"
                else:
                    inst_at, inst_src = (ts_iso(birth) if birth else ""), bsrc
            file_created = ts_iso(birth) if birth else ""
            flag = ""
            if setup_ts and inst_at:
                try:
                    if datetime.fromisoformat(inst_at).timestamp() < setup_ts - 86400:
                        flag = "migrated"
                except ValueError:
                    pass
            wf = where_froms(rec["path"])
            if wf:
                src = wf[0]
            elif row is not None and row["source_auto"] and not row["source_auto"].startswith("Імовірно"):
                src = row["source_auto"]
            else:
                src = dl.guess(rec["vendor"], rec["name"])
                if not src and pkg_id:
                    src = "Встановлено пакетом " + pkg_id
            lic_found = lic.find(rec["vendor"], rec["name"])
            lic_json = json.dumps(lic_found, ensure_ascii=False)
            vals = dict(name=rec["name"], vendor=rec["vendor"], vendor_src=rec["vendor_src"], format=rec["format"],
                        platform=rec["platform"], confidence=rec["confidence"], category=rec["category"],
                        version=rec["version"], bundle_id=rec["bundle_id"], arch=rec["arch"], au_code=rec["au_code"],
                        au_components=json.dumps(rec["au_components"], ensure_ascii=False),
                        size_bytes=rec["size_bytes"], installed_at=inst_at, installed_src=inst_src, pkg_id=pkg_id,
                        file_created_at=file_created, installed_flag=flag,
                        source_auto=src, license_auto=lic_json, description_auto=desc,
                        is_stock=1 if reason else 0, stock_reason=reason, last_seen=t, present=1)
            if row is None:
                vals.update(path=rec["path"], first_seen=t, is_new=1 if had_scan_before else 0)
                cols = ",".join(vals)
                con.execute("INSERT INTO plugins(%s) VALUES(%s)" % (cols, ",".join("?" * len(vals))), list(vals.values()))
                pid = con.execute("SELECT id FROM plugins WHERE path=?", (rec["path"],)).fetchone()["id"]
                con.execute("INSERT INTO changes(scan_id,plugin_id,at,kind,detail,name,path) VALUES(?,?,?,?,?,?,?)",
                            (scan_id, pid, t, "new", (rec["vendor"] or "?") + " · " + (rec["version"] or "версія невідома"), rec["name"], rec["path"]))
                new += 1
            else:
                pid = row["id"]
                if not row["present"]:
                    con.execute("INSERT INTO changes(scan_id,plugin_id,at,kind,detail,name,path) VALUES(?,?,?,?,?,?,?)",
                                (scan_id, pid, t, "returned", "знову з'явився", rec["name"], rec["path"]))
                if (row["version"] or "") != (rec["version"] or "") and row["version"] is not None and row["first_seen"]:
                    con.execute("INSERT INTO changes(scan_id,plugin_id,at,kind,detail,name,path) VALUES(?,?,?,?,?,?,?)",
                                (scan_id, pid, t, "updated", "%s → %s" % (row["version"] or "?", rec["version"] or "?"), rec["name"], rec["path"]))
                    upd += 1
                sets = ",".join("%s=?" % k for k in vals)
                con.execute("UPDATE plugins SET %s WHERE id=?" % sets, list(vals.values()) + [pid])
        # видалені: у базі є, на диску вже немає
        if not st["cancel"]:
            for row in con.execute("SELECT id,name,path FROM plugins WHERE present=1").fetchall():
                if row["path"] not in found_paths and not os.path.exists(row["path"]):
                    con.execute("UPDATE plugins SET present=0 WHERE id=?", (row["id"],))
                    con.execute("INSERT INTO changes(scan_id,plugin_id,at,kind,detail,name,path) VALUES(?,?,?,?,?,?,?)",
                                (scan_id, row["id"], t, "removed", "файл більше не існує", row["name"], row["path"]))
                    rem += 1
        # Скасований скан не завершений: інакше наступний вважав би «новим» усе, що не встиг знайти цей
        fin = None if st["cancel"] else now_iso()
        con.execute("UPDATE scans SET finished_at=?, found=?, new_count=?, updated_count=?, removed_count=?, errors=? WHERE id=?",
                    (fin, len(found), new, upd, rem, "\n".join(errors[:50]), scan_id))
        if fin:
            set_setting(con, "last_scan_at", fin)
        con.commit()
        res = {"scan_id": scan_id, "found": len(found), "new": new, "updated": upd, "removed": rem,
               "errors": errors[:20], "cancelled": st["cancel"]}
        st["last_result"] = res
        return res
    except Exception as ex:
        st["error"] = str(ex)
        raise
    finally:
        st["running"] = False
        st["phase"] = ""
        con.close()
        _lock.release()


# ---------------------------------------------------------------- вибірки для API

MANUAL_FIELDS = ("source_manual", "license_manual", "description_manual", "vendor_manual", "notes")


def lic_summary(row, lic):
    if row["license_manual"]:
        return "manual"
    if any(x.get("paths") and x.get("kind") != "guess" for x in lic):
        return "file"
    if any(x.get("kind") == "free" for x in lic):
        return "free"
    if lic:
        return "hint"
    return "none"


def row_to_dict(row):
    d = dict(row)
    try:
        lic = json.loads(d.get("license_auto") or "[]")
    except ValueError:
        lic = []
    d["license_auto"] = lic
    d["license_state"] = lic_summary(row, lic)
    try:
        d["au_components"] = json.loads(d.get("au_components") or "[]")
    except ValueError:
        d["au_components"] = []
    d["vendor_eff"] = d["vendor_manual"] or d["vendor"] or "Невідомо"
    d["source_eff"] = d["source_manual"] or d["source_auto"] or ""
    d["description_eff"] = d["description_manual"] or d["description_auto"] or ""
    if d["stock_override"] is None:
        d["stock"] = bool(d["is_stock"])
    else:
        d["stock"] = bool(d["stock_override"])
    return d


def list_plugins(con):
    return [row_to_dict(r) for r in con.execute("SELECT * FROM plugins ORDER BY lower(name)")]


# ---------------------------------------------------------------- продукти
# Продукт: файли одного плагіна в різних форматах. Не зберігається, а обчислюється при читанні,
# тому переміщення, нові формати й зміна виробника не потребують синхронізації.

FORMAT_ORDER = ("AU", "AAX", "VST2", "VST3", "CLAP", "LV2", "RTAS")
UNKNOWN_VENDOR = "Невідомо"
_NAME_FORMAT = re.compile(r"(?i)(?:[\s_.\-]+[(\[]?|[(\[])(?:vst[23]?|au|aax|x64|x86(?:[_-]64)?|arm64|(?:32|64)[\s-]?bit)(?![^\W_])[)\]]?")


def product_name(name, vendor=""):
    """Назва без виробника спереду та позначок формату: «FabFilter Pro-Q 3 VST3» → «Pro-Q 3». Номер версії лишається."""
    base = (name or "").strip()
    if vendor and vendor != UNKNOWN_VENDOR:
        m = re.match(re.escape(vendor) + r"[\s_:\-]+(.+)$", base, re.I)
        if m:
            base = m.group(1)
    return _NAME_FORMAT.sub("", base).strip(" _-.") or base


def _file_product_name(f):
    # Прибираємо і автоматичного виробника: ручна зміна виробника не має розбивати продукт
    return product_name(product_name(f["name"], f["vendor_eff"]), f["vendor"])


def _norm(s):
    s = (s or "").casefold()
    return "".join(c for c in s if c.isalnum()) or s.strip()


def product_key(name, vendor):
    return _norm(vendor) + "|" + _norm(product_name(name, vendor))


def _most_common(values):
    vals = [v for v in values if v]
    return min(set(vals), key=lambda v: (-vals.count(v), len(v), v)) if vals else ""


def _distinct(values):
    return list(dict.fromkeys(v for v in values if v))


def _format_rank(f):
    return FORMAT_ORDER.index(f["format"]) if f["format"] in FORMAT_ORDER else len(FORMAT_ORDER)


def _source_rank(s):
    return 2 if s.startswith("Встановлено пакетом") else 1 if s.startswith("Імовірно") else 0


def build_product(key, files):
    files = sorted(files, key=lambda f: (_format_rank(f), f["format"] or "", f["path"]))
    active = [f for f in files if f["present"]] or files
    names = [product_name(f["name"]) for f in files]  # виробника з показаної назви не прибираємо: це назва продукту
    known = [f["vendor_eff"] for f in files if f["vendor_eff"] != UNKNOWN_VENDOR]
    vendor_auto = _most_common(f["vendor"] for f in files)
    guesses = sorted((f for f in files if f["vendor"] == vendor_auto), key=lambda f: "припущ" in (f["vendor_src"] or ""))
    manual = {}
    mixed = []
    for field, sep in (("source_manual", " / "), ("license_manual", "\n"), ("description_manual", "\n"), ("notes", "\n"), ("vendor_manual", None)):
        vals = _distinct(f[field] for f in files)
        if len(vals) > 1:
            mixed.append(field)
        # Різні значення файлів показуємо всі: у файлах вони лишаються, доки власник не збереже інші
        manual[field] = (sep.join(vals) if sep else vals[0]) if vals else ""
    lic = []
    for f in files:
        for x in f["license_auto"]:
            if x not in lic:
                lic.append(x)
    category = next((f["category"] for f in files if f["category"]), "")
    source_auto = min((f["source_auto"] for f in active if f["source_auto"]), key=_source_rank, default="")
    desc = next((f["description_auto"] for f in active if f["category"] and f["description_auto"]),
                next((f["description_auto"] for f in active if f["description_auto"]), ""))
    desc = re.sub(r"^.*? \(\S+\)", lambda m: category or "Аудіоплагін", desc, count=1)
    dated = [f for f in active if f["installed_at"]]
    newest = max(dated, key=lambda f: f["installed_at"]) if dated else None
    overrides = set(f["stock_override"] for f in files)
    new_files = [f for f in active if f["is_new"]]
    d = {
        "id": min(f["id"] for f in files), "key": key, "files": files, "file_count": len(active),
        "name": _most_common(names), "vendor": vendor_auto, "vendor_eff": _most_common(known) or UNKNOWN_VENDOR,
        "vendor_src": guesses[0]["vendor_src"] if guesses else "",
        "formats": _distinct(f["format"] for f in active), "platforms": _distinct(f["platform"] for f in active),
        "versions": _distinct(f["version"] for f in active), "category": category,
        "au_components": _distinct(c for f in files for c in f["au_components"]),
        "size_bytes": sum(f["size_bytes"] or 0 for f in active),
        "present": any(f["present"] for f in files),
        "installed_at": newest["installed_at"] if newest else "", "installed_src": newest["installed_src"] if newest else "",
        "installed_flag": newest["installed_flag"] if newest else "",
        "first_seen": min((f["first_seen"] for f in files if f["first_seen"]), default=""),
        "last_seen": max((f["last_seen"] for f in files if f["last_seen"]), default=""),
        "source_auto": source_auto, "license_auto": lic, "description_auto": desc, "manual_mixed": mixed,
        "license_state": lic_summary(manual, lic),
        "is_new": 1 if new_files else 0, "new_count": len(new_files), "new_formats": _distinct(f["format"] for f in new_files),
        "is_stock": all(f["is_stock"] for f in active), "stock": all(f["stock"] for f in active),
        "stock_override": overrides.pop() if len(overrides) == 1 else None,
        "stock_reason": next((f["stock_reason"] for f in active if f["stock_reason"]), ""),
    }
    d.update(manual)
    d["source_eff"] = d["source_manual"] or source_auto
    d["description_eff"] = d["description_manual"] or desc
    return d


def group_products(files):
    """Групує файли за назвою та виробником. Файл без виробника приєднується, якщо інший виробник для цієї назви один."""
    vendors = {}
    for f in files:
        if f["vendor_eff"] != UNKNOWN_VENDOR:
            vendors.setdefault(_norm(_file_product_name(f)), set()).add(_norm(f["vendor_eff"]))
    groups = {}
    for f in files:
        name = _norm(_file_product_name(f))
        key = _norm(f["vendor_eff"]) + "|" + name
        if f["vendor_eff"] == UNKNOWN_VENDOR and len(vendors.get(name, ())) == 1:
            key = list(vendors[name])[0] + "|" + name
        groups.setdefault(key, []).append(f)
    return sorted((build_product(k, v) for k, v in groups.items()), key=lambda p: (p["name"].lower(), p["id"]))


def list_products(con):
    return group_products(list_plugins(con))


def product_of(con, fid):
    """Продукт, до якого належить файл із цим id (id продукту також є id файлу)."""
    for p in list_products(con):
        if any(f["id"] == fid for f in p["files"]):
            return p
    return None


def update_product(con, fid, data):
    """Ручні поля редагуються один раз на продукт: значення записується в усі його файли."""
    p = product_of(con, fid)
    return bool(p) and update_manual(con, [f["id"] for f in p["files"]], data)


def update_manual(con, pid, data):
    ids = pid if isinstance(pid, list) else [pid]
    sets, vals = [], []
    for k in MANUAL_FIELDS:
        if k in data:
            sets.append("%s=?" % k)
            vals.append(str(data[k] or "")[:5000])
    if "is_new" in data:
        sets.append("is_new=?")
        vals.append(1 if data["is_new"] else 0)
    if "stock_override" in data:
        v = data["stock_override"]
        sets.append("stock_override=?")
        vals.append(None if v is None else (1 if v else 0))
    if not sets:
        return False
    cur = con.execute("UPDATE plugins SET %s WHERE id IN (%s)" % (",".join(sets), ",".join("?" * len(ids))), vals + ids)
    con.commit()
    return cur.rowcount > 0


def history(con, limit=30):
    out = []
    for s in con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)):
        d = dict(s)
        d["changes"] = [dict(c) for c in con.execute(
            "SELECT kind,detail,name,path,plugin_id FROM changes WHERE scan_id=? ORDER BY id LIMIT 300", (s["id"],))]
        out.append(d)
    return out


CSV_COLS = [("product", "Продукт", "Product"), ("name", "Назва", "Name"), ("vendor_eff", "Виробник", "Vendor"),
            ("format", "Формат", "Format"), ("platform", "Платформа", "Platform"), ("path", "Шлях", "Path"),
            ("size_bytes", "Розмір (байт)", "Size (bytes)"), ("source_eff", "Звідки", "Source"),
            ("installed_at", "Дата інсталяції", "Installed"), ("version", "Версія", "Version"),
            ("license_text", "Ліцензія", "License"), ("description_eff", "Опис", "Description"),
            ("stock", "Штатний", "Stock"), ("present", "Є на диску", "On disk")]


def license_text(d, lang="uk"):
    parts = []
    if d.get("license_manual"):
        parts.append(d["license_manual"])
    for x in d.get("license_auto", []):
        if x.get("paths"):
            parts.append(("Files: " if lang == "en" else "Файли: ") + "; ".join(x["paths"]))
        elif x.get("text"):
            parts.append(x["text"])
    return " | ".join(parts)


def export_csv(con, include_stock=False, lang="uk"):
    import csv
    import io
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([c[2] if lang == "en" else c[1] for c in CSV_COLS])
    for p in localize(list_products(con), lang):
        if p["stock"] and not include_stock:
            continue
        for f in p["files"]:
            # Ручні значення спільні для продукту: новий формат теж їх отримує
            d = dict(f, product=p["name"], vendor_eff=p["vendor_eff"], license_manual=p["license_manual"],
                     source_eff=p["source_manual"] or f["source_eff"], description_eff=p["description_manual"] or f["description_eff"])
            d["license_text"] = license_text(d, lang)
            w.writerow([d.get(k, "") for k, *_ in CSV_COLS])
    return "\ufeff" + buf.getvalue()


# ---------------------------------------------------------------- мова
# База лишається українською, переклад робиться при видачі. Ручні поля й назви не перекладаються ніколи.

AUTO_FIELDS = ("platform", "arch", "category", "vendor_src", "installed_src", "source_auto", "description_auto", "stock_reason")


def license_phrases(defaults=None, user=None):
    """Українські тексти правил ліцензій → англійські (поля *_en). Текст, який власник змінив,
    лишається без перекладу: англійський варіант до нього вже не пасує."""
    if defaults is None:
        try:
            with open(os.path.join(APP_DIR, "rules", "license_rules.json"), "r", encoding="utf-8") as f:
                defaults = json.load(f)
        except (OSError, ValueError):
            defaults = {}
    if user is None:
        user = load_rules("license_rules.json")
    rules = lambda d: [r for r in (d.get("rules") if isinstance(d, dict) else None) or [] if isinstance(r, dict)]
    by_label = dict((r.get("label"), r) for r in rules(defaults))
    out = {}
    for r in rules(defaults):
        for k in ("hint", "short", "label"):
            if r.get(k) and r.get(k + "_en"):
                out[r[k]] = r[k + "_en"]
    for r in rules(user):
        d = by_label.get(r.get("label"), {})
        for k in ("hint", "short", "label"):
            en = r.get(k + "_en")
            # Власний переклад власника діє завжди, типовий лише для незміненого тексту
            if r.get(k) and en and (r[k] == d.get(k) or en != d.get(k + "_en")):
                out[r[k]] = en
    return out


def _localize_one(d, lang, lic):
    d = dict(d)
    for k in AUTO_FIELDS:
        if k in d:
            d[k] = tr(d[k], lang)
    if "platforms" in d:
        d["platforms"] = [tr(x, lang) for x in d["platforms"]]
    d["license_auto"] = [dict(x, label=tr(x.get("label"), lang, lic), short=tr(x.get("short"), lang, lic),
                              text=tr(x.get("text"), lang, lic)) for x in d.get("license_auto", [])]
    if not d.get("vendor_manual"):
        d["vendor_eff"] = tr(d.get("vendor_eff"), lang)
    d["source_eff"] = d.get("source_manual") or d.get("source_auto") or ""
    d["description_eff"] = d.get("description_manual") or d.get("description_auto") or ""
    if "files" in d:
        d["files"] = [_localize_one(f, lang, lic) for f in d["files"]]
    return d


def localize(items, lang):
    """Файли або продукти мовою інтерфейсу."""
    if lang != "en":
        return items
    lic = license_phrases()
    return [_localize_one(x, lang, lic) for x in items]


def localize_history(scans, lang):
    if lang != "en":
        return scans
    return [dict(s, errors=tr(s.get("errors"), lang), changes=[dict(c, detail=tr(c.get("detail"), lang)) for c in s["changes"]])
            for s in scans]


def localize_status(st, lang):
    if lang != "en":
        return st
    st = dict(st, phase=tr(st.get("phase"), lang), error=tr(st.get("error"), lang))
    if isinstance(st.get("last_result"), dict):
        st["last_result"] = dict(st["last_result"], errors=[tr(e, lang) for e in st["last_result"].get("errors", [])])
    return st


# ---------------------------------------------------------------- розклад (launchd)

LABEL = "com.pluginvault.weekly-scan"


def plist_path():
    return os.path.expanduser("~/Library/LaunchAgents/%s.plist" % LABEL)


def schedule_plist(python=None, script=None, weekday=1, hour=11, minute=7):
    python = python or sys.executable
    script = script or os.path.join(APP_DIR, "pluginvault.py")
    return {
        "Label": LABEL,
        "ProgramArguments": [python, script, "scan", "--trigger", "weekly", "--quiet"],
        "StartCalendarInterval": {"Weekday": weekday, "Hour": hour, "Minute": minute},
        "StandardOutPath": os.path.join(HOME, "scan.log"),
        "StandardErrorPath": os.path.join(HOME, "scan.log"),
        "ProcessType": "Background",
        "LowPriorityIO": True,
        "Nice": 10,
    }


def schedule_status():
    p = plist_path()
    installed = os.path.exists(p)
    loaded = False
    if IS_MAC and installed:
        r = subprocess.run(["launchctl", "print", "gui/%d/%s" % (os.getuid(), LABEL)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        loaded = r.returncode == 0
    return {"supported": IS_MAC, "installed": installed, "loaded": loaded, "plist": p}


def schedule_blocker(python, script):
    """Причина не вмикати розклад або None. Застосунок, відкритий просто після розпакування,
    macOS запускає з тимчасової копії (AppTranslocation), яка зникає після перезапуску."""
    if any("/AppTranslocation/" in p for p in (python, script)):
        return ("Plugius запущено з тимчасової копії, тож автоскан зламається після перезапуску Mac. "
                "Перемістіть Plugius.app у Програми, відкрийте звідти й увімкніть автоскан знову.")
    return None


def schedule_install():
    if not IS_MAC:
        return {"ok": False, "error": "Розклад (launchd) доступний лише на macOS"}
    pa = schedule_plist()["ProgramArguments"]
    err = schedule_blocker(pa[0], pa[1])
    if err:
        return {"ok": False, "error": err}
    p = plist_path()
    os.makedirs(os.path.dirname(p), exist_ok=True)
    ensure_home()
    with open(p, "wb") as f:
        plistlib.dump(schedule_plist(), f)
    dom = "gui/%d" % os.getuid()
    subprocess.run(["launchctl", "bootout", dom, p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    r = subprocess.run(["launchctl", "bootstrap", dom, p], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        r2 = subprocess.run(["launchctl", "load", "-w", p], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if r2.returncode != 0:
            return {"ok": False, "error": (r.stderr or r2.stderr).decode("utf-8", "ignore")[:300]}
    return {"ok": True}


def schedule_remove():
    p = plist_path()
    if IS_MAC and os.path.exists(p):
        dom = "gui/%d" % os.getuid()
        r = subprocess.run(["launchctl", "bootout", dom, p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if r.returncode != 0:
            subprocess.run(["launchctl", "unload", "-w", p], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if os.path.exists(p):
        os.remove(p)
    return {"ok": True}
