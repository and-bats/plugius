# -*- coding: utf-8 -*-
import json
import os
import plistlib
import shutil
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

HERE = os.path.dirname(os.path.abspath(__file__))
APP = os.path.join(os.path.dirname(HERE), "app")
sys.path.insert(0, APP)
sys.path.insert(0, HERE)

tmp = tempfile.mkdtemp(prefix="pvtest_")
os.environ["PLUGINVAULT_HOME"] = os.path.join(tmp, "data")
root = os.path.join(tmp, "disk")
home = os.path.join(root, "Users", "tester")
os.makedirs(home)

import make_tree
import pv_core as core

# Тести не мають торкатися системи: на Mac інакше поставили б справжнє завдання launchd і відкрили Finder.
core.IS_MAC = False

make_tree.build(root, home)
ctx = core.Ctx(root=root, home=home)

fails = []


def check(cond, msg):
    print(("  OK   " if cond else "  FAIL ") + msg)
    if not cond:
        fails.append(msg)


def by_name(con, name):
    r = con.execute("SELECT * FROM plugins WHERE name=?", (name,)).fetchall()
    return core.row_to_dict(r[0]) if r else None


print("== 1. Стандартний скан")
res = core.scan("standard", ctx=ctx)
print("  ", res)
con = core.connect()
names = sorted(r["name"] for r in con.execute("SELECT name FROM plugins"))
print("   знайдено:", names)
check(res["errors"] == [], "без помилок")
fab = by_name(con, "Pro-Q 3")
check(by_name(con, "Alchemy") is None, "плагіни всередині .app ігноруються")
check(by_name(con, "kernel32") is None, "system32/kernel32.dll пропущено")
check(by_name(con, "library") is None, "звичайна .dll без символів плагіна ігнорується")
check(by_name(con, "notaplugin") is None, ".so без символів плагіна ігнорується")
check(by_name(con, "evil") is None, "node_modules пропущено")
fabs = [core.row_to_dict(r) for r in con.execute("SELECT * FROM plugins WHERE name='Pro-Q 3'")]
au = [d for d in fabs if d["format"] == "AU"][0]
aax = [d for d in fabs if d["format"] == "AAX"][0]
check(au["vendor"] == "FabFilter" and au["vendor_src"] == "AU-метадані", "AU: виробник з AudioComponents")
check(au["version"] == "3.21", "AU: версія")
check(au["category"] == "Ефект", "AU: категорія Ефект")
check("Universal" in au["arch"], "AU: архітектура Universal (%s)" % au["arch"])
check(au["size_bytes"] > 20000, "розмір бандла рахується рекурсивно (%d)" % au["size_bytes"])
check(not au["stock"], "FabFilter AU не штатний")
check(aax["vendor"] == "FabFilter", "AAX: той самий виробник, що й в AU, навіть із ID пакета (%s)" % aax["vendor"])
check(any("Імовірно" in (d["source_auto"] or "") and "FabFilter-Pro-Q-3-Installer.dmg" in d["source_auto"] for d in fabs),
      "джерело вгадано з інсталятора в Downloads: %s" % au["source_auto"])
ser = by_name(con, "Serum")
check(ser["vendor"] == "Xfer Records" and ser["category"] == "Інструмент", "Serum: AU-метадані")
check("Intel" in ser["arch"], "Serum: лише Intel (%s)" % ser["arch"])
val = by_name(con, "Valhalla VintageVerb")
check(val and val["vendor"] == "Valhalla DSP" and val["vendor_src"] == "moduleinfo.json", "VST3 moduleinfo.json, без LLC (%s)" % (val and val["vendor"]))
check(val and val["category"].startswith("Ефект"), "VST3 категорія %s" % (val and val["category"]))
ws = [core.row_to_dict(r) for r in con.execute("SELECT * FROM plugins WHERE name LIKE 'WaveShell%'")][0]
check(ws["vendor"] == "Waves", "виробник з copyright і словника назв (%s)" % ws["vendor"])
check(by_name(con, "Meter")["vendor"] == "Youlean", "рік після назви виробника відкинуто (%s)" % by_name(con, "Meter")["vendor"])
check(by_name(con, "Melo")["vendor"] == "Celemony", "юридична форма й словник: Celemony (%s)" % by_name(con, "Melo")["vendor"])
check(core.normalize_vendor("Big Co", {}) == "Big Co" and core.normalize_vendor("Inc", {}) == "Inc", "нормалізація не псує звичайні назви")
gr = by_name(con, "Guitar Rig 7")
check(gr and gr["au_components"] == ["Guitar Rig 7 FX", "Guitar Rig 7 MFX"], "AU: усі плагіни у файлі (%s)" % (gr and gr["au_components"]))
check(gr and gr["category"] == "Ефект, Ефект з MIDI-входом", "AU: категорії всіх плагінів, aumf не «MIDI-ефект»")
check(gr and gr["vendor"] == "Native Instruments", "AU: виробник без GmbH")
check(au["name"] == "Pro-Q 3" and au["au_components"] == ["Pro-Q 3"], "AU з одним плагіном зберігає його назву")
check(by_name(con, "Disabled") is not None, "стандартний скан бачить теку Plug-Ins (Unused)")
lic_files = [p for x in ws["license_auto"] for p in x.get("paths", [])]
check(any(p.endswith("WaveShell.wlic") for p in lic_files), "Waves: знайдено файл ліцензії")
check(ws["license_state"] == "file", "Waves: стан ліцензії file")
old = by_name(con, "OldComp")
check("не працює" in old["arch"], "32-бітний VST2 позначено застарілим (%s)" % old["arch"])
surge = by_name(con, "Surge XT")
check(surge["vendor"] == "Surge Synth Team" and "припущення" in surge["vendor_src"], "виробник з назви теки")
# штатні
check(by_name(con, "AUDelay")["stock"], "Apple AU = штатний")
check(by_name(con, "AIR Reverb")["stock"], "AIR Reverb = штатний (Pro Tools)")
check(by_name(con, "EQ III")["stock"], "EQ III = штатний (за назвою)")
check(not by_name(con, "Mystery Fx")["stock"], "невідомий AAX не штатний")
check(not aax["stock"], "FabFilter AAX не штатний")
# не-macOS
tdr = by_name(con, "TDR Nova")
check(tdr["platform"] == "Windows" and tdr["format"] == "VST2", "TDR Nova: Windows VST2")
check(tdr["vendor"] == "Tokyo Dawn Labs" and tdr["version"] == "2.1.3", "PE VersionInfo: виробник і версія (%s / %s)" % (tdr["vendor"], tdr["version"]))
check(tdr["arch"] == "x64", "PE архітектура x64")
sk = by_name(con, "oldskool")
check(sk and sk["confidence"] == "low", "dll у теці VstPlugins без символів: низька впевненість")
lf = by_name(con, "linuxfx")
check(lf and lf["platform"] == "Linux" and lf["format"] == "VST2" and lf["arch"] == "x86_64", "Linux .so VST2")
calf = by_name(con, "calf")
check(calf and calf["format"] == "LV2", "LV2 bundle")
check(by_name(con, "BigSynth") is None, "стандартний скан не лізе в ~/Music")

check(ser["installed_flag"] == "migrated" and ser["installed_at"].startswith("2020"), "Serum: дата 2020 < налаштування Mac → позначено «перенесено» (%s)" % ser["installed_at"])
check(au["installed_flag"] == "" and au["file_created_at"], "FabFilter: свіжа дата, без позначки; file_created_at заповнено")
con2 = core.connect(); check(core.get_setting(con2, "mac_setup_at"), "час налаштування Mac збережено"); con2.close()
rep_au = [core.row_to_dict(r) for r in con.execute("SELECT * FROM plugins WHERE name='Replika' AND format='AU'")][0]
rep_aax = [core.row_to_dict(r) for r in con.execute("SELECT * FROM plugins WHERE name='Replika' AND format='AAX'")][0]
check(rep_au["installed_src"].startswith("журнал встановлень") and rep_au["installed_flag"] == "",
      "Replika: дата з журналу встановлень, без хибного «перенесено» (%s)" % rep_au["installed_at"])
check(rep_au["file_created_at"].startswith("2020"), "дата файлу лишається окремо (%s)" % rep_au["file_created_at"])
check(rep_au["pkg_id"] == "com.native-instruments.Replika.AU" and rep_aax["pkg_id"] == "com.native-instruments.Replika.AAX",
      "пакет обрано за форматом плагіна")
check(rep_au["installed_at"] > rep_aax["installed_at"], "кожен формат має дату свого пакета")
aa = by_name(con, "AutoAlign2")
check(aa["pkg_id"] == "com.SoundRadix.AutoAlign2" and aa["installed_src"].startswith("журнал встановлень"), "пакет без формату в ID теж знаходиться")
check(not by_name(con, "Splitter")["pkg_id"], "пакет чужого виробника з такою самою назвою не підходить")
check(not by_name(con, "Docs")["pkg_id"], "пакет документації чи контенту не вважається плагіном")
check(core.parse_mdls_date("2026-09-30 12:14:35 +0000") == 1790770475, "дата додавання зі Spotlight розбирається")
check(core.parse_mdls_date("(null)") is None, "відсутня дата Spotlight не ламає скан")
check(core.InstallHistory(core.Ctx(root=os.path.join(tmp, "nope"), home=home)).dates == {}, "без журналу встановлень скан працює")

print("== 2. Повний скан диска")
res = core.scan("full", ctx=ctx)
print("  ", res)
big = by_name(con, "BigSynth")
tool = by_name(con, "Tool")
logicthing = by_name(con, "LogicThing")
check(big and big["format"] == "VST3" and big["platform"] == "Windows", "повний скан: BigSynth.dll → VST3 (за символом GetPluginFactory)")
check(tool and tool["platform"] == "Windows" and tool["vendor"] == "WinCo", "Windows-розкладка .vst3 у теці: платформа/виробник (%s)" % (tool and tool["vendor"]))
check(logicthing and logicthing["stock"], "плагін у Application Support/Logic = штатний")
check(res["new"] >= 3, "нових у повному скані: %d" % res["new"])
check(big["is_new"] == 1 and tool["is_new"] == 1, "нові після другого скану позначені is_new")
check(by_name(con, "Serum")["is_new"] == 0, "плагіни першого скану не позначаються новими")
check(by_name(con, "Alchemy") is None, "повний скан теж не заходить в .app")
check(by_name(con, "kernel32") is None, "повний скан: kernel32 пропущено")
check(by_name(con, "library") is None, "повний скан: library.dll не плагін")
con.close()

print("== 3. Ручні поля переживають повторний скан; оновлення, видалення, переміщення")
con = core.connect()
sid = by_name(con, "Serum")["id"]
core.update_manual(con, sid, {"source_manual": "xferrecords.com / акаунт", "license_manual": "Лист від Xfer, серійник в 1Password",
                              "description_manual": "Вейвтейбл-синт", "stock_override": 1})
fid = au["id"]
core.update_manual(con, fid, {"notes": "куплений 2023"})
con.close()
# оновлюємо FabFilter, видаляємо OldComp, переносимо Surge
pl = os.path.join(root, "Library/Audio/Plug-Ins/Components/FabFilter Pro-Q 3.component/Contents/Info.plist")
d = plistlib.load(open(pl, "rb"))
d["CFBundleShortVersionString"] = "3.22"
plistlib.dump(d, open(pl, "wb"))
shutil.rmtree(os.path.join(root, "Library/Audio/Plug-Ins/VST/OldComp.vst"))
shutil.move(os.path.join(root, "Library/Audio/Plug-Ins/CLAP/Surge Synth Team/Surge XT.clap"),
            os.path.join(root, "Library/Audio/Plug-Ins/CLAP/Surge XT.clap"))
res = core.scan("standard", ctx=ctx)
print("  ", res)
con = core.connect()
check(res["updated"] == 1, "виявлено 1 оновлення версії")
check(res["removed"] == 1, "виявлено 1 видалений (OldComp)")
check(by_name(con, "OldComp")["present"] == 0, "OldComp позначено як відсутній, але запис лишився")
ser = by_name(con, "Serum")
check(ser["source_manual"].startswith("xferrecords") and ser["license_manual"].startswith("Лист") and ser["description_manual"] == "Вейвтейбл-синт",
      "ручні поля збережено")
check(ser["stock"] and ser["is_stock"] == 0, "ручне перевизначення штатності працює")
check(ser["license_state"] == "manual", "стан ліцензії manual")
check(ser["source_eff"].startswith("xferrecords") and ser["description_eff"] == "Вейвтейбл-синт", "ручне має пріоритет над авто")
fab = [core.row_to_dict(r) for r in con.execute("SELECT * FROM plugins WHERE name='Pro-Q 3' AND format='AU'")][0]
check(fab["version"] == "3.22" and fab["notes"] == "куплений 2023" and fab["id"] == fid, "версія оновлена, нотатки і id збережені")
surge_rows = con.execute("SELECT * FROM plugins WHERE name='Surge XT'").fetchall()
check(len(surge_rows) == 1 and surge_rows[0]["path"].endswith("CLAP/Surge XT.clap") and surge_rows[0]["present"] == 1,
      "переміщення розпізнано як той самий запис")
kinds = [r["kind"] for r in con.execute("SELECT kind FROM changes WHERE scan_id=?", (res["scan_id"],))]
check("updated" in kinds and "removed" in kinds and "moved" in kinds, "історія змін: %s" % kinds)
h = core.history(con)
check(len(h) >= 3 and h[0]["changes"], "history() повертає зміни")
res = core.scan("standard", ctx=ctx)
check(res["new"] == 0 and res["updated"] == 0 and res["removed"] == 0, "ідемпотентний скан без змін")
# plugin outside scan mode doesn't get removed
check(by_name(con, "BigSynth")["present"] == 1, "стандартний скан не «видаляє» плагіни, знайдені повним скан")
csvtxt = core.export_csv(con); print([l for l in csvtxt.splitlines() if "AUDelay" in l])
check("TDR Nova" in csvtxt and "AUDelay" not in csvtxt and "Serum" not in csvtxt, "CSV без штатних (і без вручну прихованих)")
con.close()

print("== 3b. Міграція старої бази")
import sqlite3
core.DB_PATH = os.path.join(tmp, "old.sqlite")
oc = sqlite3.connect(core.DB_PATH)
oc.executescript(core.SCHEMA.replace("file_created_at", "x_unused"))
oc.execute("ALTER TABLE plugins DROP COLUMN file_created_at") if False else None
oc.close()
os.remove(core.DB_PATH)
oc = sqlite3.connect(core.DB_PATH)
oc.execute("CREATE TABLE plugins(id INTEGER PRIMARY KEY, path TEXT UNIQUE NOT NULL, name TEXT)")
oc.execute("INSERT INTO plugins(path,name) VALUES('/a','A')")
oc.commit(); oc.close()
c3 = core.connect()
cols = set(r[1] for r in c3.execute("PRAGMA table_info(plugins)"))
check({"file_created_at", "installed_flag", "au_components"} <= cols, "стара база отримала нові колонки без втрати даних")
check(c3.execute("SELECT au_components FROM plugins").fetchone()[0] == "[]", "старий запис отримує порожній список компонентів")
c3.close()

print("== 3c. Скасований скан не псує позначку «нове»")
core.DB_PATH = os.path.join(tmp, "cancel.sqlite")
orig_walk = core.walk_roots


def cancelling_walk(roots, ctx_, st, errors):
    st["cancel"] = True
    return []


core.walk_roots = cancelling_walk
res = core.scan("standard", ctx=ctx)
core.walk_roots = orig_walk
c4 = core.connect()
check(res["cancelled"] and not core.get_setting(c4, "last_scan_at"), "скасований скан не змінює «останній скан»")
core.scan("standard", ctx=ctx)
check(c4.execute("SELECT COUNT(*) FROM plugins").fetchone()[0] > 0 and c4.execute("SELECT COUNT(*) FROM plugins WHERE is_new=1").fetchone()[0] == 0,
      "перший повний скан після скасованого нічого не вважає новим")
c4.close()
core.DB_PATH = os.path.join(tmp, "data", "pluginvault.sqlite")

print("== 3d. Оновлення правил зберігає правки користувача")
base = {"_comment": "старий", "bundle_id_prefixes": ["com.apple.", "com.avid.", "com.old."], "rules": [
    {"label": "A", "hint": "стара", "paths": []}, {"label": "B", "hint": "b", "paths": []}, {"label": "C", "hint": "c", "paths": []}]}
new = {"_comment": "новий", "bundle_id_prefixes": ["com.apple.", "com.avid.", "com.new."], "rules": [
    {"label": "A", "hint": "нова", "paths": []}, {"label": "B", "hint": "b2", "paths": []}, {"label": "C", "hint": "c", "paths": []}, {"label": "D", "hint": "d", "paths": []}],
    "aliases": {"x": "X"}}
user = {"_comment": "старий", "bundle_id_prefixes": ["com.apple.", "com.old.", "com.mine."], "rules": [
    {"label": "A", "hint": "стара", "paths": []}, {"label": "B", "hint": "моя", "paths": []}, {"label": "Моя", "hint": "m", "paths": []}]}
m = core.merge_rules(base, new, user)
check(m["_comment"] == "новий" and m["aliases"] == {"x": "X"}, "нове зі застосунку доходить")
check("com.new." in m["bundle_id_prefixes"] and "com.mine." in m["bundle_id_prefixes"], "новий рядок додано, власний лишився")
check("com.avid." not in m["bundle_id_prefixes"], "рядок, видалений користувачем, не повертається")
check("com.old." not in m["bundle_id_prefixes"], "рядок, прибраний зі застосунку, зникає")
by = dict((r["label"], r) for r in m["rules"])
check(by["A"]["hint"] == "нова" and by["B"]["hint"] == "моя" and "Моя" in by, "незмінене оновлено, власне збережено")
check("C" not in by and "D" in by, "видалене правило не повертається, нове додано")
sh = os.path.join(tmp, "sync"); sd = os.path.join(tmp, "defaults")
os.makedirs(sh); os.makedirs(sd)
for fn, body in (("stock_rules.json", new), ("license_rules.json", new), ("vendor_rules.json", new)):
    json.dump(body, open(os.path.join(sd, fn), "w"))
core.sync_rules(sh, sd)
check(json.load(open(os.path.join(sh, "vendor_rules.json"))) == new, "перший запуск копіює правила")
json.dump({"aliases": {"y": "Y"}}, open(os.path.join(sh, "stock_rules.json"), "w"))
json.dump({"aliases": {"x": "X", "z": "Z"}}, open(os.path.join(sd, "stock_rules.json"), "w"))
core.sync_rules(sh, sd)
check(json.load(open(os.path.join(sh, "stock_rules.json")))["aliases"] == {"y": "Y", "z": "Z"}, "повторний запуск додає нове, зберігає правки й не повертає видалене")
open(os.path.join(sh, "license_rules.json"), "w").write("{зламаний")
core.sync_rules(sh, sd)
check(open(os.path.join(sh, "license_rules.json")).read() == "{зламаний", "файл із помилкою не перезаписується")
check(plistlib.load(open(os.path.join(os.path.dirname(HERE), "desktop", "Info.plist"), "rb"))["CFBundleShortVersionString"] == core.VERSION,
      "версія застосунку й ядра збігається")

print("== 3e. Групування у продукти")


def fake(fid, name, vendor="", fmt="VST3", **kw):
    d = {"id": fid, "path": "/p/%d" % fid, "name": name, "vendor": vendor, "vendor_src": "", "format": fmt, "platform": "macOS", "confidence": "high",
         "category": "", "version": "1.0", "bundle_id": "", "arch": "", "au_code": "", "size_bytes": 10, "installed_at": "2024-01-01T00:00:00", "installed_src": "x",
         "pkg_id": "", "source_auto": "", "license_auto": "[]", "description_auto": "Аудіоплагін (%s) · версія 1.0" % fmt, "is_stock": 0, "stock_reason": "",
         "first_seen": "2024", "last_seen": "2024", "present": 1, "source_manual": "", "license_manual": "", "description_manual": "", "vendor_manual": "",
         "notes": "", "stock_override": None, "file_created_at": "", "installed_flag": "", "is_new": 0, "au_components": "[]"}
    d.update(kw)
    return core.row_to_dict(d)


def group(*files):
    return core.group_products(list(files))


check(core.product_name("FabFilter Pro-Q 3", "FabFilter") == "Pro-Q 3", "назва: виробник спереду прибирається")
check(core.product_name("Splice", "Splice") == "Splice", "назва, що збігається з виробником, не порожніє")
check(core.product_name("SpliceBridge", "Splice") == "SpliceBridge", "виробник без розділювача є частиною назви")
check(core.product_name("WaveShell1-VST3 14.0") == "WaveShell1 14.0", "назва: формат усередині, версія лишається")
check(core.product_name("Serum_x64") == "Serum" and core.product_name("Foo (VST3)") == "Foo" and core.product_name("Bar AU 64bit") == "Bar", "назва: архітектура й формат у кінці")
check(core.product_name("Beau") == "Beau" and core.product_name("AU Lab") == "AU Lab" and core.product_name("VST") == "VST", "назва: схожі слова й початок не чіпаються")
check(core.product_name("iZRX11SpectralEditorAAXHook") == "iZRX11SpectralEditorAAXHook", "назва: формат у складі слова лишається")
check(core.product_key("Valhalla VintageVerb", "Valhalla DSP") == core.product_key("ValhallaVintageVerb", "VALHALLA DSP"), "ключ не залежить від регістру й пробілів")
check(core.product_key("Гітара", "Виробник") != core.product_key("Бас", "Виробник"), "кирилиця в ключі не зникає")
check(len(group(fake(1, "Guitar Rig 6", "NI"), fake(2, "Guitar Rig 7", "NI"))) == 2, "різні покоління є різними продуктами")
ps = group(fake(1, "Youlean Loudness Meter 2", "Youlean"), fake(2, "Youlean Loudness Meter 2", "Youlean", "AU"))
check(len(ps) == 1 and ps[0]["name"] == "Youlean Loudness Meter 2", "показана назва зберігає виробника, якщо він у назві всіх файлів")
check(len(group(fake(1, "Comp", "A"), fake(2, "Comp", "B"))) == 2, "однакова назва в різних виробників не об'єднується")
ps = group(fake(1, "Mystery", ""), fake(2, "Mystery", "Known", "AU"))
check(len(ps) == 1 and ps[0]["vendor_eff"] == "Known", "файл без виробника приєднується до єдиного відомого")
check(len(group(fake(1, "Mystery", ""), fake(2, "Mystery", "A"), fake(3, "Mystery", "B"))) == 3, "за двох можливих виробників файл без виробника окремо")
ps = group(fake(1, "X", "V", "VST3", size_bytes=5), fake(2, "X", "V", "AAX", size_bytes=7, installed_at="2025-01-01T00:00:00", installed_flag="migrated"),
           fake(3, "X", "V", "AU", size_bytes=11, category="Ефект", description_auto="Ефект (AU) · версія 1.0"), fake(4, "X", "V", "VST2", size_bytes=100, present=0))
x = ps[0]
check(x["formats"] == ["AU", "AAX", "VST3"] and x["file_count"] == 3 and x["size_bytes"] == 23 and len(x["files"]) == 4,
      "зниклий файл є у списку, але не в сумах (%s, %s)" % (x["formats"], x["size_bytes"]))
check(x["category"] == "Ефект" and x["description_auto"] == "Ефект · версія 1.0", "категорія з AU на весь продукт, опис без формату (%s)" % x["description_auto"])
check(x["installed_at"].startswith("2025") and x["installed_flag"] == "migrated", "дата продукту: найновіша")
check(group(fake(1, "G", "V", present=0))[0]["present"] is False, "продукт без наявних файлів позначено зниклим")
ps = group(fake(1, "N", "V", "AU"), fake(2, "N", "V", "AAX", is_new=1))
check(ps[0]["is_new"] == 1 and ps[0]["new_count"] == 1 and ps[0]["new_formats"] == ["AAX"] and ps[0]["file_count"] == 2, "нове лише один файл: це видно")
check(group(fake(1, "S", "V", is_stock=1, stock_reason="r"), fake(2, "S", "V", "AU"))[0]["stock"] is False, "продукт штатний, лише коли штатні всі файли")
ps = group(fake(1, "M", "V", "AU", notes="перша", source_manual="a"), fake(2, "M", "V", "AAX", notes="друга", source_manual="a"), fake(3, "M", "V", "VST3", license_manual="л"))
check(ps[0]["notes"] == "перша\nдруга" and ps[0]["source_manual"] == "a" and ps[0]["license_manual"] == "л" and ps[0]["license_state"] == "manual",
      "ручні значення об'єднуються без втрат")
check(ps[0]["manual_mixed"] == ["notes"] and ps[0]["description_eff"].startswith("Аудіоплагін ·"), "різні значення позначено")
ps = group(fake(1, "L", "V", license_auto=json.dumps([{"label": "a", "text": "t", "paths": []}])),
           fake(2, "L", "V", "AU", license_auto=json.dumps([{"label": "a", "text": "t", "paths": []}, {"label": "b", "text": "t", "paths": ["/f"]}])))
check(len(ps[0]["license_auto"]) == 2 and ps[0]["license_state"] == "file", "ліцензії об'єднуються, найкращий стан перемагає")
ps = group(fake(1, "Q", "V", source_auto="Встановлено пакетом a"), fake(2, "Q", "V", "AU", source_auto="https://x"), fake(3, "Q", "V", "AAX", source_auto="Імовірно: y"))
check(ps[0]["source_auto"] == "https://x", "джерело: спершу точне")

con = core.connect()
prods = core.list_products(con)
byp = lambda name: [p for p in core.list_products(con) if p["name"] == name]
pq = byp("Pro-Q 3")
check(len(pq) == 1 and pq[0]["formats"] == ["AU", "AAX", "VST3"], "Pro-Q 3 з трьох файлів, навіть із виробником у назві одного (%s)" % (pq and pq[0]["formats"]))
check(pq[0]["category"] == "Ефект", "категорія AU на всьому продукті Pro-Q 3")
check(pq[0]["size_bytes"] == sum(f["size_bytes"] for f in pq[0]["files"]), "сумарний розмір")
check(pq[0]["notes"] == "куплений 2023", "нотатки, записані раніше на один файл, видно на продукті")
check(len(byp("Comp")) == 2, "Comp двох виробників лишається двома продуктами")
rep = byp("Replika")
check(len(rep) == 1 and rep[0]["formats"] == ["AU", "AAX"] and rep[0]["vendor_eff"] == "Native Instruments", "Replika: один продукт")
check(core.product_of(con, pq[0]["files"][1]["id"])["key"] == pq[0]["key"], "продукт знаходиться за будь-яким файлом")
fid = pq[0]["files"][2]["id"]
check(core.update_product(con, fid, {"source_manual": "fabfilter.com", "path": "/etc/passwd"}), "правка через будь-який файл продукту")
check(all(f["source_manual"] == "fabfilter.com" and f["path"] != "/etc/passwd" for f in byp("Pro-Q 3")[0]["files"]), "правка записана в усі файли, зайві поля ігноруються")
check(byp("Pro-Q 3")[0]["notes"] == "куплений 2023", "незачеплені ручні поля лишаються")
check(not core.update_product(con, 10 ** 6, {"notes": "x"}), "неіснуючий продукт")
core.update_product(con, fid, {"vendor_manual": "FF"})
check(len(byp("Pro-Q 3")) == 1 and byp("Pro-Q 3")[0]["vendor_eff"] == "FF" and byp("Pro-Q 3")[0]["file_count"] == 3, "зміна виробника не розбиває продукт")
core.update_product(con, fid, {"vendor_manual": ""})
check(byp("Pro-Q 3")[0]["vendor_eff"] == "FabFilter", "ручного виробника можна прибрати")
csvtxt = core.export_csv(con)
check(csvtxt.startswith("\ufeffПродукт,") and csvtxt.count("fabfilter.com") == 3, "CSV: файл на рядок, колонка продукту, ручне значення в кожного файлу")
# Новий формат наявного продукту: новий лише він, а ручні поля успадковуються
core.update_product(con, byp("Pro-Q 3")[0]["id"], {"license_manual": "Акаунт FabFilter"})
make_tree.bundle(root, "Library/Audio/Plug-Ins/CLAP/Pro-Q 3.clap", {"CFBundleIdentifier": "com.fabfilter.Pro-Q.3.CLAP", "CFBundleExecutable": "q",
                                                                  "NSHumanReadableCopyright": "© 2023 FabFilter Software Instruments"}, exe=make_tree.thin_macho("arm64"))
core.scan("standard", ctx=ctx)
pq = byp("Pro-Q 3")[0]
check(pq["new_count"] == 1 and pq["new_formats"] == ["CLAP"] and pq["file_count"] == 4, "скан: новий лише CLAP (%s)" % pq["new_formats"])
check(pq["license_manual"] == "Акаунт FabFilter" and pq["source_manual"] == "fabfilter.com" and pq["notes"] == "куплений 2023", "ручні поля після скану цілі й діють на новий формат")
check([f for f in pq["files"] if f["format"] == "AU"][0]["notes"] == "куплений 2023", "значення у файлі не змінилось")
core.update_product(con, pq["id"], {"is_new": 0})
check(byp("Pro-Q 3")[0]["is_new"] == 0, "відкриття картки скидає нове для всього продукту")
con.close()

print("== 3f. Ліцензії: хибний зелений стан")
lroot = os.path.join(tmp, "licdisk")
lhome = os.path.join(lroot, "Users", "t")
sup = os.path.join(lroot, "Library", "Application Support")
make_tree.w(os.path.join(sup, "iZotope/RX/Resources/license.txt"), b"END USER LICENSE AGREEMENT")
make_tree.w(os.path.join(sup, "iZotope/RX/EULA.rtf"), b"x")
make_tree.w(os.path.join(lhome, "Library/Application Support/Youlean/Meter Two/License"), b"x")
make_tree.w(os.path.join(sup, "Acme/real.lic"), b"x")
make_tree.w(os.path.join(sup, "Acme/Sub/license.txt"), b"x")
os.makedirs(os.path.join(sup, "Acme/AsDir"))
lrules = {"rules": [{"label": "Acme", "vendors": ["acme"], "kind": "file", "paths": ["/Library/Application Support/Acme/*"], "hint": "h"},
                    {"label": "Dir", "vendors": ["dironly"], "paths": ["/Library/Application Support/Acme/As*"], "hint": "h"}]}
li = core.LicenseIndex(core.Ctx(root=lroot, home=lhome), lrules)
st8 = lambda v, n: core.lic_summary({"license_manual": ""}, li.find(v, n))
check(li.find("iZotope", "RX") == [] and st8("iZotope", "RX") == "none", "текст угоди не вважається ліцензією")
gf = li.find("Youlean", "Meter Two")
check(len(gf) == 1 and gf[0]["kind"] == "guess" and st8("Youlean", "Meter Two") == "hint", "файл, схожий лише за назвою, дає підказку, а не зелений стан")
check(st8("Acme", "X") == "file" and [os.path.basename(p) for x in li.find("Acme", "X") for p in x["paths"]] == ["real.lic"], "справжній файл за правилом дає зелений стан, текст угоди поруч ні")
check(st8("DirOnly", "X") == "hint", "тека за шаблоном правила не є файлом ліцензії")
check(core.is_license_doc("/a/License") is False and core.is_license_doc("/a/x.lic") is False and core.is_license_doc("/a/Licenses.PDF"), "розпізнавання документів")
real = core.LicenseIndex(core.Ctx(root=os.path.join(tmp, "nope"), home=lhome), json.load(open(os.path.join(APP, "rules", "license_rules.json"), encoding="utf-8")))
kinds8 = lambda v, n: [(x["label"], x["kind"]) for x in real.find(v, n)]
check(kinds8("Valhalla DSP", "ValhallaSupermassive") == [("Valhalla DSP (безкоштовні)", "free")] and core.lic_summary({"license_manual": ""}, real.find("Valhalla DSP", "ValhallaSupermassive")) == "free", "безкоштовний Valhalla")
check(kinds8("Valhalla DSP", "ValhallaRoom") == [("Valhalla DSP", "account")], "платний Valhalla не безкоштовний")
check(all(kinds8(v, "X") for v in ("Sound Radix", "Klevgrand", "Youlean", "Splice", "Celemony", "Native Instruments", "iZotope")), "правила для всіх перевірених виробників")
rules8 = json.load(open(os.path.join(APP, "rules", "license_rules.json"), encoding="utf-8"))["rules"]
check(all(r.get("short") and len(r["short"]) <= 24 for r in rules8), "кожне правило має короткий підпис для таблиці")
check(real.find("Sound Radix", "X")[0]["short"] == "iLok" and gf[0]["short"] == "Схожий файл", "короткий підпис доходить до результату")
check(li.find("DirOnly", "X")[0]["short"] == "Dir", "правило без короткого підпису показує назву")
check(core.lic_summary({"license_manual": "моя"}, real.find("Valhalla DSP", "ValhallaSupermassive")) == "manual", "ручне значення має пріоритет над «безкоштовний»")

print("== 4. Розклад launchd")
pp = core.schedule_plist(python="/usr/bin/python3", script="/x/pluginvault.py")
raw = plistlib.dumps(pp)
back = plistlib.loads(raw)
check(back["Label"] == core.LABEL and back["StartCalendarInterval"]["Weekday"] == 1 and back["ProgramArguments"][1:3] == ["/x/pluginvault.py", "scan"],
      "plist валідний, раз на тиждень")
check(core.schedule_install()["ok"] is False and core.schedule_status()["supported"] is False, "поза macOS розклад чесно відмовляє")
tl = "/private/var/folders/0m/x/T/AppTranslocation/1B2B/d/Plugius.app/Contents/Resources"
check("Програми" in (core.schedule_blocker(tl + "/python/bin/python3", tl + "/app/pluginvault.py") or ""),
      "розклад із тимчасової копії (AppTranslocation) відхиляється з порадою перемістити в Програми")
check(core.schedule_blocker("/usr/bin/python3", tl + "/app/pluginvault.py") is not None, "тимчасовий шлях скрипта теж відхиляється")
check(core.schedule_blocker("/Applications/Plugius.app/Contents/Resources/python/bin/python3",
                            "/Applications/Plugius.app/Contents/Resources/app/pluginvault.py") is None, "звичайний шлях дозволено")

print("== 5. HTTP API")
import pluginvault as pv
from http.server import ThreadingHTTPServer
srv = ThreadingHTTPServer(("127.0.0.1", 0), pv.Handler)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = "http://127.0.0.1:%d" % port


def req(path, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"Content-Type": "application/json"} if body is not None else {}
    h.update(headers or {})
    r = urllib.request.Request(base + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


s, b = req("/")
check(s == 200 and b"Plugius" in b, "GET / віддає UI")
s, b = req("/api/plugins")
pl = json.loads(b)
check(s == 200 and len(pl) > 10, "GET /api/plugins: %d" % len(pl))
sid = [p for p in pl if p["name"] == "Serum"][0]["id"]
s, b = req("/api/plugins/%d" % sid, "PATCH", {"notes": "через API"})
check(s == 200 and json.loads(b)["notes"] == "через API", "PATCH зберігає нотатки")
s, b = req("/api/plugins/%d" % sid, "PATCH", {"path": "/etc/passwd", "name": "hack"})
check(s == 404 or json.loads(b)["name"] == "Serum", "PATCH ігнорує недозволені поля (path/name)")
s, _ = req("/api/plugins/%d" % sid, "PATCH", {"notes": "x"}, {"Content-Type": "text/plain"})
check(s == 415, "PATCH без application/json відхилено (CSRF)")
s, _ = req("/api/scan", "POST", {}, {"Origin": "http://evil.example"})
check(s == 403, "чужий Origin відхилено")
s, _ = req("/api/plugins", headers={"Host": "evil.example"})
check(s == 403, "чужий Host відхилено (DNS rebinding)")
s, b = req("/api/products")
prods = json.loads(b)
check(s == 200 and len(prods) < len(pl) and sum(len(p["files"]) for p in prods) == len(pl), "GET /api/products: %d продуктів із %d файлів" % (len(prods), len(pl)))
rp = [p for p in prods if p["name"] == "Replika"][0]
s, b = req("/api/products/%d" % rp["files"][1]["id"], "PATCH", {"notes": "спільна", "name": "hack"})
back = json.loads(b)
check(s == 200 and back["name"] == "Replika" and back["notes"] == "спільна" and all(f["notes"] == "спільна" for f in back["files"]), "PATCH продукту пише в усі файли")
s, _ = req("/api/products/%d" % rp["id"], "PATCH", {"notes": "x"}, {"Content-Type": "text/plain"})
check(s == 415, "PATCH продукту без application/json відхилено")
s, _ = req("/api/products/999999", "PATCH", {"notes": "x"})
check(s == 404, "PATCH неіснуючого продукту")
s, b = req("/api/ack-new", "POST", {})
check(s == 200 and all(p["is_new"] == 0 for p in json.loads(req("/api/plugins")[1])), "ack-new скидає позначки")
s, b = req("/api/status")
st = json.loads(b)
check(s == 200 and "scan_mode" in st and st["plugin_count"] > 10, "GET /api/status")
s, b = req("/api/settings", "POST", {"scan_mode": "standard"})
check(s == 200, "POST /api/settings")
os.environ["PV_FAKE"] = "1"
# запуск скану через API використовує реальний ctx (/), тому підміняємо
orig_scan = core.scan
core.scan = lambda mode="standard", **kw: orig_scan(mode=mode, ctx=ctx, **kw)
s, b = req("/api/scan", "POST", {"mode": "standard"})
check(s == 200 and json.loads(b)["started"], "POST /api/scan стартує")
for _ in range(100):
    time.sleep(0.1)
    if not json.loads(req("/api/status")[1])["running"]:
        break
check(not json.loads(req("/api/status")[1])["running"], "скан завершився")
core.scan = orig_scan
s, b = req("/api/history")
check(s == 200 and len(json.loads(b)) >= 4, "GET /api/history")
s, b = req("/api/export.csv")
check(s == 200 and b.startswith(b"\xef\xbb\xbf"), "CSV з BOM для Excel/Numbers")
s, b = req("/api/reveal", "POST", {"id": sid})
check(s == 400, "reveal поза macOS чесно відмовляє")
s, b = req("/api/scan", "POST", {"mode": "bogus"})
check(s == 400, "невідомий режим відхилено")

print("== 6. Англійська мова")
import re
CYR = re.compile("[а-яіїєґА-ЯІЇЄҐ]")
check(core.tr("дата встановлення пакета (pkgutil)", "en") == "package install date (pkgutil)", "точна фраза перекладається")
check(core.tr("Імовірно: інсталятор «Pro-Q.dmg» у Downloads (URL невідомий)", "en") == "Probably: installer “Pro-Q.dmg” in Downloads (URL unknown)",
      "фраза з шаблону перекладається, вставка лишається")
check(core.tr("Встановлено пакетом com.fab.pkg", "en") == "Installed by package com.fab.pkg", "префікс «Встановлено пакетом»")
check(core.tr("Ефект · Reverb · версія 1.2 · © Valhalla", "en") == "Effect · Reverb · version 1.2 · © Valhalla", "складений опис перекладається частинами")
check(core.tr("Інструмент (AU)", "en") == "Instrument (AU)", "категорія з форматом")
check(core.tr("Своя фраза власника", "en") == "Своя фраза власника", "невідома фраза лишається як є")
check(core.tr("дата встановлення пакета (pkgutil)", "uk") == "дата встановлення пакета (pkgutil)", "українською нічого не змінюється")
check(core.tr("", "en") == "" and core.tr(None, "en") is None, "порожнє значення лишається")
check(core.lang_of("lang=en") == "en" and core.lang_of("lang=uk") == "uk" and core.lang_of("") == "uk" and core.lang_of("lang=de") == "uk",
      "мова із запиту: лише uk або en")


def cyr_leaks(obj, where=""):
    """Кирилиця поза ручними полями й назвами (їх не перекладаємо ніколи)."""
    out = []
    if isinstance(obj, dict):
        manual = lambda k: bool(obj.get(k))
        for k, v in obj.items():
            if k in ("name", "path", "key", "product", "notes", "au_components") or k.endswith("_manual"):
                continue
            if (k == "source_eff" and manual("source_manual")) or (k == "description_eff" and manual("description_manual")) \
                    or (k == "vendor_eff" and manual("vendor_manual")):
                continue
            out += cyr_leaks(v, where + "." + k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out += cyr_leaks(v, where + "[%d]" % i)
    elif isinstance(obj, str) and CYR.search(obj):
        out.append("%s = %s" % (where, obj[:80]))
    return out


con = core.connect()
con.execute("UPDATE plugins SET vendor='', vendor_manual='' WHERE name='Serum'")  # «Невідомо» теж має перекластись
con.commit()
con.close()
for path in ("/api/products?lang=en", "/api/plugins?lang=en", "/api/history?lang=en", "/api/status?lang=en"):
    s, b = req(path)
    leaks = cyr_leaks(json.loads(b))
    check(s == 200 and not leaks, "%s без кирилиці поза ручними полями %s" % (path, leaks[:5]))
prods_en = json.loads(req("/api/products?lang=en")[1])
check(any(p["vendor_eff"] == "Unknown" for p in prods_en), "«Невідомо» → Unknown")
check(any((p["source_auto"] or "").startswith("Probably:") for p in prods_en), "«Імовірно» → Probably")
rp_en = [p for p in prods_en if p["name"] == "Replika"][0]
check(rp_en["notes"] == "спільна", "ручні поля англійською не перекладаються")
prods_uk = json.loads(req("/api/products")[1])
check(any((p["source_auto"] or "").startswith("Імовірно") for p in prods_uk), "без lang усе українською, як було")
s, b = req("/api/scan?lang=en", "POST", {"mode": "bogus"})
check(s == 400 and json.loads(b)["error"] == "unknown mode", "помилка API англійською")
s, b = req("/api/export.csv?lang=en")
csv_en = b.decode("utf-8-sig")
check(csv_en.splitlines()[0].startswith("Product,Name,Vendor,Format"), "CSV англійською: заголовки")
check("Ефект" not in csv_en and "Effect (AU)" in csv_en and "Instrument" in csv_en, "CSV англійською: збережені фрази перекладено")
check(b"\xd0\x9f\xd1\x80\xd0\xbe\xd0\xb4\xd1\x83\xd0\xba\xd1\x82" in req("/api/export.csv")[1], "CSV без lang українською")

# Ліцензії: англійські підказки з типових правил; підказку, змінену власником, не перекладаємо
defaults = json.load(open(os.path.join(APP, "rules", "license_rules.json"), encoding="utf-8"))
cy_fields = [(r["label"], k) for r in defaults["rules"] for k in ("hint", "short", "label") if CYR.search(r.get(k, ""))]
missing_en = [x for x in cy_fields if not defaults["rules"][[r["label"] for r in defaults["rules"]].index(x[0])].get(x[1] + "_en")]
check(not missing_en, "у кожного українського hint/short/label є переклад %s" % missing_en[:5])
check(all(not CYR.search(r.get(k + "_en", "")) for r in defaults["rules"] for k in ("hint", "short", "label")), "переклади правил без кирилиці")
waves = [r for r in defaults["rules"] if r["label"] == "Waves"][0]
fab_r = [r for r in defaults["rules"] if r["label"] == "FabFilter"][0]
old = {"_comment": "x", "rules": [{k: v for k, v in r.items() if not k.endswith("_en")} for r in (waves, fab_r)]}
user = json.loads(json.dumps(old))
user["rules"][0]["hint"] = "Мій запис про Waves"
merged = core.merge_rules(old, {"_comment": "x", "rules": [waves, fab_r]}, user)
check(merged["rules"][0]["hint"] == "Мій запис про Waves" and merged["rules"][0].get("hint_en") == waves["hint_en"],
      "злиття доносить hint_en і зберігає правку власника")
check(merged["rules"][1]["short_en"] == fab_r["short_en"], "злиття доносить short_en")
ph = core.license_phrases(defaults, merged)
check(ph.get(fab_r["hint"]) == fab_r["hint_en"], "незмінена підказка має англійський варіант")
check("Мій запис про Waves" not in ph, "змінена власником підказка не перекладається")
user2 = json.loads(json.dumps(merged))
user2["rules"].append({"label": "Мій виробник", "vendors": ["my"], "hint": "Свій текст", "hint_en": "My own text"})
check(core.license_phrases(defaults, user2).get("Свій текст") == "My own text", "власний hint_en у правилі власника діє")

# Інтерфейс: словник обох мов
ui = open(os.path.join(APP, "ui.html"), encoding="utf-8").read()
m = re.search(r'<script type="application/json" id="i18n">(.*?)</script>', ui, re.S)
check(bool(m), "словник у ui.html")
if m:
    L = json.loads(m.group(1))
    check(set(L["uk"]) == set(L["en"]), "ключі однакові в uk і en (%s)" % sorted(set(L["uk"]) ^ set(L["en"]))[:5])
    bad_pl = [k for k in L["uk"] if isinstance(L["uk"][k], list) and not (len(L["uk"][k]) == 3 and len(L["en"].get(k, [])) == 2)]
    check(not bad_pl, "множина: три форми uk і дві en %s" % bad_pl[:5])
    ph_re = re.compile(r"\{\w+\}")
    flat = lambda v: " ".join(v) if isinstance(v, list) else v
    bad_ph = [k for k in L["uk"] if k in L["en"] and sorted(set(ph_re.findall(flat(L["uk"][k])))) != sorted(set(ph_re.findall(flat(L["en"][k]))))]
    check(not bad_ph, "підстановки {..} однакові в обох мовах %s" % bad_ph[:5])
    check(not [k for k, v in L["en"].items() if CYR.search(flat(v))], "англійський словник без кирилиці")
    used = set(re.findall(r'\bt[hn]?\("([\w.]+)"', ui)) | set(re.findall(r'data-i18n(?:-\w+)?="([\w.]+)"', ui))
    check(not (used - set(L["uk"])), "усі t(\"…\") є в словнику %s" % sorted(used - set(L["uk"]))[:5])
    code = ui[ui.index("<body>"):].replace(m.group(0), "")
    code = re.sub(r"(?m)^\s*//.*$|\s//\s.*$|/\*.*?\*/", "", code)
    stray = [ln.strip()[:70] for ln in code.splitlines() if CYR.search(ln)]
    check(not stray, "у розмітці й коді інтерфейсу немає тексту поза словником %s" % stray[:5])
srv.shutdown()

print("== Збірка застосунку: вбудований Python і лаунчер")
import subprocess
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "tools"))
import build_app

check(build_app.prune_python("lib/python3.13/tkinter/__init__.py"), "tkinter прибирається")
check(build_app.prune_python("lib/libtcl9.0.dylib"), "бібліотеки Tcl/Tk прибираються")
check(build_app.prune_python("lib/python3.13/lib-dynload/_tkinter.cpython-313-darwin.so"), "_tkinter.so прибирається")
check(build_app.prune_python("lib/python3.13/site-packages/pip/__init__.py"), "pip прибирається")
check(build_app.prune_python("lib/python3.13/encodings/__pycache__/utf_8.cpython-313.pyc"), "__pycache__ прибирається")
check(build_app.prune_python("include/python3.13/pyconfig.h"), "include прибирається")
check(build_app.prune_python("bin/pip3"), "зайві команди в bin прибираються")
check(not build_app.prune_python("bin/python3.13"), "бінарник python лишається")
check(not build_app.prune_python("bin/python3"), "посилання python3 лишається")
check(not build_app.prune_python("lib/python3.13/sqlite3/__init__.py"), "sqlite3 лишається")
check(not build_app.prune_python("lib/python3.13/http/server.py"), "http.server лишається")
check(not build_app.prune_python("lib/python3.13/lib-dynload/_dbm.cpython-313-darwin.so"), "інші модулі lib-dynload лишаються")

pyt = os.path.join(tmp, "pybuild")
MACHO = b"\xcf\xfa\xed\xfe" + b"\0" * 60
for arch in ("arm64", "x86_64"):
    r = os.path.join(pyt, arch)
    os.makedirs(os.path.join(r, "bin"))
    os.makedirs(os.path.join(r, "lib", "python3.13", "idlelib"))
    open(os.path.join(r, "bin", "python3.13"), "wb").write(MACHO + arch.encode())
    os.symlink("python3.13", os.path.join(r, "bin", "python3"))
    open(os.path.join(r, "lib", "python3.13", "os.py"), "w").write("# os " + arch)
    open(os.path.join(r, "lib", "python3.13", "idlelib", "x.py"), "w").write("")
lipo_calls = []


def fake_lipo(a, b, out):
    lipo_calls.append((a, b))
    open(out, "wb").write(b"UNIVERSAL")


dest = os.path.join(pyt, "out")
build_app.assemble_python(os.path.join(pyt, "arm64"), os.path.join(pyt, "x86_64"), dest, lipo=fake_lipo)
check(open(os.path.join(dest, "bin", "python3.13"), "rb").read() == b"UNIVERSAL", "Mach-O склеєно lipo")
check(len(lipo_calls) == 1 and lipo_calls[0][1].endswith(os.path.join("x86_64", "bin", "python3.13")),
      "lipo отримує пару arm64 + x86_64")
check(os.path.islink(os.path.join(dest, "bin", "python3")) and os.readlink(os.path.join(dest, "bin", "python3")) == "python3.13",
      "відносне посилання збережено")
check(open(os.path.join(dest, "lib", "python3.13", "os.py")).read() == "# os arm64", "звичайні файли копіюються")
check(not os.path.exists(os.path.join(dest, "lib", "python3.13", "idlelib")), "прибрані теки не копіюються")
check(build_app.macho_files(os.path.join(pyt, "arm64")) == [os.path.join(pyt, "arm64", "bin", "python3.13")],
      "Mach-O знаходяться за сигнатурою, посилання пропускаються")
os.remove(os.path.join(pyt, "x86_64", "bin", "python3.13"))
try:
    build_app.assemble_python(os.path.join(pyt, "arm64"), os.path.join(pyt, "x86_64"), dest + "2", lipo=fake_lipo)
    check(False, "немає пари x86_64 для Mach-O: помилка")
except build_app.BuildError:
    check(True, "немає пари x86_64 для Mach-O: помилка")


def launcher_pick(*cands):
    src = open(os.path.join(os.path.dirname(HERE), "desktop", "Plugius")).read()
    fn = src[src.index("pick_python() {"):]
    fn = fn[:fn.index("\n}\n") + 3]
    p = subprocess.run(["/bin/bash", "-c", fn + 'pick_python "$@"', "x"] + list(cands),
                       stdout=subprocess.PIPE, universal_newlines=True)
    return p.returncode, p.stdout.strip()


fakebin = os.path.join(tmp, "fakebin")
os.makedirs(fakebin)
emb, brew = os.path.join(fakebin, "embedded"), os.path.join(fakebin, "brew")
for f in (emb, brew):
    open(f, "w").write("#!/bin/sh\n")
    os.chmod(f, 0o755)
missing = os.path.join(fakebin, "missing")
check(launcher_pick(emb, brew) == (0, emb), "лаунчер бере вбудований Python першим")
check(launcher_pick(missing, brew) == (0, brew), "без вбудованого лаунчер бере наступний")
check(launcher_pick(missing)[0] != 0, "без жодного Python лаунчер повертає помилку")

print()
if fails:
    print("ПРОВАЛЕНО: %d" % len(fails))
    for f in fails:
        print(" -", f)
    sys.exit(1)
print("УСІ ТЕСТИ ПРОЙДЕНО")
shutil.rmtree(tmp, ignore_errors=True)
