// Plugius — десктопна оболонка: вікно WKWebView + локальний Python-сервер.
import Cocoa
import WebKit

let port = 8765
let baseURL = URL(string: "http://127.0.0.1:\(port)/")!

// Мова за системою: українська, якщо macOS українською, інакше англійська. Інтерфейс сторінки має власний перемикач
let systemLang = Locale.preferredLanguages.first ?? "en"
let isUk = systemLang.lowercased().hasPrefix("uk")
func L(_ uk: String, _ en: String) -> String { return isUk ? uk : en }

func page(_ text: String, detail: String = "") -> String {
    return """
    <html><head><meta charset="utf-8"><style>
    :root{color-scheme:light dark}
    body{font:15px -apple-system,system-ui;display:flex;height:100vh;margin:0;align-items:center;justify-content:center;flex-direction:column;background:Canvas;color:CanvasText}
    h2{font-size:22px;margin:0 0 8px} p{opacity:.65;max-width:520px;text-align:center;white-space:pre-wrap}
    </style></head><body><h2>\(text)</h2><p>\(detail)</p></body></html>
    """
}

final class AppDelegate: NSObject, NSApplicationDelegate, NSWindowDelegate, WKNavigationDelegate, WKUIDelegate, WKDownloadDelegate {
    var window: NSWindow!
    var web: WKWebView!
    var server: Process?
    var lastDownload: URL?

    func applicationDidFinishLaunching(_ notification: Notification) {
        buildMenu()
        let config = WKWebViewConfiguration()
        // navigator.language у WKWebView може не збігатися з мовою macOS, тож передаємо її сторінці явно
        let langJS = "window.plugiusSystemLang = \"\(systemLang.replacingOccurrences(of: "\"", with: ""))\";"
        config.userContentController.addUserScript(WKUserScript(source: langJS, injectionTime: .atDocumentStart, forMainFrameOnly: true))
        web = WKWebView(frame: .zero, configuration: config)
        web.customUserAgent = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15 PlugiusApp"
        web.navigationDelegate = self
        web.uiDelegate = self
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 1280, height: 820),
                          styleMask: [.titled, .closable, .miniaturizable, .resizable],
                          backing: .buffered, defer: false)
        window.title = "Plugius"
        window.minSize = NSSize(width: 900, height: 560)
        window.contentView = web
        window.delegate = self
        if !window.setFrameUsingName("PlugiusMain") { window.center() }
        window.setFrameAutosaveName("PlugiusMain")
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        web.loadHTMLString(page(L("Запуск…", "Starting…")), baseURL: nil)
        ping { alive in
            if !alive { self.startServer() }
            self.waitForServer(attempt: 0)
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { return true }
    func applicationWillTerminate(_ notification: Notification) { server?.terminate() }

    // MARK: сервер
    func ping(_ done: @escaping (Bool) -> Void) {
        var req = URLRequest(url: baseURL.appendingPathComponent("api/ping"))
        req.timeoutInterval = 1
        URLSession.shared.dataTask(with: req) { data, _, _ in
            let ok = data.flatMap { String(data: $0, encoding: .utf8) }?.contains("pluginvault") ?? false
            DispatchQueue.main.async { done(ok) }
        }.resume()
    }

    // Спершу вбудований Python, потім Homebrew, системний лише з Command Line Tools
    // (без них /usr/bin/python3 — заглушка, що пропонує їх встановити).
    func findPython() -> String? {
        let embedded = Bundle.main.resourceURL!.appendingPathComponent("python/bin/python3").path
        for p in [embedded, "/opt/homebrew/bin/python3", "/usr/local/bin/python3", "/usr/bin/python3"] {
            guard FileManager.default.isExecutableFile(atPath: p) else { continue }
            if p == "/usr/bin/python3" && !hasCommandLineTools() { continue }
            return p
        }
        return nil
    }

    func hasCommandLineTools() -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/xcode-select")
        p.arguments = ["-p"]
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    func startServer() {
        guard let py = findPython() else {
            web.loadHTMLString(page(L("Не знайдено Python 3", "Python 3 not found"), detail: L("Вбудований Python відсутній: завантажте застосунок заново.\nАбо відкрийте Термінал, виконайте xcode-select --install і запустіть Plugius ще раз.", "The built-in Python is missing: download the app again.\nOr open Terminal, run xcode-select --install and start Plugius again.")), baseURL: nil)
            return
        }
        let res = Bundle.main.resourceURL!.appendingPathComponent("app")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: py)
        p.arguments = [res.appendingPathComponent("pluginvault.py").path, "serve", "--no-browser"]
        p.currentDirectoryURL = res
        var env = ProcessInfo.processInfo.environment
        env["PLUGINVAULT_PORT"] = String(port)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        p.environment = env
        p.standardOutput = FileHandle.nullDevice
        p.standardError = FileHandle.nullDevice
        do { try p.run(); server = p } catch {
            web.loadHTMLString(page(L("Не вдалося запустити сервер", "Couldn't start the server"), detail: "\(error)"), baseURL: nil)
        }
    }

    func waitForServer(attempt: Int) {
        ping { alive in
            if alive {
                self.web.load(URLRequest(url: baseURL))
            } else if attempt < 60 {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.25) { self.waitForServer(attempt: attempt + 1) }
            } else {
                self.web.loadHTMLString(page(L("Сервер не відповідає", "The server isn't responding"), detail: L("Можливо, порт \(port) зайнятий іншою програмою.", "Port \(port) may be used by another app.")), baseURL: nil)
            }
        }
    }

    // MARK: навігація та завантаження
    func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction,
                 decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        if let url = navigationAction.request.url, let scheme = url.scheme, scheme.hasPrefix("http"),
           let host = url.host, host != "127.0.0.1", host != "localhost" {
            NSWorkspace.shared.open(url)
            decisionHandler(.cancel)
            return
        }
        decisionHandler(.allow)
    }

    func webView(_ webView: WKWebView, decidePolicyFor navigationResponse: WKNavigationResponse,
                 decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        if let http = navigationResponse.response as? HTTPURLResponse,
           let cd = http.value(forHTTPHeaderField: "Content-Disposition"), cd.lowercased().contains("attachment") {
            decisionHandler(.download)
        } else if !navigationResponse.canShowMIMEType {
            decisionHandler(.download)
        } else {
            decisionHandler(.allow)
        }
    }

    func webView(_ webView: WKWebView, navigationResponse: WKNavigationResponse, didBecome download: WKDownload) { download.delegate = self }
    func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) { download.delegate = self }

    func download(_ download: WKDownload, decideDestinationUsing response: URLResponse, suggestedFilename: String,
                  completionHandler: @escaping (URL?) -> Void) {
        let dir = FileManager.default.urls(for: .downloadsDirectory, in: .userDomainMask)[0]
        let ns = suggestedFilename as NSString
        let base = ns.deletingPathExtension, ext = ns.pathExtension
        var dest = dir.appendingPathComponent(suggestedFilename)
        var n = 1
        while FileManager.default.fileExists(atPath: dest.path) {
            dest = dir.appendingPathComponent(ext.isEmpty ? "\(base) \(n)" : "\(base) \(n).\(ext)")
            n += 1
        }
        lastDownload = dest
        completionHandler(dest)
    }

    func downloadDidFinish(_ download: WKDownload) {
        if let f = lastDownload { NSWorkspace.shared.activateFileViewerSelecting([f]) }
    }

    // MARK: JS-діалоги (confirm / alert)
    func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        let a = NSAlert(); a.messageText = message; a.addButton(withTitle: "OK"); a.runModal(); completionHandler()
    }

    func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String,
                 initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        let a = NSAlert(); a.messageText = message
        a.addButton(withTitle: "OK"); a.addButton(withTitle: L("Скасувати", "Cancel"))
        completionHandler(a.runModal() == .alertFirstButtonReturn)
    }

    // MARK: меню
    @objc func reloadPage() { web.reload() }

    func buildMenu() {
        let main = NSMenu()
        let appItem = NSMenuItem(); main.addItem(appItem)
        let appMenu = NSMenu(); appItem.submenu = appMenu
        appMenu.addItem(withTitle: L("Про Plugius", "About Plugius"), action: #selector(NSApplication.orderFrontStandardAboutPanel(_:)), keyEquivalent: "")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: L("Сховати Plugius", "Hide Plugius"), action: #selector(NSApplication.hide(_:)), keyEquivalent: "h")
        appMenu.addItem(.separator())
        appMenu.addItem(withTitle: L("Вийти з Plugius", "Quit Plugius"), action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")

        let editItem = NSMenuItem(); main.addItem(editItem)
        let edit = NSMenu(title: L("Редагування", "Edit")); editItem.submenu = edit
        edit.addItem(withTitle: L("Скасувати", "Undo"), action: Selector(("undo:")), keyEquivalent: "z")
        edit.addItem(withTitle: L("Повторити", "Redo"), action: Selector(("redo:")), keyEquivalent: "Z")
        edit.addItem(.separator())
        edit.addItem(withTitle: L("Вирізати", "Cut"), action: #selector(NSText.cut(_:)), keyEquivalent: "x")
        edit.addItem(withTitle: L("Копіювати", "Copy"), action: #selector(NSText.copy(_:)), keyEquivalent: "c")
        edit.addItem(withTitle: L("Вставити", "Paste"), action: #selector(NSText.paste(_:)), keyEquivalent: "v")
        edit.addItem(withTitle: L("Вибрати все", "Select All"), action: #selector(NSText.selectAll(_:)), keyEquivalent: "a")

        let viewItem = NSMenuItem(); main.addItem(viewItem)
        let view = NSMenu(title: L("Вигляд", "View")); viewItem.submenu = view
        let reload = NSMenuItem(title: L("Оновити сторінку", "Reload Page"), action: #selector(reloadPage), keyEquivalent: "r")
        reload.target = self
        view.addItem(reload)

        let winItem = NSMenuItem(); main.addItem(winItem)
        let win = NSMenu(title: L("Вікно", "Window")); winItem.submenu = win
        win.addItem(withTitle: L("Згорнути", "Minimize"), action: #selector(NSWindow.performMiniaturize(_:)), keyEquivalent: "m")
        win.addItem(withTitle: L("Закрити", "Close"), action: #selector(NSWindow.performClose(_:)), keyEquivalent: "w")
        NSApp.windowsMenu = win
        NSApp.mainMenu = main
    }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.regular)
app.run()
