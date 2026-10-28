// run_monitor_sweep.sh の進み具合を出す小さなウィンドウ (scripts/sweep_progress.sh が作って開く)。
// 引数 = 状態ファイル (key=value の行。sweep_progress.sh の sweep_status_write / sweep_status_set が書く)。
// 1 秒ごとに読み直すだけで、sweep には何もしない (閉じても sweep は止まらない)。
import AppKit

let statusPath = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : ""

/// 状態ファイルを読む。sim= の行 (実行中のセル "進み|相対パス") と、エラーの内容 (err= / errcell=) は別にまとめる
func readStatus() -> ([String: String], [(Double, String)], [(String, [String])])? {
    guard let s = try? String(contentsOfFile: statusPath, encoding: .utf8) else { return nil }
    var kv = [String: String]()
    var sims = [(Double, String)]()
    var errs = [(String, [String])]()
    for line in s.split(separator: "\n") {
        guard let i = line.firstIndex(of: "=") else { continue }
        let k = String(line[..<i]), v = String(line[line.index(after: i)...])
        if k == "sim" {
            let p = v.split(separator: "|", maxSplits: 1)
            if p.count == 2, let x = Double(p[0]) { sims.append((min(max(x, 0), 1), String(p[1]))) }
        } else if k == "err" || k == "errcell" {
            // err = シード|文、errcell = シード|セル|理由|ログの最後の行
            errs.append((k, v.split(separator: "|", maxSplits: k == "err" ? 1 : 3, omittingEmptySubsequences: false).map(String.init)))
        } else {
            kv[k] = v
        }
    }
    return (kv, sims, errs)
}

func hms(_ t: Int) -> String { String(format: "%d:%02d:%02d", t / 3600, (t % 3600) / 60, t % 60) }

/// セルの相対パス (avoid_low_reputation/judge_method3/n_payment12800/avg_pmt_amt=100/judge_count=10/p_0_001) を短くする
func shortCell(_ rel: String) -> String {
    var out = [String]()
    for part in rel.split(separator: "/") {
        if part.hasPrefix("judge_count=") || part == "avoid_low_reputation" || part == "no_defense" { continue }
        if part.hasPrefix("judge_") { out.append(String(part.dropFirst(6))) }
        else if part.hasPrefix("n_payment") { out.append("n=" + part.dropFirst(9)) }
        else if part.hasPrefix("avg_pmt_amt=") { out.append(part.dropFirst(12) + " sat") }
        else if part.hasPrefix("p_") { out.append("p=" + part.dropFirst(2).replacingOccurrences(of: "_", with: ".")) }
        else { out.append(String(part)) }
    }
    return out.joined(separator: "  ")
}

final class Controller: NSObject, NSApplicationDelegate {
    let width: CGFloat = 460
    let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 492, height: 320),
                          styleMask: [.titled, .closable, .miniaturizable], backing: .buffered, defer: false)
    let head = NSTextField(labelWithString: "読み込み中…")
    let seedText = NSTextField(labelWithString: "")
    let seedBar = NSProgressIndicator()
    let allText = NSTextField(labelWithString: "")
    let allBar = NSProgressIndicator()
    let simsTitle = NSTextField(labelWithString: "実行中のセル")
    // 実行中のセル / エラーの内容。エラーが多いときに全部読めるよう、スクロールできる文の欄にする
    let simsScroll = NSTextView.scrollableTextView()
    var simsText: NSTextView { simsScroll.documentView as! NSTextView }
    let mono = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
    let pin = NSButton(checkboxWithTitle: "いつも手前に出す", target: nil, action: nil)
    let doneButton = NSButton(title: "完了", target: nil, action: nil)   // 終わってから出す。押すとウィンドウを閉じる
    var finished = false

    func applicationDidFinishLaunching(_ n: Notification) {
        head.font = .boldSystemFont(ofSize: 15)
        simsTitle.font = .systemFont(ofSize: 11)
        simsTitle.textColor = .secondaryLabelColor
        simsText.font = mono
        simsText.isEditable = false
        simsText.isSelectable = true   // エラーの内容を写せるように
        simsText.drawsBackground = false
        simsText.textContainerInset = .zero
        simsText.textContainer?.lineFragmentPadding = 0
        simsScroll.drawsBackground = false
        simsScroll.borderType = .noBorder
        simsScroll.hasVerticalScroller = true
        simsScroll.autohidesScrollers = true
        for b in [seedBar, allBar] {
            b.isIndeterminate = false; b.minValue = 0; b.maxValue = 1; b.style = .bar
            b.widthAnchor.constraint(equalToConstant: width).isActive = true
        }
        for t in [head, seedText, allText] {
            t.lineBreakMode = .byTruncatingTail
            t.widthAnchor.constraint(equalToConstant: width).isActive = true
        }
        // 実行中のセルは最大 8 行 (sweep の並列数)。行数が変わってもウィンドウの大きさが変わらないようにとっておく
        simsScroll.widthAnchor.constraint(equalToConstant: width).isActive = true
        simsScroll.heightAnchor.constraint(equalToConstant: ceil(8 * NSLayoutManager().defaultLineHeight(for: mono)) + 2).isActive = true
        pin.target = self
        pin.action = #selector(togglePin)
        pin.state = .on
        doneButton.target = self
        doneButton.action = #selector(closeWindow)
        doneButton.bezelStyle = .rounded
        doneButton.keyEquivalent = "\r"
        doneButton.isHidden = true
        // 下の段: 左に「いつも手前に出す」、右に完了のボタン。ボタンが出てもウィンドウの大きさが変わらないよう、隠している間も場所はとっておく
        let bottom = NSStackView()
        bottom.orientation = .horizontal
        bottom.detachesHiddenViews = false
        bottom.addView(pin, in: .leading)
        bottom.addView(doneButton, in: .trailing)
        bottom.widthAnchor.constraint(equalToConstant: width).isActive = true
        let stack = NSStackView(views: [head, seedText, seedBar, allText, allBar, simsTitle, simsScroll, bottom])
        stack.orientation = .vertical
        stack.alignment = .leading
        stack.spacing = 6
        stack.setCustomSpacing(12, after: seedBar)
        stack.setCustomSpacing(12, after: allBar)
        stack.setCustomSpacing(12, after: simsScroll)
        stack.edgeInsets = NSEdgeInsets(top: 14, left: 16, bottom: 14, right: 16)
        window.contentView = stack
        window.setContentSize(stack.fittingSize)
        window.title = "sweep の進み具合"
        window.level = .floating
        window.isReleasedWhenClosed = false
        window.center()
        window.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
        refresh()
        Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in self?.refresh() }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ s: NSApplication) -> Bool { true }

    @objc func togglePin() { window.level = pin.state == .on ? .floating : .normal }

    @objc func closeWindow() { window.close() }

    /// 下の欄の文を変える (同じなら触らない。毎秒入れ直すと、読んでいる途中のスクロールや選択が戻るので)
    func setSims(_ text: String) {
        guard simsText.string != text else { return }
        simsText.string = text
        simsText.font = mono
        simsText.textColor = .labelColor
    }

    func refresh() {
        guard let (kv, sims, errs) = readStatus() else { head.stringValue = "状態ファイルを読めない: \(statusPath)"; return }
        func int(_ k: String) -> Int { Int(kv[k] ?? "") ?? 0 }
        let now = Int(Date().timeIntervalSince1970)
        var state = kv["state"] ?? ""
        let seed = kv["seed"] ?? "", idx = max(int("seed_index"), 1), cnt = max(int("seed_count"), 1)
        let done = int("done"), total = int("total"), failed = int("failed")
        let runStart = int("run_start") > 0 ? int("run_start") : now
        let pid = Int32(int("pid"))
        let ended = ["done", "failed"].contains(state)
        // 終わったと書く前に sweep のプロセスがいなくなったら、途中で止まったとみなす
        if !ended && pid > 0 && kill(pid, 0) != 0 { state = "stopped" }
        if let out = kv["out"], !out.isEmpty { window.title = "sweep の進み具合 — " + (out as NSString).lastPathComponent }

        let seedLabel = cnt > 1 ? "シード \(seed) (\(idx) / \(cnt))" : "シード \(seed)"
        var color = NSColor.labelColor
        switch state {
        case "starting": head.stringValue = "準備中  " + seedLabel
        case "running": head.stringValue = "走行中  " + seedLabel
        case "transfer": head.stringValue = "NAS へ移している  " + seedLabel
        case "summary": head.stringValue = "集計中 (results_summary.csv を作っている)  " + seedLabel
        case "seed_done": head.stringValue = "シード \(seed) 完了 · 次のシードの準備中"
        case "seed_failed": head.stringValue = "シード \(seed) がエラーで終わった (rc=\(kv["rc"] ?? "?")) · 次のシードへ"; color = .systemRed
        case "done":
            // 終わったが失敗したセルがあるときは橙 (複数シードのときは親が全シードの合計を書く)
            let failedCells = kv["failed_total"] != nil ? int("failed_total") : failed
            head.stringValue = "完了 (全 \(cnt) シード)" + (failedCells > 0 ? " · 失敗したセル \(failedCells) 個" : "")
            color = failedCells > 0 ? .systemOrange : .systemGreen
        case "failed": head.stringValue = "エラーで終わった (rc=\(kv["rc"] ?? "?"))"; color = .systemRed
        case "stopped": head.stringValue = "止まった (sweep のプロセスがない)"; color = .systemRed
        default: head.stringValue = state
        }
        if let fs = kv["failed_seeds"], !fs.isEmpty { head.stringValue += "  · 失敗したシード \(fs)"; color = .systemRed }
        head.textColor = color

        // 実行中のセルの途中の進みも足して、バーと残り時間をなめらかにする
        let partial = sims.reduce(0) { $0 + $1.0 }
        var fSeed = total > 0 ? min((Double(done) + partial) / Double(total), 1) : 0
        if ["transfer", "summary", "seed_done", "seed_failed", "done"].contains(state) { fSeed = 1 }
        var fAll = (Double(idx - 1) + fSeed) / Double(cnt)
        if state == "done" { fAll = 1 }
        seedBar.doubleValue = fSeed
        allBar.doubleValue = fAll
        let pct = total > 0 ? 100 * Double(done) / Double(total) : 0
        seedText.stringValue = total == 0 ? "このシード: セルはまだない"
            : String(format: "このシード: %d / %d セル (%.1f%%) · 失敗 %d", done, total, pct, failed)
            + (kv["nas"] == "1" ? " · NAS へ \(int("nas_ok")) (失敗 \(int("nas_ng")))" : (kv["nas"] == nil ? "" : " · NAS なし (ローカルだけ)"))
        if ended || state == "stopped" {
            let last = int("updated") > 0 ? int("updated") : now
            allText.stringValue = String(format: "全体: %.1f%% · かかった時間 %@", fAll * 100, hms(max(last - runStart, 0)))
        } else {
            let elapsed = max(now - runStart, 0)
            var s = String(format: "全体: %.1f%% · 経過 %@", fAll * 100, hms(elapsed))
            if fAll >= 0.01 {
                let eta = Int(Double(elapsed) * (1 - fAll) / fAll)
                let f = DateFormatter(); f.dateFormat = "HH:mm"
                s += " · 残り 約 \(hms(eta)) (\(f.string(from: Date(timeIntervalSinceNow: Double(eta)))) ごろ)"
            }
            allText.stringValue = s
        }
        if !errs.isEmpty {
            // エラーの内容: sweep が止まった理由・失敗したセル (理由とログの最後の行)・NAS へ移せなかったもの
            simsTitle.stringValue = "エラーの内容"
            simsTitle.textColor = .systemRed
            setSims(errs.map { (k, f) -> String in
                let who = cnt > 1 && !f[0].isEmpty ? "シード \(f[0]) · " : ""
                if k == "errcell" && f.count == 4 { return who + shortCell(f[1]) + ": " + f[2] + "\n    " + f[3] }
                return who + (f.count > 1 ? f[1] : f[0])
            }.joined(separator: "\n"))
        } else {
            simsTitle.stringValue = "実行中のセル"
            simsTitle.textColor = .secondaryLabelColor
            let top = state == "stopped" ? [] : sims.sorted { $0.0 > $1.0 }.prefix(8)
            setSims(top.isEmpty ? "—" : top.map { String(format: "%5.1f%%  ", $0.0 * 100) + shortCell($0.1) }.joined(separator: "\n"))
        }

        // 終わったら一度だけ前に出し、閉じるボタンを出す (完了なら「完了」、エラーや止まったときは「閉じる」)
        if (ended || state == "stopped") && !finished {
            finished = true
            doneButton.title = state == "done" ? "完了" : "閉じる"
            doneButton.isHidden = false
            window.orderFrontRegardless()
        }
    }
}

let app = NSApplication.shared
let controller = Controller()
app.delegate = controller
app.setActivationPolicy(.accessory)
app.run()
