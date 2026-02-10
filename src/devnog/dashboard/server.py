"""Localhost HTTP server for the DevNog dashboard."""

from __future__ import annotations

import json
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from devnog.core.config import load_config
from devnog.fix.engine import FixEngine
from devnog.scanner.engine import Scanner


class DashboardServer:
    """Minimal HTTP server serving the dashboard."""

    def __init__(self, project_path: Path, port: int = 7654):
        self.project_path = project_path
        self.port = port
        self.config = load_config(project_path)

    def start(self, open_browser: bool = True):
        """Start the dashboard server."""
        handler = _make_handler(self.project_path, self.config)
        server = HTTPServer(("127.0.0.1", self.port), handler)

        if open_browser:
            webbrowser.open(f"http://localhost:{self.port}")

        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.shutdown()


def _make_handler(project_path: Path, config):
    """Create a request handler class with project context."""

    class DashboardHandler(BaseHTTPRequestHandler):
        """HTTP request handler for the DevNog dashboard API and UI."""

        def log_message(self, format, *args):
            pass  # Suppress default logging

        def do_GET(self):
            parsed = urlparse(self.path)
            path = parsed.path

            if path == "/" or path == "":
                self._serve_html()
            elif path == "/api/scan":
                self._api_scan()
            elif path == "/api/qa":
                self._api_qa()
            elif path == "/api/runtime":
                self._api_runtime()
            elif path == "/api/history":
                self._api_history()
            else:
                self._send_json({"error": "Not found"}, 404)

        def do_POST(self):
            parsed = urlparse(self.path)
            path = parsed.path

            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length) if content_length else b""

            if path == "/api/fix":
                self._api_fix(body)
            elif path == "/api/apply":
                self._api_apply(body)
            elif path == "/api/undo":
                self._api_undo(body)
            elif path == "/api/scan/url":
                self._api_scan_url(body)
            else:
                self._send_json({"error": "Not found"}, 404)

        def _serve_html(self):
            html = _get_dashboard_html()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html.encode())))
            self.end_headers()
            self.wfile.write(html.encode())

        def _api_scan(self):
            scanner = Scanner(project_path, config)
            report = scanner.scan()
            self._send_json(_report_to_json(report))

        def _api_qa(self):
            try:
                from devnog.qa.engine import QAGate
                gate = QAGate(project_path)
                verdict = gate.evaluate()
                self._send_json({
                    "verdict": verdict.verdict,
                    "score": verdict.score,
                    "passed": [_finding_to_json(f) for f in verdict.passed_checks],
                    "warnings": [_finding_to_json(f) for f in verdict.warnings],
                    "failures": [_finding_to_json(f) for f in verdict.failures],
                })
            except Exception as e:
                self._send_json({"error": str(e)}, 500)

        def _api_runtime(self):
            try:
                from devnog.capture.store import CaptureStore
                store = CaptureStore(project_path)
                captures = store.get_recent(limit=50)
                self._send_json({
                    "captures": [
                        {
                            "id": str(c.id),
                            "function": c.function_name,
                            "error_type": c.error_type,
                            "error_message": c.error_message,
                            "file": str(c.file_path),
                            "line": c.line_number,
                            "occurrences": c.occurrence_count,
                            "timestamp": str(c.timestamp),
                        }
                        for c in captures
                    ]
                })
            except Exception:
                self._send_json({"captures": []})

        def _api_history(self):
            from devnog.fix.undo import UndoManager
            manager = UndoManager(project_path)
            entries = manager.list_undoable()
            self._send_json({
                "entries": [
                    {
                        "finding_id": e.finding_id,
                        "file": str(e.file),
                        "timestamp": e.timestamp,
                    }
                    for e in entries
                ]
            })

        def _api_fix(self, body: bytes):
            data = json.loads(body) if body else {}
            finding_id = data.get("finding_id", "")

            scanner = Scanner(project_path, config)
            report = scanner.scan()
            finding = next((f for f in report.findings if f.check_id == finding_id), None)

            if not finding:
                self._send_json({"error": f"Finding {finding_id} not found"}, 404)
                return

            engine = FixEngine(project_path, config)
            proposal = engine.generate_fix(finding)

            if not proposal:
                self._send_json({"error": "No fix available", "suggestion": finding.suggestion})
                return

            self._send_json({
                "finding_id": proposal.finding_id,
                "description": proposal.description,
                "diff": proposal.diff,
                "file": str(proposal.file),
                "line_start": proposal.line_start,
                "confidence": proposal.confidence,
                "confidence_score": proposal.confidence_score,
                "requires_review": proposal.requires_review,
                "manual_steps": proposal.manual_steps,
                "side_effects": proposal.side_effects,
                "new_code": proposal.new_code,
                "original_code": proposal.original_code,
            })

        def _api_apply(self, body: bytes):
            data = json.loads(body) if body else {}
            finding_id = data.get("finding_id", "")

            scanner = Scanner(project_path, config)
            report = scanner.scan()
            finding = next((f for f in report.findings if f.check_id == finding_id), None)

            if not finding:
                self._send_json({"error": f"Finding {finding_id} not found"}, 404)
                return

            engine = FixEngine(project_path, config)
            proposal = engine.generate_fix(finding)

            if not proposal:
                self._send_json({"error": "No fix available"}, 400)
                return

            result = engine.apply_fix(proposal)

            # Rescan for new score
            new_report = scanner.scan()

            self._send_json({
                "success": result.success,
                "message": result.message,
                "new_score": new_report.overall_score,
                "old_score": report.overall_score,
            })

        def _api_undo(self, body: bytes):
            data = json.loads(body) if body else {}
            finding_id = data.get("finding_id", "")

            engine = FixEngine(project_path, config)
            result = engine.undo_fix(finding_id)

            self._send_json({
                "success": result.success,
                "message": result.message,
            })

        def _api_scan_url(self, body: bytes):
            import asyncio
            from devnog.core.input_resolver import InputResolver

            data = json.loads(body) if body else {}
            url = data.get("url", "")

            resolver = InputResolver()
            try:
                resolved = asyncio.run(resolver.resolve(url))
                scanner = Scanner(resolved.path, config)
                report = scanner.scan()
                result = _report_to_json(report)
                result["read_only"] = True
                asyncio.run(resolver.cleanup(resolved))
                self._send_json(result)
            except Exception as e:
                self._send_json({"error": str(e)}, 400)

        def _send_json(self, data: dict, status: int = 200):
            body = json.dumps(data, default=str).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return DashboardHandler


def _finding_to_json(f) -> dict:
    return {
        "check_id": f.check_id,
        "category": f.category.value,
        "severity": f.severity.value,
        "message": f.message,
        "file": str(f.file) if f.file else None,
        "line": f.line,
        "fix_type": f.fix_type.value,
        "suggestion": f.suggestion,
    }


def _report_to_json(report) -> dict:
    return {
        "overall_score": report.overall_score,
        "total_lines": report.total_lines,
        "total_files": report.total_files,
        "category_scores": {
            k: {"score": v.score, "findings_count": len(v.findings)}
            for k, v in report.category_scores.items()
        },
        "findings": [_finding_to_json(f) for f in report.findings],
        "auto_fixable": report.auto_fixable_count,
        "ai_fixable": report.ai_fixable_count,
        "manual": report.manual_count,
    }


def _get_dashboard_html() -> str:
    """Return the embedded dashboard HTML."""
    # Try to load from template file first
    template_path = Path(__file__).parent / "template.html"
    if template_path.exists():
        return template_path.read_text()

    # Fallback to embedded HTML
    return _EMBEDDED_HTML


_EMBEDDED_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DevNog Dashboard</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }
.header { background: #161b22; border-bottom: 1px solid #30363d; padding: 16px 24px; display: flex; justify-content: space-between; align-items: center; }
.header h1 { font-size: 20px; color: #58a6ff; }
.tabs { display: flex; gap: 8px; background: #161b22; padding: 0 24px; border-bottom: 1px solid #30363d; }
.tab { padding: 12px 16px; cursor: pointer; border-bottom: 2px solid transparent; color: #8b949e; }
.tab:hover { color: #c9d1d9; }
.tab.active { color: #58a6ff; border-bottom-color: #58a6ff; }
.content { max-width: 1000px; margin: 0 auto; padding: 24px; }
.score-card { text-align: center; padding: 32px; background: #161b22; border-radius: 12px; margin-bottom: 24px; border: 1px solid #30363d; }
.score-number { font-size: 72px; font-weight: bold; }
.score-label { font-size: 14px; color: #8b949e; margin-top: 8px; }
.categories { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }
.category-card { background: #161b22; padding: 16px; border-radius: 8px; border: 1px solid #30363d; }
.category-name { font-size: 12px; color: #8b949e; text-transform: uppercase; letter-spacing: 1px; }
.category-score { font-size: 24px; font-weight: bold; margin: 8px 0; }
.bar { height: 4px; background: #21262d; border-radius: 2px; margin-top: 8px; }
.bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s; }
.findings { background: #161b22; border-radius: 12px; border: 1px solid #30363d; overflow: hidden; }
.finding { display: flex; align-items: center; padding: 12px 16px; border-bottom: 1px solid #21262d; gap: 12px; }
.finding:last-child { border-bottom: none; }
.severity { width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }
.severity.critical { background: #f85149; }
.severity.warning { background: #d29922; }
.severity.info { background: #58a6ff; }
.finding-id { font-family: monospace; font-weight: bold; min-width: 70px; color: #8b949e; }
.finding-msg { flex: 1; }
.finding-loc { font-family: monospace; font-size: 12px; color: #8b949e; }
.fix-btn { padding: 4px 12px; background: #238636; color: white; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; }
.fix-btn:hover { background: #2ea043; }
.fix-btn.fix-all { padding: 8px 20px; font-size: 14px; }
.fix-btn:disabled { background: #21262d; color: #484f58; cursor: not-allowed; }
.modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 100; justify-content: center; align-items: center; }
.modal-overlay.active { display: flex; }
.modal { background: #161b22; border: 1px solid #30363d; border-radius: 12px; max-width: 700px; width: 90%; max-height: 80vh; overflow-y: auto; padding: 24px; }
.modal h3 { margin-bottom: 16px; }
.diff { font-family: monospace; font-size: 13px; background: #0d1117; padding: 16px; border-radius: 8px; margin: 16px 0; white-space: pre-wrap; overflow-x: auto; }
.diff-add { color: #3fb950; }
.diff-del { color: #f85149; }
.modal-actions { display: flex; gap: 8px; margin-top: 16px; }
.btn { padding: 8px 16px; border-radius: 6px; border: none; cursor: pointer; font-size: 14px; }
.btn-apply { background: #238636; color: white; }
.btn-skip { background: #21262d; color: #c9d1d9; }
.btn-close { background: #21262d; color: #c9d1d9; }
.loading { text-align: center; padding: 40px; color: #8b949e; }
.actions-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
.scan-input { display: flex; gap: 8px; margin-bottom: 16px; }
.scan-input input { flex: 1; padding: 8px 12px; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #c9d1d9; }
.success { color: #3fb950; }
.error { color: #f85149; }
.confidence { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; }
.confidence.high { background: #238636; color: white; }
.confidence.medium { background: #9e6a03; color: white; }
.confidence.low { background: #da3633; color: white; }
</style>
</head>
<body>
<div class="header">
    <h1>DevNog Dashboard</h1>
    <span id="status" class="loading">Loading...</span>
</div>
<div class="tabs">
    <div class="tab active" onclick="showTab('report', this)">Report Card</div>
    <div class="tab" onclick="showTab('qa', this)">QA Gate</div>
    <div class="tab" onclick="showTab('runtime', this)">Runtime</div>
    <div class="tab" onclick="showTab('history', this)">History</div>
</div>
<div class="content" id="main-content"></div>

<div class="modal-overlay" id="fix-modal">
    <div class="modal">
        <h3 id="modal-title">Fix Preview</h3>
        <div id="modal-confidence"></div>
        <p id="modal-desc"></p>
        <div class="diff" id="modal-diff"></div>
        <div id="modal-steps"></div>
        <div id="modal-effects"></div>
        <div class="modal-actions">
            <button class="btn btn-apply" id="modal-apply" onclick="applyFix()">Apply</button>
            <button class="btn btn-skip" onclick="closeModal()">Skip</button>
        </div>
    </div>
</div>

<script>
let currentData = null;
let currentFixId = null;

async function api(path, method='GET', body=null) {
    const opts = { method };
    if (body) { opts.body = JSON.stringify(body); opts.headers = {'Content-Type':'application/json'}; }
    const r = await fetch('/api/' + path, opts);
    return r.json();
}

function scoreColor(s) { return s >= 80 ? '#3fb950' : s >= 60 ? '#d29922' : '#f85149'; }

async function loadScan() {
    const c = document.getElementById('main-content');
    c.innerHTML = '<div class="loading">Scanning...</div>';
    currentData = await api('scan');
    document.getElementById('status').textContent = 'Score: ' + currentData.overall_score + '/100';
    document.getElementById('status').style.color = scoreColor(currentData.overall_score);
    renderReport(currentData);
}

function renderReport(data) {
    const c = document.getElementById('main-content');
    let html = '<div class="score-card"><div class="score-number" style="color:'+scoreColor(data.overall_score)+'">'+data.overall_score+'</div><div class="score-label">Overall Health Score</div></div>';

    html += '<div class="categories">';
    for (const [key, val] of Object.entries(data.category_scores || {})) {
        const color = scoreColor(val.score);
        html += '<div class="category-card"><div class="category-name">'+key.replace('_',' ')+'</div><div class="category-score" style="color:'+color+'">'+val.score+'</div><div class="bar"><div class="bar-fill" style="width:'+val.score+'%;background:'+color+'"></div></div></div>';
    }
    html += '</div>';

    html += '<div class="actions-bar"><span>'+data.findings.length+' issues ('+data.auto_fixable+' auto-fixable)</span><button class="fix-btn fix-all" onclick="fixAll()">Fix All Safe</button></div>';

    html += '<div class="scan-input"><input type="text" id="scan-url" placeholder="GitHub URL to scan..."><button class="fix-btn" onclick="scanUrl()">Scan URL</button></div>';

    html += '<div class="findings">';
    for (const f of data.findings) {
        html += '<div class="finding"><div class="severity '+f.severity+'"></div><span class="finding-id">'+f.check_id+'</span><span class="finding-msg">'+f.message+'</span><span class="finding-loc">'+(f.file||'')+':'+(f.line||'')+'</span><button class="fix-btn" onclick="showFix(\\''+f.check_id+'\\')">FIX</button></div>';
    }
    html += '</div>';
    c.innerHTML = html;
}

async function showFix(id) {
    currentFixId = id;
    const data = await api('fix', 'POST', {finding_id: id});
    if (data.error) { alert(data.error + (data.suggestion ? '\\n' + data.suggestion : '')); return; }
    document.getElementById('modal-title').textContent = 'Fix Preview - ' + id;
    document.getElementById('modal-desc').textContent = data.description || '';

    let confHtml = '<span class="confidence '+data.confidence+'">'+data.confidence.toUpperCase()+'</span>';
    document.getElementById('modal-confidence').innerHTML = confHtml;

    let diffHtml = '';
    for (const line of (data.diff||'').split('\\n')) {
        if (line.startsWith('+')) diffHtml += '<span class="diff-add">'+line+'</span>\\n';
        else if (line.startsWith('-')) diffHtml += '<span class="diff-del">'+line+'</span>\\n';
        else diffHtml += line + '\\n';
    }
    document.getElementById('modal-diff').innerHTML = diffHtml;

    let stepsHtml = '';
    if (data.manual_steps && data.manual_steps.length) {
        stepsHtml = '<p style="margin-top:12px;color:#d29922">Manual steps:</p><ul>';
        data.manual_steps.forEach(s => stepsHtml += '<li>'+s+'</li>');
        stepsHtml += '</ul>';
    }
    document.getElementById('modal-steps').innerHTML = stepsHtml;

    let effectsHtml = '';
    if (data.side_effects && data.side_effects.length) {
        effectsHtml = '<p style="margin-top:12px;color:#d29922">Side effects:</p><ul>';
        data.side_effects.forEach(s => effectsHtml += '<li>'+s+'</li>');
        effectsHtml += '</ul>';
    }
    document.getElementById('modal-effects').innerHTML = effectsHtml;

    document.getElementById('fix-modal').classList.add('active');
}

async function applyFix() {
    if (!currentFixId) return;
    const data = await api('apply', 'POST', {finding_id: currentFixId});
    closeModal();
    if (data.success) {
        document.getElementById('status').textContent = 'Score: ' + data.new_score + '/100 (+' + (data.new_score - data.old_score) + ')';
        await loadScan();
    } else {
        alert('Fix failed: ' + data.message);
    }
}

async function fixAll() {
    if (!currentData) return;
    for (const f of currentData.findings) {
        if (f.fix_type === 'rule_based') {
            await api('apply', 'POST', {finding_id: f.check_id});
        }
    }
    await loadScan();
}

async function scanUrl() {
    const url = document.getElementById('scan-url').value;
    if (!url) return;
    document.getElementById('main-content').innerHTML = '<div class="loading">Cloning and scanning...</div>';
    const data = await api('scan/url', 'POST', {url});
    if (data.error) { alert(data.error); await loadScan(); return; }
    data.read_only = true;
    renderReport(data);
}

function closeModal() { document.getElementById('fix-modal').classList.remove('active'); }

function showTab(tab, el) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    el.classList.add('active');
    if (tab === 'report') loadScan();
    else if (tab === 'qa') loadQA();
    else if (tab === 'runtime') loadRuntime();
    else if (tab === 'history') loadHistory();
}

async function loadQA() {
    const c = document.getElementById('main-content');
    c.innerHTML = '<div class="loading">Running QA checks...</div>';
    const data = await api('qa');
    let html = '<div class="score-card"><div class="score-number" style="color:'+scoreColor(data.score)+'">'+data.verdict+'</div><div class="score-label">'+data.score+'/100</div></div>';
    html += '<div class="findings">';
    for (const f of (data.passed||[])) html += '<div class="finding"><div class="severity" style="background:#3fb950"></div><span class="finding-msg">PASS: '+f.message+'</span></div>';
    for (const f of (data.warnings||[])) html += '<div class="finding"><div class="severity warning"></div><span class="finding-id">'+f.check_id+'</span><span class="finding-msg">'+f.message+'</span><button class="fix-btn" onclick="showFix(\\''+f.check_id+'\\')">FIX</button></div>';
    for (const f of (data.failures||[])) html += '<div class="finding"><div class="severity critical"></div><span class="finding-id">'+f.check_id+'</span><span class="finding-msg">'+f.message+'</span><button class="fix-btn" onclick="showFix(\\''+f.check_id+'\\')">FIX</button></div>';
    html += '</div>';
    c.innerHTML = html;
}

async function loadRuntime() {
    const c = document.getElementById('main-content');
    const data = await api('runtime');
    if (!data.captures || !data.captures.length) { c.innerHTML = '<div class="loading">No runtime captures. Add @capture or @healable decorators.</div>'; return; }
    let html = '<h2 style="margin-bottom:16px">Runtime Failures</h2><div class="findings">';
    for (const cap of data.captures) html += '<div class="finding"><div class="severity critical"></div><span class="finding-id">'+cap.error_type+'</span><span class="finding-msg">'+cap.function+' - '+cap.error_message+'</span><span class="finding-loc">'+cap.occurrences+' times</span></div>';
    html += '</div>';
    c.innerHTML = html;
}

async function loadHistory() {
    const c = document.getElementById('main-content');
    const data = await api('history');
    let html = '<h2 style="margin-bottom:16px">Fix History</h2>';
    if (!data.entries || !data.entries.length) { html += '<div class="loading">No fix history yet.</div>'; c.innerHTML = html; return; }
    html += '<div class="findings">';
    for (const e of data.entries) html += '<div class="finding"><span class="finding-id">'+e.finding_id+'</span><span class="finding-msg">'+e.file+'</span><span class="finding-loc">'+e.timestamp+'</span><button class="fix-btn" onclick="undoFix(\\''+e.finding_id+'\\')">UNDO</button></div>';
    html += '</div>';
    c.innerHTML = html;
}

async function undoFix(id) {
    await api('undo', 'POST', {finding_id: id});
    loadHistory();
    loadScan();
}

loadScan();
</script>
</body>
</html>"""
