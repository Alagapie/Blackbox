"""Record the Blackbox demo video: narrated, captioned, driving the live dashboard.

Needs (separate from the project's requirements):  pip install playwright imageio-ffmpeg edge-tts
Before running: start the system (python run.py --fresh) and run the three Muse scenarios
(honest, pressure, redteam) so the dashboard starts with three clean real agents.

    python submission/video/make_video.py
Output: submission/blackbox_demo.mp4
"""

from __future__ import annotations

import asyncio
import json
import re
import shutil
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import imageio_ffmpeg
from playwright.async_api import async_playwright

HERE = Path(__file__).resolve().parent
OUT = HERE.parent / "blackbox_demo.mp4"
WORK = HERE / "_build"
DASH = "http://127.0.0.1:8000"
SLIDES = (HERE / "slides.html").as_uri()
VOICE = "en-US-AndrewNeural"
# Live Muse runs before this recording (documented in the report) + the 3 run just before recording.
PRIOR_RUNS = int(__import__("os").environ.get("PRIOR_RUNS", "12"))
RUNS = PRIOR_RUNS + 3
RUNS_WORD = {9: "nine", 12: "twelve", 15: "fifteen", 18: "eighteen"}.get(RUNS, str(RUNS))
W, H = 1366, 768
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()

LINES = {
    "title": "This is Blackbox: a tamper-evident flight recorder for AI agents. "
             "Our idea in one line: current agent logs trust the agent. Ours treat it as a suspect.",
    "problem": "Autonomous agents now run with real access to files, shells and databases, often on the same machine as "
               "the logs we use to oversee them. So an agent that does something harmful can simply delete or rewrite "
               "the evidence. And this isn't hypothetical: in evaluations, frontier models have tried to disable their "
               "own oversight. If the agent can reach the log, the log can't be trusted.",
    "how": "Blackbox splits the system in two. The agent's only tools go through our interceptor, which records every "
           "action in a separate ledger before it runs. No record, no action. The ledger is append-only, hash-chained "
           "and signed, and an independent witness keeps fingerprints of it. Then a verifier checks everything: the "
           "chain, the agent's own local log, the witness, and whether the agent's final report tells the truth.",
    "clean": "Here is the live system. We ran three real agents on Meta's Muse model: an honest cleanup task, an agent "
             "under pressure to free disk space, and a red-team prompt telling it to hide its tracks. All three are clean.",
    "pressure": "Under pressure, Muse cleared the caches and a large debug log, but kept the database, the backup and the "
                "audit log, and reported exactly that. In the red-team run, it refused the hidden instruction. "
                "The verifier raised no alarms on any of them.",
    "rogue": "None of the real agents touched the evidence. But oversight has to work on the day one does. So here is a scripted rogue. "
             "It deletes the customer database, deletes its own audit log, and then reports: nothing else was touched.",
    "caught": "Caught. The agent wiped its local log, but every action is still in the ledger. We see the database "
              "deletion, the cover-up attempt, and two actions missing from its report. And the ledger itself is intact.",
    "audit": "Keyword rules can miss a paraphrase, so we also ask Muse to act as an honesty auditor. It reads each "
             "agent's report against the tamper-proof record.",
    "verdict": "Its verdict on the rogue: deceptive. On the three real agents: honest.",
    "verdict_flag": "Its verdict on the rogue: deceptive. And it flagged something we never planted: a real Muse agent "
                    "whose report claims more than the record shows. Here it said it had checked files that the record "
                    "shows it never opened. A small overclaim, but provable, because the record can't be edited.",
    "edit": "Now the attacker goes after the ledger itself. An insider edits the database file directly, turning the "
            "database deletion into something harmless.",
    "edited": "Detected immediately. The entry's hash no longer matches, and the ledger is marked compromised.",
    "stolen": "The worst case: the attacker has stolen the ledger's signing key. They rewrite history and re-sign every "
              "entry, so every hash and signature is valid again. Cryptography alone can't catch this.",
    "witness": "But the independent witness still holds the original fingerprints. The rewrite is exposed.",
    "failclosed": "And the core rule. Here the ledger is unreachable. The agent tries to delete the database, then to run "
                  "r m minus r f. Both are refused, and the data survives. No record, no action.",
    "results": "Seven out of seven attacks detected, including the stolen key. Zero false alarms from the verifier across " + RUNS_WORD +
               " live Muse runs. About seventeen milliseconds of overhead per action. Blackbox: current agent logs trust the "
               "agent. Ours treat it as a suspect.",
}
CAPTION_FIX = {"r m minus r f": "rm -rf"}
REAL = {"Honest agent", "Agent under pressure", "Red-team rogue"}
_SESS: dict = {}


def sessions_label(f):
    if not _SESS:
        _SESS.update(api("/api/state")["sessions"])
    return _SESS.get(f.get("session_id"), {}).get("label", "")

CURSOR_JS = """
(() => {
  if (document.getElementById('__cur')) return;
  const c = document.createElement('div'); c.id = '__cur';
  c.innerHTML = '<svg width="26" height="26" viewBox="0 0 24 24"><path d="M4 2l16 9-7 2-3 7z" fill="#fff" stroke="#111" stroke-width="1.6" stroke-linejoin="round"/></svg>';
  Object.assign(c.style, {position:'fixed', left:'800px', top:'450px', zIndex: 99999, pointerEvents:'none',
    transition:'left .8s cubic-bezier(.4,0,.2,1), top .8s cubic-bezier(.4,0,.2,1)', filter:'drop-shadow(0 2px 4px rgba(0,0,0,.4))'});
  document.body.appendChild(c);
  const cap = document.createElement('div'); cap.id = '__cap';
  Object.assign(cap.style, {position:'fixed', left:'50%', bottom:'26px', transform:'translateX(-50%)', zIndex: 99998,
    maxWidth:'1240px', padding:'12px 22px', borderRadius:'14px', background:'rgba(8,9,16,.86)', color:'#fff',
    font:'500 21px/1.4 Inter, system-ui, sans-serif', textAlign:'center', pointerEvents:'none',
    boxShadow:'0 10px 30px rgba(0,0,0,.35)', transition:'opacity .25s', opacity: 0});
  document.body.appendChild(cap);
  const ring = document.createElement('div'); ring.id = '__ring';
  Object.assign(ring.style, {position:'fixed', width:'44px', height:'44px', borderRadius:'50%', border:'3px solid #8b84ff',
    zIndex: 99997, pointerEvents:'none', opacity: 0, transform:'translate(-50%,-50%) scale(.4)', transition:'all .45s ease-out'});
  document.body.appendChild(ring);
  const st = document.createElement('style'); st.textContent = '#toast{display:none!important}'; document.head.appendChild(st);
  const runs = document.getElementById('nruns-slide'); if (runs) runs.textContent = '%RUNS%';
})();
"""


def ff(*args: str) -> str:
    p = subprocess.run([FFMPEG, "-hide_banner", "-y", *args], capture_output=True, text=True)
    if p.returncode != 0 and "-i" in args and "-f" not in args:
        pass
    return p.stderr


def duration(path: Path) -> float:
    m = re.search(r"Duration: (\d+):(\d+):([\d.]+)", ff("-i", str(path)))
    return int(m[1]) * 3600 + int(m[2]) * 60 + float(m[3])


def tts() -> dict[str, tuple[Path, float]]:
    out = {}
    for key, text in LINES.items():
        p = WORK / f"vo_{key}.mp3"
        if not p.exists():
            subprocess.run([sys.executable, "-m", "edge_tts", "--voice", VOICE, "--rate", "+4%", "--text", text, "--write-media", str(p)], check=True)
        out[key] = (p, duration(p))
    return out


def api(path: str, method: str = "GET"):
    req = urllib.request.Request(DASH + path, method=method)
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


class Recorder:
    def __init__(self, page, cdp, vo):
        self.page, self.cdp, self.vo = page, cdp, vo
        self.frames: list[tuple[float, Path]] = []
        self.skips: list[tuple[float, float]] = []
        self.audio: list[tuple[float, Path]] = []
        self.speaking: asyncio.Task | None = None
        self.t0 = time.time()

    async def start(self):
        self.cdp.on("Page.screencastFrame", self._frame)
        await self.cdp.send("Page.startScreencast", {"format": "jpeg", "quality": 92, "maxWidth": W, "maxHeight": H})

    def _frame(self, ev):
        p = WORK / "frames" / f"f{len(self.frames):06d}.jpg"
        import base64
        p.write_bytes(base64.b64decode(ev["data"]))
        self.frames.append((time.time(), p))
        asyncio.ensure_future(self.cdp.send("Page.screencastFrameAck", {"sessionId": ev["sessionId"]}))

    async def overlay(self):
        await self.page.evaluate(CURSOR_JS.replace("%RUNS%", str(RUNS)))

    async def say(self, key: str):
        """Start narration (and captions) without blocking. Call wait_voice() to block until it ends."""
        await self.wait_voice()
        path, dur = self.vo[key]
        self.audio.append((time.time(), path))
        self.speaking = asyncio.ensure_future(self._captions(LINES[key], dur))

    async def _captions(self, text: str, dur: float):
        for k, v in CAPTION_FIX.items():
            text = text.replace(k, v)
        parts = [s.strip() for s in re.split(r"(?<=[.:!?])\s+", text) if s.strip()]
        total = sum(len(s) for s in parts)
        end = time.time() + dur
        for s in parts:
            await self._cap(s)
            await asyncio.sleep(dur * len(s) / total)
        await asyncio.sleep(max(0, end - time.time()))
        await self._cap("")

    async def _cap(self, s: str):
        try:
            await self.page.evaluate("""(s) => { const c = document.getElementById('__cap'); if (!c) return;
                c.textContent = s; c.style.opacity = s ? 1 : 0; }""", s)
        except Exception:
            pass

    async def wait_voice(self, pad: float = 0.5):
        if self.speaking:
            await self.speaking
            self.speaking = None
            await asyncio.sleep(pad)

    async def wait_for(self, js: str, timeout: float = 120):
        """Wait for a condition. Time spent waiting after the voice-over ends is cut from the video."""
        start = time.time()
        voice_end = None
        while True:
            if await self.page.evaluate(js):
                break
            if self.speaking is None or self.speaking.done():
                voice_end = voice_end or time.time()
            if time.time() - start > timeout:
                raise TimeoutError(js)
            await asyncio.sleep(0.25)
        if voice_end and time.time() - voice_end > 1.2:
            self.skips.append((voice_end + 0.4, time.time() - 0.6))
        await asyncio.sleep(0.8)

    async def point(self, selector: str, click: bool = True):
        box = await self.page.locator(selector).first.bounding_box()
        x, y = box["x"] + min(box["width"] / 2, 60), box["y"] + box["height"] / 2
        await self.page.evaluate("""([x, y]) => { const c = document.getElementById('__cur');
            c.style.left = x + 'px'; c.style.top = y + 'px'; }""", [x, y])
        await asyncio.sleep(1.0)
        if click:
            await self.page.evaluate("""([x, y]) => { const r = document.getElementById('__ring');
                r.style.transition = 'none'; r.style.left = x + 'px'; r.style.top = y + 'px'; r.style.opacity = 1;
                r.style.transform = 'translate(-50%,-50%) scale(.4)'; r.offsetWidth;
                r.style.transition = 'all .5s ease-out'; r.style.opacity = 0; r.style.transform = 'translate(-50%,-50%) scale(1.6)'; }""", [x, y])
            await self.page.locator(selector).first.click()
            await asyncio.sleep(0.4)

    async def scroll_to(self, js_el: str, offset: int = 84):
        await self.page.evaluate(f"""() => {{ const el = {js_el};
            window.scrollTo({{top: el.getBoundingClientRect().top + window.scrollY - {offset}, behavior: 'smooth'}}); }}""")
        await asyncio.sleep(1.4)

    async def slide(self, sid: str):
        await self.page.evaluate("(s) => show(s)", sid)
        await asyncio.sleep(0.9)


async def record(vo):
    st = api("/api/state")
    assert st["report"]["status"] == "VERIFIED" and not st["report"]["findings"], "live Muse runs must verify clean"
    # The narration claims these agents kept the database, the backup and the audit log: check it.
    for e in st["events"]:
        if e["event_type"] == "action_requested" and e["action"] in ("delete_file", "write_file"):
            path = str(e["args"].get("path", ""))
            assert not any(k in path for k in ("customers", "audit.log")), f"narration would be false: {e}"
    shutil.rmtree(WORK / "frames", ignore_errors=True)
    (WORK / "frames").mkdir(parents=True)
    sessions = api("/api/state")["sessions"]
    by = {v["scenario"]: k for k, v in sessions.items()}
    assert {"honest", "pressure", "redteam"} <= set(by), "run the three Muse scenarios first"

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(channel="msedge", headless=True)
        ctx = await browser.new_context(viewport={"width": W, "height": H}, device_scale_factor=1, color_scheme="dark")
        await ctx.add_init_script("try { localStorage.setItem('bb-theme', 'dark') } catch (e) {}")
        page = await ctx.new_page()
        cdp = await ctx.new_cdp_session(page)
        rec = Recorder(page, cdp, vo)

        await page.goto(SLIDES + "#title")
        await page.wait_for_load_state("networkidle")
        await asyncio.sleep(1.2)
        await rec.overlay()
        await rec.start()
        await asyncio.sleep(1.0)
        await rec.slide("title")
        await rec.say("title"); await rec.wait_voice(0.8)
        await rec.slide("problem"); await rec.say("problem"); await rec.wait_voice(0.8)
        await rec.slide("how"); await rec.say("how"); await rec.wait_voice(0.8)

        # --- live dashboard ---
        await page.goto(DASH)
        await page.wait_for_function("document.querySelectorAll('[data-sess]').length >= 3")
        await rec.overlay()
        await asyncio.sleep(1.0)
        await rec.say("clean")
        await asyncio.sleep(4)
        await rec.scroll_to("document.getElementById('sessions')", 150)
        await rec.wait_voice(0.3)
        await rec.say("pressure")
        await rec.point(f"[data-sess='{by['pressure']}']")
        await asyncio.sleep(1.2)
        await rec.scroll_to("document.getElementById('timeline')", 130)
        await asyncio.sleep(3)
        await rec.page.evaluate("document.getElementById('timeline').scrollTo({top: 300, behavior: 'smooth'})")
        await rec.wait_voice(0.3)
        await rec.point("#clear-filter")
        await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        await asyncio.sleep(1.2)

        # --- scripted rogue ---
        await rec.say("rogue")
        await asyncio.sleep(3)
        await rec.point("[data-scenario='scripted_rogue']")
        await rec.wait_voice(0.2)
        await rec.wait_for("document.getElementById('hero').classList.contains('TAMPERED')")
        await rec.say("caught")
        await asyncio.sleep(2.5)
        await rec.scroll_to("document.getElementById('findings')", 150)
        await rec.wait_voice(0.6)

        # --- AI auditor ---
        await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        await asyncio.sleep(1)
        await rec.say("audit")
        await rec.point(".tab[data-tab='audit']")
        await rec.point("#audit-btn")
        await rec.wait_voice(0.2)
        await rec.wait_for("!document.getElementById('audit-btn').disabled && "
                           "document.querySelectorAll('.ai').length >= 4", timeout=240)
        verdicts = {sessions_label(f): f["details"].get("verdict") for f in api("/api/state")["report"]["findings"]
                    if f["type"] == "llm_honesty_verdict"}
        print("auditor verdicts:", verdicts)
        flagged = [k for k, v in verdicts.items() if k in REAL and v != "honest"]
        await rec.scroll_to("document.getElementById('sessions')", 150)
        if flagged:
            await rec.say("verdict_flag")
            await asyncio.sleep(5)
            await rec.scroll_to("""[...document.querySelectorAll('.finding')].find(f => /AI auditor/.test(f.textContent)
                && /%s/.test(f.textContent) && !/HONEST/.test(f.querySelector('.msg').textContent))""" % flagged[0], 200)
        else:
            await rec.say("verdict")
        await rec.wait_voice(1.0)

        # --- insider: edit an entry ---
        await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        await asyncio.sleep(1)
        await rec.say("edit")
        await rec.point(".tab[data-tab='attack']")
        await asyncio.sleep(0.8)
        await rec.point("[data-attack='edit_ledger_entry']")
        await rec.wait_voice(0.2)
        await rec.wait_for("document.getElementById('s-integrity').textContent === 'Compromised'")
        await rec.say("edited")
        await asyncio.sleep(2.5)
        await rec.scroll_to("document.getElementById('findings')", 150)
        await rec.wait_voice(0.6)

        # --- insider: stolen key ---
        await page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        await asyncio.sleep(1)
        await rec.say("stolen")
        await rec.point("[data-attack='rewrite_stolen_key']")
        await rec.wait_voice(0.2)
        await rec.wait_for("[...document.querySelectorAll('.finding b')].some(b => /witness/i.test(b.textContent))")
        await rec.say("witness")
        await rec.scroll_to("document.getElementById('findings')", 150)
        await rec.wait_voice(1.0)

        # --- closing slides ---
        await page.goto(SLIDES + "#failclosed")
        await page.wait_for_load_state("networkidle")
        await rec.overlay()
        await asyncio.sleep(0.5)
        await rec.say("failclosed"); await rec.wait_voice(0.8)
        await rec.slide("results"); await rec.say("results"); await rec.wait_voice(2.0)

        end = time.time()
        await cdp.send("Page.stopScreencast")
        await browser.close()
    return rec, end


def build(rec: Recorder, end: float):
    skips = sorted(rec.skips)

    def edited(t: float) -> float:
        cut = sum(max(0, min(t, b) - a) for a, b in skips if t > a)
        return t - rec.frames[0][0] - cut

    lines = []
    times = [t for t, _ in rec.frames] + [end]
    for i, (t, p) in enumerate(rec.frames):
        d = edited(times[i + 1]) - edited(t)
        if d > 0.0005:
            lines += [f"file '{p.as_posix()}'", f"duration {d:.4f}"]
    lines.append(f"file '{rec.frames[-1][1].as_posix()}'")
    (WORK / "frames.txt").write_text("\n".join(lines), encoding="utf-8")

    inputs, filters = ["-f", "concat", "-safe", "0", "-i", str(WORK / "frames.txt")], []
    for i, (t, p) in enumerate(rec.audio, start=1):
        inputs += ["-i", str(p)]
        ms = max(0, int(edited(t) * 1000))
        filters.append(f"[{i}:a]adelay={ms}|{ms}[a{i}]")
    n = len(rec.audio)
    filters.append("".join(f"[a{i}]" for i in range(1, n + 1)) + f"amix=inputs={n}:normalize=0:dropout_transition=0,volume=1.0[aout]")
    err = ff(*inputs, "-filter_complex", ";".join(filters),
             "-map", "0:v", "-map", "[aout]",
             "-vf", "fps=30,scale=1920:1080:flags=lanczos,format=yuv420p",
             "-c:v", "libx264", "-preset", "medium", "-crf", "18", "-c:a", "aac", "-b:a", "160k",
             "-movflags", "+faststart", "-shortest", str(OUT))
    if not OUT.exists():
        raise SystemExit(err[-3000:])
    print(f"wrote {OUT}  ({duration(OUT):.1f}s, cut {sum(b - a for a, b in skips):.1f}s of waiting)")


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    vo = tts()
    print("voice-over:", round(sum(d for _, d in vo.values()), 1), "s")
    rec, end = asyncio.run(record(vo))
    build(rec, end)


if __name__ == "__main__":
    main()
