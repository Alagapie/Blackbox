# Submission package

| File | What it is |
|---|---|
| `Blackbox_report.pdf` | The research report (required). Main body ≤ 8 pages, then references and appendices A–D. |
| `blackbox_demo.mp4` | 3–4 minute narrated, captioned demo video (optional item). 1080p. |
| `report/report.html` | Source of the PDF. Edit this, then re-export (see below). |
| `video/` | Script and slides that generate the video automatically from the live dashboard. |

## Before submitting

The report follows the official Apart Research submission template (cover page, sections 1–6, Code and Data,
References, Appendix A–D, LLM Usage Statement).

1. Author is set to Abdulbasit Suleiman, Independent Researcher (edit the cover in `report/report.html` to change it).
2. Replace the yellow `[GitHub link]` placeholder under "Code and Data" once the repo exists.
3. After any edit, re-export the PDF (command below).

## Re-export the PDF

```powershell
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --headless=new --no-pdf-header-footer `
  --virtual-time-budget=10000 --print-to-pdf="$PWD\submission\Blackbox_report.pdf" `
  "file:///$($PWD -replace '\\','/')/submission/report/report.html"
```

## Re-record the video

Needs `pip install playwright imageio-ffmpeg edge-tts` (in a separate venv) and Microsoft Edge.

1. `.venv\Scripts\python run.py --fresh`
2. Run the three Muse scenarios (Honest, Pressure, Red-team) from the dashboard and wait until they finish.
3. `python submission/video/make_video.py` (set `PRIOR_RUNS` to the number of earlier documented live runs).

The narration adapts to what the AI auditor actually says, because live model behaviour varies between runs.
