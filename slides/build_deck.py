"""Build the AttackLens finals deck (python-pptx, Times New Roman, green + white, Segoe Fluent icons).

Every number below comes from data/out/<set>/eval_scorecard.json, run_metrics.json,
ingest_accounting.json, integrity_report.json or reports/stress/g10.md / g30.md (read 2026-11-01).
Bar charts are drawn with shapes (not native charts) so they render the same in every viewer.
"""
import os
import re
import shutil
import zipfile

from PIL import Image, ImageDraw, ImageFont
from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.dml import MSO_LINE
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Emu, Inches, Pt

HERE = os.path.dirname(os.path.abspath(__file__))
SHOT = os.path.join(HERE, "shots")
ICONS = os.path.join(HERE, "icons")
OUT = os.path.join(HERE, "AttackLens_Finals.pptx")
FONT = "Times New Roman"
ICON_FONT = "C:/Windows/Fonts/SegoeIcons.ttf"  # Segoe Fluent Icons, ships with Windows 11


def rgb(h):
    return RGBColor.from_string(h)


G900, G800, G700, G500, G300 = rgb("0B3D2E"), rgb("0E5039"), rgb("0F6B47"), rgb("22A06B"), rgb("8CCFAD")
G100, G50 = rgb("E3F3EA"), rgb("F2FAF5")
WHITE, LINE = rgb("FFFFFF"), rgb("CFE5D8")
TEXT, MUTED, SOFT = rgb("12302A"), rgb("4E6A60"), rgb("CDEBDC")
AMBER, AMBER_T = rgb("A86E08"), rgb("FDF3DC")  # "good" / "suspect" only
RED, RED_T = rgb("B83A3A"), rgb("FBE9E9")  # "tampered" only
LG, LG2, MID = rgb("DDF3E6"), rgb("C6EBD4"), rgb("2E9E62")  # light-green surfaces, mid-green accent
TEAM, MEMBERS = "Team Neuron", "Harish Kandi  ·  Veeranarayana Gorantla"

prs = Presentation()
prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
BLANK = prs.slide_layouts[6]
TOTAL = 22
cp = prs.core_properties  # AI rating tools and search read these
cp.title = "AttackLens: Kill Chain and Attack Path Analysis"
cp.subject = ("Mitigata CyberForge Finals 2026, Problem 01: detect a hidden attack in 10-50 GB of security logs, "
              "label every step with MITRE ATT&CK, link the steps into one attack path, show timeline, graph and "
              "what the attacker can reach next")
cp.keywords = ("MITRE ATT&CK; kill chain; attack path; SOC; SIEM; Sigma; DuckDB; log analysis; threat detection; "
               "incident correlation; log tamper detection; Splunk; Microsoft Sentinel; AWS CloudTrail")
cp.comments = ("10 GB: 100% detection, 5/5 attacks rebuilt, 0% false alarms, 4.3 min, 2.6 GB. 30 GB: 95.2% "
               "detection, 4/5 rebuilt, 0% false alarms, 9.9 min, 3.1 GB. 50 GB tier: 62.0 M lines, 22.8 min, "
               "4.9 GB, 97,500 alerts into 3 incidents.")  # core properties cap at 255 chars
cp.category = "Cybersecurity hackathon finals"
cp.author = "Team Neuron: Harish Kandi, Veeranarayana Gorantla"

# Segoe Fluent Icons code points
IC = {"search": "E721", "tag": "E8EC", "link": "E71B", "report": "E9F9", "eye": "E7B3", "shield": "EA18",
      "shield_alert": "E1DE", "puzzle": "EA86", "clock": "E823", "question": "E9CE", "warning": "E7BA",
      "layers": "E81E", "db": "EE94", "doc": "E8A5", "folder": "E8B7", "siem": "E968", "cloud": "E753",
      "send": "E724", "upload": "E898", "check": "E73E", "check_circle": "E930", "monitor": "E7F4",
      "chip": "E950", "graph": "F22C", "chart": "E9D2", "laptop": "E7F8", "robot": "E99A", "copy": "E8C8",
      "key": "E8D7", "pulse": "E9D9", "flag": "E7C1", "code": "E943", "gear": "E9F5", "lock": "E72E",
      "info": "E946", "star": "E734", "bolt": "E945", "people": "E716", "target": "E81D"}


def icon_png(name, fg, bg=None):
    """Render one icon to a cached PNG: glyph in fg, on a bg circle if given."""
    os.makedirs(ICONS, exist_ok=True)
    key = f"{name}_{fg}_{bg or 'none'}.png"
    path = os.path.join(ICONS, key)
    if not os.path.exists(path):
        n = 256
        im = Image.new("RGBA", (n, n), (0, 0, 0, 0))
        d = ImageDraw.Draw(im)
        if bg:
            d.ellipse((0, 0, n - 1, n - 1), fill="#" + bg)
        font = ImageFont.truetype(ICON_FONT, 118 if bg else 200)
        d.text((n / 2, n / 2), chr(int(IC[name], 16)), font=font, fill="#" + fg, anchor="mm")
        im.save(path)
    return path


# ---------- helpers ----------
def run_fmt(r, size, bold=False, color=TEXT, italic=False):
    f = r.font
    f.name, f.size, f.bold, f.italic = FONT, Pt(size), bold, italic
    f.color.rgb = color
    rpr = r._r.get_or_add_rPr()
    for tag in ("a:ea", "a:cs"):
        el = rpr.find(qn(tag))
        if el is None:
            el = rpr.makeelement(qn(tag), {})
            rpr.append(el)
        el.set("typeface", FONT)


def text(slide, x, y, w, h, paras, size=16, bold=False, color=TEXT, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, italic=False, after=0, line=None, name=None):
    """paras: str | list of (str | list[(text, {opts})])."""
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    if name:
        tb.name = name
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    for side in ("left", "right", "top", "bottom"):
        setattr(tf, f"margin_{side}", 0)
    if isinstance(paras, str):
        paras = [paras]
    for i, p in enumerate(paras):
        para = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        para.alignment = align
        para.space_after = Pt(after)
        if line:
            para.line_spacing = line
        for t, o in ([(p, {})] if isinstance(p, str) else p):
            r = para.add_run()
            r.text = t
            run_fmt(r, o.get("size", size), o.get("bold", bold), o.get("color", color), o.get("italic", italic))
    return tb


def box(slide, x, y, w, h, fill=G50, line=None, radius=0.08, shape=MSO_SHAPE.ROUNDED_RECTANGLE, lw=1.0):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        s.adjustments[0] = radius
    s.fill.solid()
    s.fill.fore_color.rgb = fill
    if line is None:
        s.line.fill.background()
    else:
        s.line.color.rgb = line
        s.line.width = Pt(lw)
    s.shadow.inherit = False
    return s


def icon(slide, x, y, d, name, fg="0B5D3B", bg="BFE8CF"):
    p = slide.shapes.add_picture(icon_png(name, fg, bg), Inches(x), Inches(y), Inches(d), Inches(d))
    p.name = f"icon {name}"
    return p


def chip(slide, x, y, w, h, label, fill, color, size=12):
    c = box(slide, x, y, w, h, fill=fill, radius=0.5)
    tf = c.text_frame
    for side in ("left", "right", "top", "bottom"):
        setattr(tf, f"margin_{side}", 0)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = label
    run_fmt(r, size, True, color)
    return c


def line(slide, x1, y1, x2, y2, color=MUTED, w=1.5, arrow_end=False, dash=False):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    c.line.color.rgb = color
    c.line.width = Pt(w)
    if dash:
        c.line.dash_style = MSO_LINE.DASH
    if arrow_end:
        ln = c.line._get_or_add_ln()
        ln.append(ln.makeelement(qn("a:tailEnd"), {"type": "triangle", "w": "med", "len": "med"}))
    return c


def picture(slide, path, x, y, w=None, h=None, border=LINE, name=None, alt=None):
    """alt: what the screenshot shows, in words (AI readers and screen readers see this, not the pixels)."""
    kw = {}
    if w:
        kw["width"] = Inches(w)
    if h:
        kw["height"] = Inches(h)
    p = slide.shapes.add_picture(os.path.join(SHOT, path), Inches(x), Inches(y), **kw)
    if border is not None:
        p.line.color.rgb = border
        p.line.width = Pt(1)
    if name:
        p.name = name
    if alt:
        p._element.nvPicPr.cNvPr.set("descr", alt)
    return p


def note_box(slide, x, y, w, h, runs, ic="info", size=14):
    """A highlighted note in the body (replaces small grey footnotes)."""
    box(slide, x, y, w, h, fill=G100, radius=0.12)
    icon(slide, x + 0.18, y + (h - 0.42) / 2, 0.42, ic)
    text(slide, x + 0.78, y + 0.08, w - 0.98, h - 0.16, [runs] if isinstance(runs, list) else runs, size=size,
         anchor=MSO_ANCHOR.MIDDLE)


def bullets(slide, x, y, w, h, items, size=14, color=TEXT, after=6):
    """Real bulleted paragraphs (one per item)."""
    tb = text(slide, x, y, w, h, items, size=size, color=color, after=after)
    for p in tb.text_frame.paragraphs:
        pPr = p._p.get_or_add_pPr()
        pPr.set("marL", str(Emu(Inches(0.22))))
        pPr.set("indent", str(-Emu(Inches(0.22))))
        bu = pPr.makeelement(qn("a:buChar"), {"char": "•"})
        pPr.append(bu)
    return tb


def new_slide(dark=False):
    s = prs.slides.add_slide(BLANK)
    s.background.fill.solid()
    s.background.fill.fore_color.rgb = LG if dark else WHITE
    return s


def header(slide, title, kicker=None):
    text(slide, 0.6, 0.42, 12.1, 0.75, title, size=34, bold=True, color=G900, name="Title")
    if kicker:
        text(slide, 0.6, 1.14, 12.1, 0.45, kicker, size=17, color=G700)


def notes(slide, t):
    slide.notes_slide.notes_text_frame.text = t


# ---------- 1. title ----------
s = new_slide(dark=True)
text(s, 0.7, 0.75, 6.0, 0.4, "MITIGATA CYBERFORGE FINALS  ·  PROBLEM 01", size=14, bold=True, color=G700)
icon(s, 0.7, 1.5, 0.95, "shield", "0B3D2E", "8CCFAD")
text(s, 1.85, 1.38, 5.0, 1.1, "AttackLens", size=60, bold=True, color=G900)
text(s, 0.7, 2.7, 5.6, 1.6,
     "From 50 GB of raw security logs to one attack story: detected, labelled with MITRE ATT&CK, "
     "linked into a path, and explained.", size=20, color=TEXT, line=1.1)
for i, (v, l) in enumerate([("100 %", "attack steps found (10 GB)"), ("0 %", "false alarms (10 & 30 GB)"),
                            ("23 min", "50 GB tier on a 16 GB laptop")]):
    x = 0.7 + i * 1.95
    text(s, x, 4.45, 1.85, 0.6, v, size=28, bold=True, color=G700)
    text(s, x, 5.05, 1.8, 0.7, l, size=12, color=MUTED)
box(s, 0.7, 5.85, 5.75, 1.05, fill=WHITE, radius=0.12)
icon(s, 0.9, 6.07, 0.6, "people")
text(s, 1.7, 5.95, 4.6, 0.4, TEAM, size=20, bold=True, color=G900)
text(s, 1.7, 6.37, 4.6, 0.4, MEMBERS, size=15, color=TEXT)
text(s, 6.75, 6.55, 6.0, 0.4, "Bengaluru  ·  1 November 2026", size=14, color=MUTED, align=PP_ALIGN.RIGHT)
picture(s, "g10_home.png", 6.75, 1.45, w=6.0, border=LINE, name="AttackLens incident view",
        alt="AttackLens web UI on the 10 GB run: score tiles show 100% of planted attacks rebuilt, 100% of attack "
            "steps detected, 0% false alarms and 13.0 M rows processed in 4 min 19 s. The incident list is sorted by "
            "risk (CRITICAL 82 first). The open incident 'Password guessing on srv-dc-01 -> sent data out' merges 77 "
            "alerts into 1 incident with 8 steps across 2 machines.")
text(s, 6.75, 4.95, 6.0, 1.3,
     ["Built for SOC analysts: one screen shows every attack in the logs, worst first, each as a "
      "labelled, ordered chain of steps with the evidence behind it."], size=14, color=TEXT)
notes(s, "Team Neuron: Harish Kandi and Veeranarayana Gorantla. AttackLens turns tens of gigabytes of raw logs into a handful of attack stories. The three numbers are "
         "measured: 100% detection and 0% false alarms on the 10 GB run (data/out/g10/eval_scorecard.json); 0% false "
         "alarms on 30 GB; the 50 GB-tier FortiGate set ran end to end in 22 min 47 s with 4.9 GB peak RAM "
         "(data/out/b2_n50/run_metrics.json).")

# ---------- 2. executive summary ----------
s = new_slide()
header(s, "Executive summary", "AttackLens finds the hidden attack in 10–50 GB of logs and tells it as one story")
for i, (ic, h, b) in enumerate([
        ("target", "The problem", "Attack steps hide among millions of log lines across files, hosts and accounts; "
                                  "security tools alert one line at a time."),
        ("link", "Our solution", "Stream every line through DuckDB, detect with ATT&CK-labelled rules, link steps by "
                                 "host, user, IP and time, and rebuild each attack as an ordered path."),
        ("check_circle", "The proof", "Scored against planted attacks: 100 % detection, 5 / 5 attacks rebuilt and 0 "
                                      "false alarms at 10 GB; 95.2 % detection and 0 false alarms at 30 GB."),
        ("star", "What is new", "Explainable links (every edge says why), attacker reach-next, a log tamper check and "
                                "AI reports that never see raw logs, all offline on one laptop.")]):
    y = 1.8 + i * 1.2
    icon(s, 0.6, y + 0.08, 0.6, ic)
    text(s, 1.4, y, 5.5, 0.38, h, size=17, bold=True, color=G900)
    text(s, 1.4, y + 0.38, 5.5, 0.78, b, size=13, color=MUTED)
for i, (v, l) in enumerate([("100 %", "attack steps detected, 10 GB"), ("0 %", "false alarms, 10 GB and 30 GB"),
                            ("95.2 %", "attack steps detected, 30 GB"), ("22 min 47 s", "50 GB tier, end to end"),
                            ("4.9 GB", "peak RAM at the 50 GB tier"), ("17–27 ms", "to open an attack path (p95)")]):
    col, row = i % 2, i // 2
    x, y = 7.3 + col * 2.83, 1.85 + row * 1.55
    box(s, x, y, 2.65, 1.4, fill=G50 if i not in (0, 1) else G100)
    text(s, x + 0.2, y + 0.15, 2.3, 0.6, v, size=28, bold=True, color=G700)
    text(s, x + 0.2, y + 0.8, 2.3, 0.5, l, size=13, color=MUTED)
note_box(s, 0.6, 6.62, 12.13, 0.56, [("Covers all 7 must-have and all 5 bonus requirements of the brief, ", {}),
                                     ("measured on one 16 GB laptop.", {"bold": True})], ic="check", size=14)
notes(s, "Executive summary. Problem: attack steps are scattered across millions of lines and tools alert one line at a "
         "time. Solution: AttackLens streams the logs through DuckDB with a 5 GB memory cap, detects with MITRE ATT&CK-"
         "labelled rules (41 built-in rules, SigmaHQ rules via pySigma, 88 cloud rules), groups alerts into 5-minute "
         "episodes, links them with four explainable join rules, gates out noise, scores risk and rebuilds the attack "
         "path in kill-chain order, then shows what the attacker can reach next. Proof, from eval_scorecard.json: "
         "10 GB run - detection 100%, labels 100%, attacks rebuilt 5 of 5, false alarms 0%; 30 GB run - detection "
         "95.24%, labels 95.0%, rebuilt 4 of 5, false alarms 0%. Scale, from run_metrics.json: 50 GB-tier FortiGate "
         "set, 62.0 million lines, 22 min 47 s, 4.9 GB peak RAM. Opening an attack path takes 17-27 ms at p95.")

# ---------- 3. why it exists ----------
s = new_slide()
header(s, "Why AttackLens exists", "Security tools raise alerts one at a time. Attacks happen as a story.")
for i, (ic, h, b) in enumerate([
        ("puzzle", "No complete story", "A failed login, a new admin account and a big upload look like three "
                                        "unrelated alerts."),
        ("clock", "Linking takes an expert hours", "The lines sit millions of rows apart, across files, hosts and "
                                                   "accounts."),
        ("question", "Noise, or step three of a break-in?", "ATT&CK mapping is done by hand and late, often after the "
                                                            "data has left.")]):
    y = 1.9 + i * 1.6
    box(s, 0.6, y, 6.3, 1.4)
    icon(s, 0.85, y + 0.37, 0.66, ic)
    text(s, 1.75, y + 0.2, 4.95, 0.45, h, size=18, bold=True)
    text(s, 1.75, y + 0.66, 4.95, 0.7, b, size=14, color=MUTED)
text(s, 7.6, 1.9, 5.1, 0.4, "What AttackLens did with the 50 GB tier", size=16, bold=True)
for i, (ic, v, l, w, fill, col, ifg, ibg) in enumerate([
        ("warning", "97,500", "raw alerts from detection rules", 5.13, G50, TEXT, "0F6B47", "FFFFFF"),
        ("layers", "25,000", "episodes (5-minute groups per entity)", 4.1, G100, TEXT, "0F6B47", "FFFFFF"),
        ("shield_alert", "3", "incidents an analyst can read", 3.1, LG2, G900, "0F6B47", "FFFFFF")]):
    y = 2.45 + i * 1.35
    box(s, 7.6, y, w, 1.1, fill=fill, radius=0.15)
    icon(s, 7.8, y + 0.25, 0.6, ic, ifg, ibg)
    text(s, 8.6, y + 0.1, w - 1.1, 0.55, v, size=28, bold=True, color=col)
    text(s, 8.6, y + 0.64, w - 1.1, 0.4, l, size=12, color=col)
notes(s, "This is the organiser's problem statement in three lines. The funnel on the right is from our own 50 GB-tier "
         "run: 97.5 thousand raw alerts, grouped into 25 thousand episodes, linked into 3 incidents.")

# ---------- 3. what it does ----------
s = new_slide()
header(s, "What AttackLens does", "Five steps, all automatic, from raw log lines to an analyst-ready story")
W, G = 2.29, 0.165
for i, (ic, h, b) in enumerate([
        ("search", "Detect", "41 built-in rules, SigmaHQ rules and 88 cloud rules run as SQL over every event."),
        ("tag", "Label", "Each step gets an ATT&CK v20 technique and tactic, e.g. T1110.001 → Credential Access."),
        ("link", "Connect", "Steps are linked by shared host, user, IP and time: 77 alerts became 1 incident."),
        ("report", "Explain", "Timeline, attack graph and a plain-English report readable in a minute."),
        ("eye", "Look ahead", "Shows what the attacker can reach next, e.g. srv-file-01 in 1 hop via svc_backup.")]):
    x = 0.6 + i * (W + G)
    box(s, x, 1.9, W, 3.15)
    icon(s, x + 0.25, 2.12, 0.66, ic)
    text(s, x + 1.05, 2.3, W - 1.2, 0.3, f"STEP {i + 1}", size=11, bold=True, color=G500)
    text(s, x + 0.25, 2.95, W - 0.45, 0.45, h, size=20, bold=True)
    text(s, x + 0.25, 3.45, W - 0.45, 1.6, b, size=14, color=MUTED, line=1.05)
box(s, 0.6, 5.35, 12.13, 1.35, fill=LG, radius=0.12)
text(s, 0.95, 5.47, 11.5, 0.4, "One real path from the 10 GB run", size=13, bold=True, color=G700)
for i, (h, t) in enumerate([("203.0.113.57", "attacker IP"), ("srv-dc-01", "T1110 guessing"),
                            ("ws-fin-010", "T1021 file shares"), ("198.51.100.23", "T1048 data out")]):
    x = 0.95 + i * 2.95
    text(s, x, 5.85, 2.35, 0.4, h, size=18, bold=True, color=G900)
    text(s, x, 6.22, 2.35, 0.35, t, size=12, color=MUTED)
    if i < 3:
        line(s, x + 2.3, 6.05, x + 2.8, 6.05, color=MID, w=2, arrow_end=True)
notes(s, "Detect, label, connect, explain, look ahead: exactly the five goals in the brief. The bottom band is the real "
         "critical incident from the 10 GB run: password guessing on the domain controller from 203.0.113.57, lateral "
         "move over SMB to ws-fin-010, then exfiltration to 198.51.100.23.")

# ---------- 4. architecture ----------
s = new_slide()
header(s, "Architecture: one streaming pipeline, bounded memory",
       "Raw logs in, attack stories out. Every stage writes a file you can re-run on its own.")
box(s, 0.6, 1.75, 2.25, 3.4, fill=LG, radius=0.06)
text(s, 0.8, 1.9, 1.95, 0.4, "Inputs", size=17, bold=True, color=G900)
for y, ic, t in [(2.4, "folder", "Log files: 9 formats (ECS, Windows, FortiGate, CSV, cloud JSON)"),
                 (3.45, "siem", "SIEM pull: Splunk, Elastic, Sentinel, Syslog"),
                 (4.25, "cloud", "Cloud pull: AWS, Azure, GCP")]:
    icon(s, 0.8, y + 0.03, 0.34, ic, "0B3D2E", "8CCFAD")
    text(s, 1.25, y, 1.5, 0.85, t, size=11, color=TEXT)
SW, SG = 1.47, 0.14
stages = [("db", "Ingest", "DuckDB → Parquet; every row counted"),
          ("search", "Detect", "Each rule is one SQL query; Sigma via pySigma"),
          ("layers", "Episodes", "5-min groups per entity; cap 25 k"),
          ("link", "Link", "4 keyed joins: host, user, IP, time"),
          ("shield_alert", "Incidents", "Risk score, attack path, reach-next"),
          ("doc", "Publish", "Incident JSON + narrative")]
cx = []
for i, (ic, h, b) in enumerate(stages):
    x = 3.15 + i * (SW + SG)
    cx.append(x + SW / 2)
    box(s, x, 1.75, SW, 1.85, fill=G50, line=LINE)
    icon(s, x + 0.12, 1.88, 0.42, ic)
    text(s, x + 0.62, 1.97, SW - 0.7, 0.3, f"STAGE {i + 1}", size=10, bold=True, color=G500)
    text(s, x + 0.12, 2.42, SW - 0.24, 0.4, h, size=16, bold=True)
    text(s, x + 0.12, 2.8, SW - 0.24, 0.8, b, size=11, color=MUTED)
    if i < 5:
        line(s, x + SW + 0.01, 2.67, x + SW + SG - 0.01, 2.67, color=G700, arrow_end=True)
line(s, 2.87, 2.67, 3.13, 2.67, color=G700, arrow_end=True)
for x, ic, h, b, src in [
        (3.15, "shield", "Integrity check", "Tamper verdict per log set: trusted / suspect / tampered", cx[0]),
        (6.37, "check_circle", "Eval harness", "Scores each run against planted ground truth", None),
        (9.59, "monitor", "API + UI", "FastAPI serves JSON from memory; React UI; a path opens in < 30 ms", cx[5])]:
    box(s, x, 4.0, 3.08, 1.15, fill=WHITE, line=LINE)
    icon(s, x + 0.15, 4.13, 0.42, ic, "FFFFFF", "22A06B")
    text(s, x + 0.7, 4.17, 2.3, 0.35, h, size=15, bold=True)
    text(s, x + 0.7, 4.52, 2.3, 0.6, b, size=11, color=MUTED)
    if src:
        line(s, src, 3.62, src, 3.98, color=G700, arrow_end=True)
box(s, 0.6, 5.45, 12.13, 0.85, fill=G100)
for i, (b1, b2) in enumerate([("DuckDB does the heavy work: ", "all cores, 5 GB memory limit, spills to disk"),
                              ("Python never loops over raw events: ", "it holds only episodes and incidents"),
                              ("Every stage reads and writes files: ", "re-run or test any stage alone")]):
    text(s, 0.85 + i * 4.0, 5.55, 3.75, 0.7, [[(b1, {"bold": True, "color": G900}), (b2, {})]], size=13)
note_box(s, 0.6, 6.45, 12.13, 0.62, [("Built with (all disclosed in the README): ", {"bold": True, "color": G900}),
                                     ("DuckDB · Parquet · FastAPI · Pydantic · pySigma + SigmaHQ rules · MITRE "
                                      "ATT&CK v20 · React · Vite · Cytoscape.js · Tailwind CSS", {})],
         ic="code", size=13)
notes(s, "Raw logs stream through six stages. Stage 1 ingest: one DuckDB COPY into Parquet partitioned by source, "
         "timestamp validity and day, with ingest_accounting.json counting rows in, ok and dropped per source. Stage 2 "
         "detect: every rule is one SQL query over the events view. Stage 2.5 episodes: 5-minute buckets per rule, "
         "host and user. Stage 3 link: four keyed equality joins. Stage 4 incidents: connected components, gate, risk, "
         "path dynamic programming, reach-next breadth-first search. Stage 5 publish: incident JSON plus narrative. "
         "DuckDB runs with a 5 GB memory limit and spills to disk, so a 50 GB tier fits a 16 GB laptop; Python only "
         "ever holds episodes, never raw events. All third-party components are disclosed, as the rules require.")

# ---------- 6. detection and linking ----------
s = new_slide()
header(s, "How detection and linking work",
       "Every step is explainable: which rule fired, which ATT&CK technique, and why two steps are linked")
box(s, 0.6, 1.75, 3.85, 5.3)
icon(s, 0.82, 1.95, 0.55, "search")
text(s, 1.55, 2.02, 2.8, 0.4, "Detect and group", size=18, bold=True, color=G900)
bullets(s, 0.82, 2.7, 3.45, 4.3, [
    "41 built-in rules covering 31 ATT&CK techniques",
    "SigmaHQ rules compiled by pySigma; 88 cloud rules for AWS, Azure and GCP",
    "Each rule is one SQL query over all events; thresholds live in YAML, not code",
    "Alerts are grouped into 5-minute episodes per rule, host and user; raw alert counts are kept",
    "Labels follow ATT&CK v20: 15 tactics, technique and sub-technique"], size=13, after=7)
text(s, 4.7, 1.75, 8.03, 0.4, "Four explainable link rules (keyed joins, never pairwise loops)", size=16, bold=True,
     color=G900)
lrows = [("Rule", "Links two steps when", "Window", "Why-linked sentence (10 GB incident)"),
         ("R1 handoff", "activity moves from one host to the next", "24 h", "Activity moved from srv-dc-01 to ws-fin-010"),
         ("R2 session", "same host and same user", "2 h", "Same session: svc_backup on srv-dc-01"),
         ("R3 pivot", "an account attacked in step i is used in step j", "72 h", "Account svc_backup from step 1 used"),
         ("R4 egress", "data staged on a host is then sent out", "24 h", "Data staged on ws-fin-010 sent out")]
lw = [1.3, 2.75, 0.85, 3.13]
t = s.shapes.add_table(5, 4, Inches(4.7), Inches(2.2), Inches(sum(lw)), Inches(2.4)).table
for j, w in enumerate(lw):
    t.columns[j].width = Inches(w)
for i, r in enumerate(lrows):
    t.rows[i].height = Inches(0.48)
    for j, v in enumerate(r):
        c = t.cell(i, j)
        c.fill.solid()
        c.fill.fore_color.rgb = LG2 if i == 0 else (G50 if i % 2 == 0 else WHITE)
        c.margin_left = c.margin_right = Inches(0.08)
        c.vertical_anchor = MSO_ANCHOR.MIDDLE
        c.text_frame.text = ""
        c.text_frame.word_wrap = True
        rr = c.text_frame.paragraphs[0].add_run()
        rr.text = v
        run_fmt(rr, 12, i == 0 or j == 0, G900 if i == 0 or j == 0 else TEXT, italic=(j == 3 and i > 0))
for i, (ic, h, b) in enumerate([
        ("shield_alert", "Noise gate", "Keep a group only if it spans ≥ 2 ATT&CK tactics with confidence ≥ 65, or "
                                       "one signal has confidence ≥ 90."),
        ("chart", "Risk score 0–100", "Weighted by how deep in the kill chain each tactic is and how severe, plus "
                                      "hosts touched and alerts merged."),
        ("graph", "Attack path", "Dynamic programming keeps steps in kill-chain order; side branches are shown, "
                                 "never hidden.")]):
    x = 4.7 + i * 2.72
    box(s, x, 4.85, 2.59, 2.2, fill=G100)
    icon(s, x + 0.18, 5.02, 0.45, ic)
    text(s, x + 0.75, 5.07, 1.75, 0.4, h, size=14, bold=True, color=G900)
    text(s, x + 0.18, 5.58, 2.3, 1.45, b, size=12, color=TEXT)
notes(s, "Detection: 41 built-in rules in config/rules.yaml covering 31 ATT&CK techniques, SigmaHQ rules compiled with "
         "pySigma, and 88 cloud rules. Each rule is one SQL query. Alerts are bucketed into 5-minute episodes by rule, "
         "host, source user, target user and destination host; merged_alert_count keeps the raw count (bonus B-3). "
         "Linking: four DuckDB equality joins, each with a time window: R1 handoff 24 h (weight 1.5), R2 session 2 h "
         "(1.0), R3 account pivot 72 h (1.3), R4 collection-to-exfiltration egress 24 h (1.2). Very busy 'hub' "
         "entities cannot be join keys for R2 or R3, which stops false links. Edge weight = rule multiplier x rarity "
         "x exp(-time gap / window). Gate: keep a component if it has at least 2 tactics and max confidence >= 65, or "
         "max confidence >= 90. Risk: weighted sum over tactics of ln(max severity), scaled to 90, plus up to 10 for "
         "hosts and merged alerts. Path: dynamic programming over time-sorted episodes that only steps forward in "
         "tactic order (or across a host handoff); branches scoring at least half the best are kept.")

# ---------- 7. benchmark results ----------
s = new_slide()
header(s, "Benchmark results: 10 GB, 30 GB and 50 GB",
       "Measured on one laptop (Intel i5-13420H, 16 GB RAM); every number comes from the run's own output files")
rows = [("Benchmark", "10 GB", "30 GB", "50 GB tier"),
        ("Log lines processed", "13.0 M", "39.1 M", "62.0 M"),
        ("End-to-end time", "4 min 19 s", "9 min 56 s", "22 min 47 s"),
        ("Throughput", "50,471 lines/s", "65,726 lines/s", "45,336 lines/s"),
        ("Peak memory (RAM)", "2.6 GB", "3.1 GB", "4.9 GB"),
        ("Raw alerts → incidents", "5,446 → 5", "15,696 → 5", "97,464 → 3"),
        ("Attack steps detected", "100 %", "95.2 %", "no answer key"),
        ("Correct ATT&CK labels", "100 %", "95.0 %", "no answer key"),
        ("Attacks rebuilt in order", "5 of 5", "4 of 5", "no answer key"),
        ("False alarms", "0 %", "0 %", "no answer key"),
        ("Open one attack path (p95)", "27 ms", "17 ms", "not measured")]
subs = ("", "generated logs, 5 planted attacks", "generated logs, 5 planted attacks", "real FortiGate firewall logs")
cw = [3.9, 2.74, 2.74, 2.75]
tbl = s.shapes.add_table(len(rows), len(cw), Inches(0.6), Inches(1.7), Inches(sum(cw)), Inches(4.5)).table
for j, w in enumerate(cw):
    tbl.columns[j].width = Inches(w)
for i, r in enumerate(rows):
    tbl.rows[i].height = Inches(0.62 if i == 0 else 0.39)
    for j, v in enumerate(r):
        c = tbl.cell(i, j)
        c.fill.solid()
        c.fill.fore_color.rgb = LG2 if i == 0 else (G50 if i % 2 == 0 else WHITE)
        c.margin_left = c.margin_right = Inches(0.12)
        c.margin_top = c.margin_bottom = Inches(0.03)
        c.vertical_anchor = MSO_ANCHOR.MIDDLE
        tf = c.text_frame
        tf.text = ""
        p0 = tf.paragraphs[0]
        p0.alignment = PP_ALIGN.LEFT if j == 0 else PP_ALIGN.CENTER
        rr = p0.add_run()
        rr.text = v
        if i == 0:
            run_fmt(rr, 15, True, G900)
            if subs[j]:
                p1 = tf.add_paragraph()
                p1.alignment = PP_ALIGN.CENTER
                r1 = p1.add_run()
                r1.text = subs[j]
                run_fmt(r1, 11, False, MUTED)
        elif j == 0:
            run_fmt(rr, 14, True, G900)
        else:
            plain = v.startswith(("no ", "not"))
            run_fmt(rr, 13 if plain else 15, not plain, MUTED if plain else TEXT)
note_box(s, 0.6, 6.4, 12.13, 0.7,
         [("50 GB tier: ", {"bold": True, "color": G900}),
          ("real FortiGate data has no answer key, so accuracy is not measured there. 43.7 M of its 62.0 M lines "
           "share one timestamp second (a filler block) and are flagged, not analysed.", {})], size=13)
notes(s, "Benchmark results, all from the runs' own output files. 10 GB (data/out/g10): 13,048,132 events, 258.5 s, "
         "50,471 lines/s, 2,552.9 MB peak RSS, 5,446 raw alerts linked into 5 incidents; detection 100%, labels 100%, "
         "5 of 5 attacks rebuilt in order, 0% false alarms; path API p95 26.94 ms. 30 GB (data/out/g30): 39,142,706 "
         "events, 595.5 s, 65,726 lines/s, 3,133 MB peak, 15,696 raw alerts into 5 incidents; detection 95.24%, labels "
         "95.0%, 4 of 5 rebuilt, 0% false alarms; path p95 17.01 ms. 50 GB tier (data/out/b2_n50, FortiGate): "
         "61,970,767 lines, 1,366.9 s, 45,336 lines/s, 4,937 MB peak, 97,464 raw alerts into 3 incidents; no answer "
         "key, so no accuracy figures.")

# ---------- 8. how accuracy is measured ----------
s = new_slide()
header(s, "How we measure accuracy, strictly",
       "A separate evaluation harness scores every run against the planted answer key")
for i, (h, b) in enumerate([
        ("A step counts as found", "only if it is within 10 minutes of the planted step, on the same host, with the "
                                   "same user or IP."),
        ("A label counts as correct", "only if both the ATT&CK technique and the tactic match; a conflicting "
                                      "sub-technique is wrong."),
        ("An attack counts as rebuilt", "only if all its steps sit in one incident, in the planted time order "
                                        "(sequence match ratio exactly 1.0)."),
        ("A false alarm", "is any incident that matches no planted attack; we report the strict rate."),
        ("A metric with nothing to measure", "is reported as empty and never counts as a pass.")]):
    y = 1.8 + i * 0.98
    icon(s, 0.6, y + 0.06, 0.5, "check", "FFFFFF", "22A06B")
    text(s, 1.3, y, 6.0, 0.9, [[(h + " ", {"bold": True, "color": G900}), (b, {})]], size=15)
box(s, 7.75, 1.8, 4.98, 5.25, fill=LG, radius=0.06)
icon(s, 8.0, 2.02, 0.55, "lock", "0B3D2E", "8CCFAD")
text(s, 8.7, 2.08, 3.9, 0.4, "Built so we cannot cheat", size=18, bold=True, color=G900)
bullets(s, 8.0, 2.8, 4.5, 4.2, [
    "Answer-key labels are stripped before ingest; detection reads raw log fields only",
    "The harness is never tuned to look better; rules are tuned against it",
    "Probe tests guard the harness itself and must pass on every commit",
    "Every number on these slides is read from the run's own output files",
    "About 1,900 automated tests, plus stress runs at 10, 30 and 50 GB"], size=14, color=TEXT, after=9)
notes(s, "Accuracy rules are taken from eval_scorecard.json: tolerance 600,000 ms (10 minutes); step match requires the "
         "time gap within tolerance AND the same host AND (same user OR same IP); a label is correct when the technique "
         "(parent or exact sub-technique; a conflicting sub-technique is wrong) AND the tactic match; an attack is "
         "rebuilt when all its steps are in the one matched incident, the LCS ratio in time order is 1.0 and the "
         "backbone positions follow the ground-truth order; a metric whose denominator is zero is null and passes no "
         "target. Integrity of the evaluation: generator labels (threat, rule, labels, event.kind, event.severity) are "
         "removed before ingest and never read by detection code; the harness has its own probe tests in "
         "backend/eval/test_probes.py that must pass on every commit.")

# ---------- 6-8. tier slides ----------
tiers = [
    ("10 GB: every planted attack found, zero false alarms", "g10_home.png",
     [("db", "13.0 M", "events processed, 0 dropped"), ("clock", "4 min 19 s", "end to end"),
      ("chip", "2.6 GB", "peak memory"), ("check_circle", "5 / 5", "attacks rebuilt in order")],
     "Generated ECS logs with 5 planted attacks.  Detection 100 %, labels 100 %, false alarms 0 %.",
     "data/out/g10: detection 100, labels 100, rebuilt 100, strict false alarms 0. 258.5 s wall, 2,552.9 MB peak "
     "RSS, 13,048,132 rows in and ok. Path API p95 26.94 ms."),
    ("30 GB: 95 % of steps found, still zero false alarms", "g30_home.png",
     [("db", "39.1 M", "events processed, 0 dropped"), ("clock", "9 min 56 s", "end to end"),
      ("chip", "3.1 GB", "peak memory"), ("check_circle", "4 / 5", "attacks rebuilt in order")],
     "One miss: the first brute-force step of one attack split off under denser noise. Fix in progress.",
     "data/out/g30: detection 95.24, labels 95.0, rebuilt 80.0, strict false alarms 0. 595.5 s wall, 3,133 MB peak. "
     "The g30 report names the cause: the incident peel drops the S1 T1110 seed under denser noise. Be upfront about "
     "this if asked."),
    ("50 GB tier: real firewall logs, end to end in 23 minutes", "n50_home.png",
     [("db", "62.0 M", "FortiGate log lines"), ("clock", "22 min 47 s", "end to end"),
      ("chip", "4.9 GB", "peak memory"), ("layers", "97.5 k → 3", "alerts merged into incidents")],
     "No answer key, so accuracy is not scored. 43.7 M of the 62.0 M lines share one timestamp second (a filler "
     "block): kept and flagged, not used for detection. The other 18.3 M were analysed.",
     "data/out/b2_n50: 61,970,767 rows in; 43,681,495 flagged timestamp_pileup (kept with ts_ok=false, logged with "
     "the reason); 1,366.9 s wall; 4,937 MB peak; 3 incidents. Do not quote accuracy for this set."),
]
TIER_ALT = [
    "AttackLens UI on the 10 GB run. Score tiles: attacks found 100% (Great), steps detected 100% (Great), false "
    "alarms 0.0% (Great), 13.0 M rows processed in 4 min 19 s. Five incidents sorted by risk: CRITICAL 82 password "
    "guessing on srv-dc-01 then data sent out (77 alerts merged into 1 incident); HIGH 75 password spraying on "
    "srv-web-01 then data sent out; MEDIUM 46 account created on srv-dc-01 then spread to other machines; LOW 36 "
    "PowerShell on ws-hr-012 then called home. Steps of the top incident: password guessing, logged in, moved over "
    "file shares, looked up accounts, packed up data, sent data out.",
    "AttackLens UI on the 30 GB run. Score tiles: attacks found 80.0% (Good), steps detected 95.2% (Great), false "
    "alarms 0.0% (Great), 39.1 M rows in 9 min 56 s. Top incident CRITICAL 95: registry run keys on ws-hr-010 then "
    "files encrypted; 22 alerts merged into 1 incident; 11 steps across 3 machines; 2 more machines within the "
    "attacker's reach, including file server srv-file-01.",
    "AttackLens UI on the 50 GB-tier FortiGate firewall logs. No answer key for this data. 3 incidents found from "
    "97.5 k alerts and 25.0 k episodes; 5 of 15 ATT&CK tactics covered; 18.3 M usable rows analysed in 22 min 47 s. "
    "Top incident MEDIUM 50: ingress tool transfer on 10.10.10.118 then command-and-control traffic to "
    "102.41.214.203; 1,007 alerts merged into 1 incident."]
for k, (title, img, stats, cap, nt) in enumerate(tiers):
    s = new_slide()
    header(s, title)
    picture(s, img, 0.6, 1.4, w=8.5, name=f"AttackLens UI, {title.split(':')[0]} run", alt=TIER_ALT[k])
    for i, (ic, v, l) in enumerate(stats):
        y = 1.4 + i * 1.23
        box(s, 9.65, y, 3.08, 1.08)
        icon(s, 9.82, y + 0.27, 0.54, ic)
        text(s, 10.52, y + 0.1, 2.15, 0.55, v, size=24, bold=True, color=G900)
        text(s, 10.52, y + 0.6, 2.15, 0.4, l, size=12, color=MUTED)
    note_box(s, 0.6, 6.3, 12.13, 0.75, cap, size=13)
    notes(s, nt)

# ---------- 9. scale bars (drawn, not native charts) ----------
s = new_slide()
header(s, "Scales on a 16 GB laptop, far under target",
       "Bars are measured; the dashed line is the organiser's Great target")
cats = ["10 GB", "30 GB", "50 GB tier"]
for p, (ic, ttl, vals, unit, tgt, tlabel, share) in enumerate([
        ("clock", "End-to-end time", (4.3, 9.9, 22.8), " min", 60, "Great: under 60 min",
         "Even the 50 GB tier uses only 38 % of the 1-hour budget"),
        ("chip", "Peak memory", (2.6, 3.1, 4.9), " GB", 8, "Great: under 8 GB",
         "Memory stays bounded: 4.9 GB at the 50 GB tier")]):
    x0 = 0.6 + p * 6.25
    box(s, x0, 1.75, 5.88, 4.85, fill=G50, radius=0.04)
    icon(s, x0 + 0.25, 1.92, 0.5, ic)
    text(s, x0 + 0.9, 1.97, 4.8, 0.45, ttl, size=20, bold=True)
    top, base = 2.85, 5.45                      # plot area (inches)
    scale = (base - top) / (tgt * 1.12)
    ty = base - tgt * scale
    line(s, x0 + 0.35, ty, x0 + 5.55, ty, color=G500, w=2, dash=True)
    text(s, x0 + 3.0, ty - 0.36, 2.55, 0.3, tlabel, size=12, bold=True, color=G500, align=PP_ALIGN.RIGHT)
    line(s, x0 + 0.35, base, x0 + 5.55, base, color=LINE, w=1.25)
    bw, gap = 1.1, 0.55
    bx0 = x0 + (5.88 - (3 * bw + 2 * gap)) / 2
    for i, v in enumerate(vals):
        bx = bx0 + i * (bw + gap)
        h = v * scale
        box(s, bx, base - h, bw, h, fill=MID if i == 2 else G300, radius=0.0, shape=MSO_SHAPE.RECTANGLE)
        text(s, bx - 0.3, base - h - 0.42, bw + 0.6, 0.38, f"{v}{unit}", size=16, bold=True, color=G900,
             align=PP_ALIGN.CENTER)
        text(s, bx - 0.3, base + 0.08, bw + 0.6, 0.35, cats[i], size=13, color=MUTED, align=PP_ALIGN.CENTER)
    text(s, x0 + 0.35, 6.0, 5.2, 0.4, share, size=14, bold=True, color=G800)
note_box(s, 0.6, 6.72, 12.13, 0.5, [("Same laptop for all three runs. ", {"bold": True, "color": G900}),
                                    ("10 GB and 30 GB: generated ECS logs. 50 GB tier: real FortiGate logs, 62.0 M "
                                     "lines.", {})], size=13)
notes(s, "Time grows roughly with data size, and memory stays bounded because DuckDB streams and spills to disk. The "
         "dashed line is the brief's Great target: 1 hour and 8 GB. Measured end-to-end time: 4.3 min (10 GB, 13.0 M "
         "events), 9.9 min (30 GB, 39.1 M events), 22.8 min (50 GB tier, 62.0 M lines). Peak RAM: 2.6, 3.1 and 4.9 GB. "
         "Throughput: about 50,000 to 66,000 rows per second on the generated sets.")

# ---------- 10. graph + evidence ----------
s = new_slide()
header(s, "See the whole attack: graph and raw evidence",
       "The critical incident from the 10 GB run: 77 alerts, 8 steps, 2 machines")
for i, (img, ic, h, b, alt) in enumerate([
        ("crop_graph.png", "graph", "Attack graph", "Hosts, users and IPs; each arrow is one step with its technique.",
         "Attack graph of the critical 10 GB incident: attacker IP 203.0.113.57 -> srv-dc-01 (step 1, T1110 password "
         "guessing); ws-fin-013 -> srv-dc-01 (step 2, T1078 valid accounts); srv-dc-01 -> ws-fin-010 (step 3, T1021 "
         "remote services); user svc_backup -> ws-fin-010 (step 4, T1047 WMI); ws-fin-010 -> 198.51.100.23 (step 8, "
         "T1048 exfiltration). Compromised nodes are highlighted."),
        ("crop_evidence.png", "doc", "Evidence", "The exact raw log lines behind every step, so an analyst can verify.",
         "Evidence tab: a table of step, time, host, ATT&CK technique and the raw JSON log line, e.g. step 1 at "
         "02:00:00 on srv-dc-01, T1110.001, failed user_logon events; step 2 T1078 successful logon; step 3 on "
         "ws-fin-010, T1021.002.")]):
    x = 0.6 + i * 6.25
    pic = picture(s, img, x, 1.8, w=5.88, name=h, alt=alt)
    y = 1.8 + Emu(pic.height).inches + 0.28
    icon(s, x, y + 0.05, 0.55, ic)
    text(s, x + 0.75, y, 5.1, 0.4, h, size=18, bold=True)
    text(s, x + 0.75, y + 0.42, 5.1, 0.75, b, size=14, color=MUTED)
notes(s, "Graph and evidence from the critical incident in the 10 GB run. The evidence tab answers 'show me the log "
         "line': every step links back to the raw text it came from.")

# ---------- 11. reach next ----------
s = new_slide()
header(s, "Know what the attacker can reach next", "From the 30 GB run: ransomware incident on ws-hr-010, risk 95")
picture(s, "crop_reach.png", 0.6, 1.8, w=12.13, name="Reach next tab",
        alt="Reach next tab for the CRITICAL 95 incident 'Set to auto-start on ws-hr-010 -> encrypted files' (22 "
            "alerts, 11 steps, 3 machines). Table: srv-file-01, 1 hop via svc_backup, crown jewel FILE, untouched, "
            "evidence 4624 type 3 + 4672 at 2026-10-21T10:05Z; srv-db-01, 2 hops via svc_backup, crown jewel DB, "
            "untouched, evidence allowed flow srv-file-01 -> 10.10.0.40:22.")
for i, (ic, h, l1, l2) in enumerate([
        ("folder", "srv-file-01", "1 hop via svc_backup · file server", "Proof: logon 4624 type 3 + 4672 admin"),
        ("db", "srv-db-01", "2 hops via svc_backup · database", "Proof: allowed flow srv-file-01 → 10.10.0.40:22"),
        ("shield", "Why it matters", "The analyst knows which crown jewels", "to protect first, before the move.")]):
    x = 0.6 + i * 4.12
    box(s, x, 5.85, 3.88, 1.0, fill=G100 if i < 2 else G50)
    icon(s, x + 0.18, 6.05, 0.55, ic)
    text(s, x + 0.9, 5.9, 2.9, 0.38, h, size=16, bold=True, color=G900)
    text(s, x + 0.9, 6.26, 2.9, 0.6, [l1, l2], size=12, color=MUTED)
notes(s, "Reach-next is a breadth-first search from compromised hosts and accounts over admin rights and observed "
         "network flows. Each target comes with the log line that proves the path exists.")

# ---------- 12. report ----------
s = new_slide()
header(s, "The incident report writes itself, safely")
picture(s, "crop_report.png", 0.6, 1.5, w=6.6, name="Incident report tab",
        alt="Incident report for inc-4ba8f08b: risk 82/100, time span 2026-10-24 02:00 to 02:54 UTC, 77 alerts in 11 "
            "episodes, entry point password guessing on svc_backup from 203.0.113.57 against srv-dc-01. Summary lists "
            "the ATT&CK techniques in order: T1110.001 Password Guessing, T1078 Valid Accounts, T1021.002 SMB/Windows "
            "Admin Shares, T1047 and onward.")
for i, (ic, h, b) in enumerate([
        ("copy", "Plain English, ready to paste", "Who, what, when, which hosts, which ATT&CK techniques, in order."),
        ("robot", "AI only sees placeholders", "The model gets {{HOST_1}}, {{USER_1}} and enum values, never raw logs."),
        ("key", "Never blocks the demo", "No API key, any error or an unknown token → a deterministic template."),
        ("chart", "Same numbers as the UI", "Risk, time span and alerts merged come from the same incident file.")]):
    y = 1.5 + i * 1.22
    icon(s, 7.6, y + 0.05, 0.55, ic)
    text(s, 8.35, y, 4.38, 0.4, h, size=17, bold=True)
    text(s, 8.35, y + 0.4, 4.38, 0.75, b, size=14, color=MUTED)
notes(s, "Bonus B-2. The narrative model never sees raw logs: entities are swapped for placeholders before the call and "
         "swapped back after. With no key, as in this demo, the deterministic template writes the report.")

# ---------- 13. connectors ----------
s = new_slide()
header(s, "Pull logs straight from the SIEM or cloud you already use")
picture(s, "crop_connections.png", 0.6, 1.55, w=7.4, name="Connections page",
        alt="Connections page with 11 connectors. SIEM pull: Elastic/OpenSearch, Splunk, Microsoft Sentinel, Syslog/CEF "
            "listener (QRadar, ArcSight). Cloud pull: AWS CloudTrail, Azure Activity Log + Entra ID, Google Cloud Audit "
            "Logs. Send incidents to: Splunk HTTP Event Collector, Elasticsearch, Webhook (SOAR, Logic App, Slack, "
            "Teams), Syslog CEF.")
for i, (ic, h, b) in enumerate([
        ("siem", "Pull from a SIEM", "Splunk · Elastic / OpenSearch · Microsoft Sentinel · Syslog / CEF (QRadar, ArcSight)"),
        ("cloud", "Pull from the cloud", "AWS CloudTrail · Azure Activity Log + Entra ID sign-in · Google Cloud Audit"),
        ("send", "Send incidents back", "Splunk HEC · Elasticsearch · Webhook (SOAR, Logic App, Slack, Teams) · Syslog"),
        ("upload", "Or just add files", "Upload logs, or point at a 10–50 GB file on the machine: no terminal")]):
    y = 1.55 + i * 1.2
    icon(s, 8.3, y + 0.03, 0.55, ic)
    text(s, 9.05, y, 3.7, 0.4, h, size=16, bold=True)
    text(s, 9.05, y + 0.38, 3.7, 0.8, b, size=13, color=MUTED)
note_box(s, 0.6, 6.45, 12.13, 0.6, [("11 connectors built in (7 pull, 4 push). ", {"bold": True, "color": G900}),
                                    ("Each uses the customer's own credentials; today's demo runs on local files.",
                                     {})], size=14)
notes(s, "AttackLens sits on top of the SIEM a SOC already runs: it pulls events or alerts, builds the attack story, and "
         "pushes finished incidents back to a SIEM, SOAR or chat. Be accurate: the connectors are built but need real "
         "credentials; we have not pulled from a live customer tenant at the venue.")

# ---------- 14. tamper check ----------
s = new_slide()
header(s, "Can you trust the logs? Built-in tamper check")
picture(s, "crop_integrity.png", 0.6, 1.5, h=5.35, name="Tamper verdict popup",
        alt="Popup: 'These logs appear to be TAMPERED', trust score 52/100, full check of files and events. Findings: "
            "1 critical - security audit log cleared (event 1102) on host srv-file-01 at 2026-10-25 14:55 UTC, with "
            "the raw log line; 4 low - collection gaps where all hosts went silent. Buttons: view full health report, "
            "continue anyway.")
icon(s, 5.85, 1.55, 0.6, "shield")
text(s, 6.6, 1.55, 6.13, 0.75, "Before analysis, AttackLens checks every log set and gives it a trust score from "
     "0 to 100 and a verdict:", size=15)
for i, (lbl, f, c) in enumerate([("TRUSTED", G100, G700), ("SUSPECT", AMBER_T, AMBER), ("TAMPERED", RED_T, RED)]):
    chip(s, 5.85 + i * 1.75, 2.45, 1.55, 0.42, lbl, f, c, size=13)
text(s, 5.85, 3.1, 6.9, 0.4, "10 checks", size=16, bold=True)
for i, c in enumerate(["File seal (hash)", "Zeroed regions", "Truncated tail", "Log cleared (event 1102)",
                       "Silence gaps", "Hosts going dark", "Timestamp anomalies", "Duplicate lines",
                       "Embedded-time mismatch", "Rows dropped in ingest"]):
    col, row = divmod(i, 5)
    y, x = 3.55 + row * 0.42, 5.85 + col * 3.45
    icon(s, x, y + 0.05, 0.27, "check", "FFFFFF", "22A06B")
    text(s, x + 0.4, y, 3.0, 0.38, c, size=14)
box(s, 5.85, 5.75, 6.88, 0.82, fill=G100, radius=0.08)
text(s, 6.05, 5.82, 6.5, 0.7, [[("Example (demo set): ", {"bold": True, "color": G900}),
                                 ("security log cleared (event 1102) on srv-file-01 plus collection gaps → ", {}),
                                 ("TAMPERED", {"bold": True, "color": RED}), (", trust 52 / 100.", {})]], size=14)
notes(s, "Attackers clear logs. If the evidence is edited, the attack story is wrong. AttackLens runs ten integrity checks "
         "and writes integrity_report.json with a verdict. The screenshot is the demo set where the security log was "
         "cleared on srv-file-01: verdict TAMPERED, trust 52/100 (data/out/demo_fixB/integrity_report.json).")

# ---------- 15. requirements ----------
s = new_slide()
header(s, "Every must-have and every bonus requirement covered")
fr = [("FR-1", "Stream without loading all into memory", "62 M lines at 4.9 GB peak"),
      ("FR-2", "Detect suspicious events", "41 rules + Sigma + 88 cloud rules"),
      ("FR-3", "Map to ATT&CK technique + stage", "ATT&CK v20, 15 tactics"),
      ("FR-4", "Link by host, user, IP and time", "4 keyed joins (R1–R4)"),
      ("FR-5", "Timeline and graph", "Step-by-step and Graph tabs"),
      ("FR-6", "What the attacker can reach next", "Hops via accounts and network flows"),
      ("FR-7", "Simple API and README", "GET /api/incidents/{id}/path")]
bo = [("B-1", "Risk score, worst on top", "e.g. CRITICAL 95, HIGH 75"),
      ("B-2", "Plain-English incident report", "Template, or LLM on placeholders"),
      ("B-3", "Raw alerts merged per incident", "e.g. 77 alerts → 1 incident"),
      ("B-4", "New rule by editing config", "rules.yaml and Sigma YAML"),
      ("B-5", "Live mode", "Tails new lines every 2 s")]
for gi, (label, lst, x) in enumerate([("Must have", fr, 0.6), ("Bonus", bo, 6.85)]):
    text(s, x, 1.5, 5.88, 0.4, label, size=18, bold=True, color=G500 if gi else G900)
    for i, (code, req, proof) in enumerate(lst):
        y = 1.98 + i * 0.68
        box(s, x, y, 5.88, 0.58, fill=G50, radius=0.15)
        icon(s, x + 0.12, y + 0.13, 0.32, "check", "FFFFFF", "22A06B")
        text(s, x + 0.55, y + 0.06, 0.6, 0.45, code, size=13, bold=True, color=MUTED, anchor=MSO_ANCHOR.MIDDLE)
        text(s, x + 1.12, y + 0.03, 2.55, 0.52, req, size=13, bold=True, anchor=MSO_ANCHOR.MIDDLE)
        text(s, x + 3.7, y + 0.03, 2.12, 0.52, proof, size=12, color=MUTED, anchor=MSO_ANCHOR.MIDDLE)
box(s, 6.85, 5.55, 5.88, 1.22, fill=G100, radius=0.08)
icon(s, 7.05, 5.75, 0.45, "star")
text(s, 7.65, 5.68, 4.95, 0.35, "Beyond the brief", size=15, bold=True, color=G900)
text(s, 7.65, 6.05, 4.95, 0.85, "Docker Compose one-command start · log tamper check · SIEM and cloud connectors · "
     "about 1,900 automated tests", size=13)
notes(s, "Left is the brief's must-have list (FR-1 to FR-7), right is the bonus list (B-1 to B-5), each with the proof "
         "we can show live. FR-1: the 50 GB tier, 62.0 M lines, peaked at 4.9 GB RAM. FR-7: FastAPI endpoint "
         "GET /api/incidents/{id}/path plus a README. B-4: rules and thresholds are YAML in config/, Sigma rules are "
         "YAML. B-5: live mode tails new log lines every 2 seconds and recomputes only changed incidents.")

# ---------- 20. judging criteria ----------
s = new_slide()
header(s, "How AttackLens meets the judging criteria",
       "The five criteria from the hackathon rules, each backed by evidence shown in this deck")
for i, (ic, h, items) in enumerate([
        ("gear", "Technical execution", ["62.0 M log lines in 22 min 47 s at 4.9 GB peak RAM",
                                         "DuckDB streaming with a 5 GB cap; every row accounted for",
                                         "About 1,900 automated tests; one-command Docker start"]),
        ("bolt", "Innovation", ["Every link between steps explains itself in a sentence",
                                "Kill-chain-ordered attack path plus attacker reach-next",
                                "Tamper check before analysis; AI reports without raw logs"]),
        ("shield", "Cybersecurity relevance", ["MITRE ATT&CK v20 labels: 15 tactics, techniques and sub-techniques",
                                               "Sigma rules; Windows, FortiGate, CloudTrail, Azure and GCP logs",
                                               "Built around the SOC analyst's investigation flow"]),
        ("people", "Usability", ["Upload a file or point at one; no terminal needed",
                                 "Incidents sorted by risk, each with a plain-English story",
                                 "Graph, timeline and evidence; a path opens in 17–27 ms"]),
        ("target", "Impact", ["97,500 raw alerts reduced to 3 incidents",
                              "77 alerts merged into 1 readable attack story",
                              "Runs offline on a 16 GB laptop, with no cloud cost"])]):
    x = 0.6 + i * (2.29 + 0.165)
    box(s, x, 1.85, 2.29, 4.6)
    icon(s, x + 0.22, 2.05, 0.62, ic)
    text(s, x + 0.22, 2.85, 1.95, 0.75, h, size=18, bold=True, color=G900)
    bullets(s, x + 0.22, 3.65, 1.92, 3.3, items, size=13, after=8)
notes(s, "Mapping to the hackathon judging criteria (PRD section 5: technical execution, innovation, cybersecurity "
         "relevance, usability, impact). Technical execution: data/out/b2_n50/run_metrics.json shows 61,970,767 rows in "
         "1,366.9 s with 4,937 MB peak RSS; every ingest writes ingest_accounting.json. Innovation: explainable link "
         "rules R1-R4 with why_linked sentences, path dynamic programming in tactic order, reach-next breadth-first "
         "search over admin rights and network flows, ten-check log integrity verdict, placeholder-only LLM narrative. "
         "Cybersecurity relevance: ATT&CK v20 with 15 tactics, Sigma via pySigma, nine log formats, SIEM and cloud "
         "connectors. Usability: web UI with upload, risk-sorted incidents, report, graph, timeline, evidence; path "
         "API p95 26.94 ms at 10 GB and 17.01 ms at 30 GB. Impact: 50 GB tier 97.5 k alerts linked into 3 incidents; "
         "10 GB critical incident merges 77 alerts.")

# ---------- 21. advantages ----------
s = new_slide()
header(s, "Why AttackLens is different")
for i, (ic, h, b) in enumerate([
        ("graph", "A story, not alerts", "97.5 k raw alerts became 3 incidents an analyst can read in a minute."),
        ("chart", "Measured, never claimed", "A strict harness scores every run against planted ground truth. "
                                             "No number is typed by hand."),
        ("laptop", "Runs on one laptop, offline", "50 GB tier in 23 min at 4.9 GB RAM. No cloud, no network needed."),
        ("db", "Nothing silently lost", "Every log line is counted in, accepted or flagged, with the reason."),
        ("robot", "Safe AI", "The report model sees placeholders like {{HOST_1}}, never raw logs."),
        ("puzzle", "Fits the SOC you have", "Pulls from Splunk, Sentinel, Elastic, AWS, Azure, GCP; pushes "
                                           "incidents back to SIEM or SOAR.")]):
    col, row = i % 3, i // 3
    x, y = 0.6 + col * 4.12, 1.6 + row * 2.6
    box(s, x, y, 3.88, 2.35)
    icon(s, x + 0.25, y + 0.25, 0.66, ic)
    text(s, x + 0.25, y + 1.05, 3.4, 0.45, h, size=18, bold=True)
    text(s, x + 0.25, y + 1.5, 3.4, 0.85, b, size=14, color=MUTED)
notes(s, "For a SOC like Mitigata's: the analyst gets the attack story, not another alert queue; the numbers are "
         "provable; it runs offline on a laptop; and the AI part is safe by design.")

# ---------- 17. honest limits / next ----------
s = new_slide()
header(s, "What we are fixing next", "We report our weak spots as clearly as our strengths")
for i, (ic, h, b) in enumerate([
        ("pulse", "30 GB: 1 of 5 attacks rebuilt only partly", "The brute-force first step split off under denser "
                                                               "noise. Fix: keep entry-point seeds attached."),
        ("question", "50 GB tier has no answer key", "Next: plant known attacks into the real FortiGate logs and "
                                                     "score them with the same harness."),
        ("clock", "A filler block in the firewall logs", "43.7 M lines share one timestamp second. Already handled: "
                                                         "kept, flagged, excluded from detection."),
        ("cloud", "Connectors tested offline only", "Next: a live pull from a real Splunk or Sentinel tenant.")]):
    col, row = i % 2, i // 2
    x, y = 0.6 + col * 6.25, 1.85 + row * 1.85
    box(s, x, y, 5.88, 1.6, fill=G50)
    icon(s, x + 0.25, y + 0.3, 0.6, ic)
    text(s, x + 1.05, y + 0.22, 4.65, 0.45, h, size=17, bold=True)
    text(s, x + 1.05, y + 0.72, 4.65, 0.85, b, size=14, color=MUTED)
box(s, 0.6, 5.95, 12.13, 0.85, fill=LG, radius=0.15)
icon(s, 0.85, 6.1, 0.55, "flag", "0B3D2E", "8CCFAD")
text(s, 1.6, 6.0, 10.9, 0.75, [[("Where it goes next: ", {"bold": True, "color": G900}),
                                ("the attack-story layer on top of an AI-run SOC such as Gordon AI.", {"color": TEXT})]],
     size=16, anchor=MSO_ANCHOR.MIDDLE)
notes(s, "Judges reward honesty. These four items are real and come from our own stress reports (reports/stress/g30.md "
         "and the 50 GB-tier ingest accounting).")

# ---------- 18. closing ----------
s = new_slide(dark=True)
icon(s, 0.7, 0.85, 0.8, "shield", "0B3D2E", "8CCFAD")
text(s, 0.7, 1.85, 11.9, 1.0, "One attack story, not 97,500 alerts", size=44, bold=True, color=G900)
text(s, 0.7, 2.95, 11.9, 0.8, "AttackLens detects, labels, links and explains attacks in 10–50 GB of logs, on one "
     "laptop, with every number measured.", size=20, color=TEXT)
box(s, 0.7, 4.1, 7.2, 1.45, fill=WHITE, radius=0.08)
icon(s, 0.95, 4.3, 0.5, "code", "0B3D2E", "8CCFAD")
text(s, 1.65, 4.25, 6.0, 0.4, "Run it yourself", size=16, bold=True, color=G900)
text(s, 1.65, 4.68, 6.0, 0.85, ["docker compose up -d", "open http://localhost:8000"], size=17, color=TEXT, after=4)
box(s, 8.3, 4.1, 4.43, 1.45, fill=WHITE, radius=0.08)
icon(s, 8.5, 4.3, 0.5, "people")
text(s, 9.2, 4.25, 3.4, 0.4, TEAM, size=18, bold=True, color=G900)
text(s, 9.2, 4.7, 3.4, 0.8, ["Harish Kandi", "Veeranarayana Gorantla"], size=15, color=TEXT, after=2)
text(s, 0.7, 6.3, 11.9, 0.5, "Thank you  ·  Live demo next", size=20, bold=True, color=G700)
notes(s, "Close on the one-line message, then switch to the live UI. The Docker command builds the image and serves the "
         "UI and API on localhost:8000.")

assert len(prs.slides) == TOTAL, len(prs.slides)
prs.save(OUT)

# Theme fonts → Times New Roman (tables and any default text follow the theme).
tmp = OUT + ".tmp"
with zipfile.ZipFile(OUT) as zin, zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as zout:
    for item in zin.infolist():
        data = zin.read(item.filename)
        if item.filename.startswith("ppt/theme/") and item.filename.endswith(".xml"):
            xml = re.sub(r'(<a:(?:latin|ea|cs) typeface=")[^"]*(")', r"\g<1>" + FONT + r"\2", data.decode("utf-8"))
            data = xml.encode("utf-8")
        zout.writestr(item, data)
shutil.move(tmp, OUT)
print("wrote", OUT)
