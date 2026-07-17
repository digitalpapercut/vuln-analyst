#!/usr/bin/env python3
"""Build release artifacts into dist/:

1. One self-contained ZIP per skill, ready to upload in Claude
   (Customize > Skills > + > upload): each ZIP contains the skill folder at
   its root with SKILL.md and a private copy of scripts/, and script paths
   in SKILL.md rewritten from `scripts/` to `<skill>/scripts/`-relative.
2. A full-repo ZIP for clone-averse users.

Usage:  python3 tools/make_release.py [--version 1.0.0]
"""
import argparse
import os
import re
import shutil
import zipfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
SKILLS = os.path.join(ROOT, "skills")
SCRIPTS = os.path.join(ROOT, "scripts")


def zip_dir(zip_path, src_dir, arc_root, exclude_dirs=()):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for base, dirs, files in os.walk(src_dir):
            dirs[:] = [d for d in dirs
                       if d != "__pycache__" and d not in exclude_dirs]
            for f in files:
                if f.endswith(".pyc"):
                    continue
                full = os.path.join(base, f)
                rel = os.path.relpath(full, src_dir)
                z.write(full, os.path.join(arc_root, rel))


def build_skill_zip(name, version):
    stage = os.path.join(DIST, "_stage", name)
    if os.path.exists(stage):
        shutil.rmtree(stage)
    shutil.copytree(os.path.join(SKILLS, name), stage)
    shutil.copytree(SCRIPTS, os.path.join(stage, "scripts"))

    skill_md = os.path.join(stage, "SKILL.md")
    with open(skill_md, encoding="utf-8") as f:
        body = f.read()
    # `python3 scripts/x.py` works unchanged because scripts/ now lives
    # inside the skill folder; just add a portability note.
    if "## Bundled scripts" not in body:
        body += ("\n## Bundled scripts\n\n"
                 "This packaged skill bundles its data scripts under its own "
                 "`scripts/` directory. Run them relative to this skill's "
                 "folder. They require outbound HTTPS to the public data "
                 "sources listed in each script's docstring; if a fetch "
                 "fails in a restricted environment, report the blocked "
                 "domain to the user rather than answering from memory.\n")
    with open(skill_md, "w", encoding="utf-8") as f:
        f.write(body)

    out = os.path.join(DIST, f"{name}-{version}.zip")
    zip_dir(out, stage, name)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", default="1.0.0")
    args = ap.parse_args()

    os.makedirs(DIST, exist_ok=True)
    built = []
    for name in sorted(os.listdir(SKILLS)):
        if os.path.isfile(os.path.join(SKILLS, name, "SKILL.md")):
            built.append(build_skill_zip(name, args.version))

    full = os.path.join(DIST, f"vuln-analyst-agent-{args.version}.zip")
    zip_dir(full, ROOT, "vuln-analyst-agent", exclude_dirs=("dist", ".git"))
    built.append(full)

    shutil.rmtree(os.path.join(DIST, "_stage"), ignore_errors=True)
    print("Built:")
    for b in built:
        print(" ", os.path.relpath(b, ROOT))


if __name__ == "__main__":
    main()
