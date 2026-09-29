# ToastyDZ · Hack The Box writeups

Searchable walkthroughs with syntax-highlighted code, copy buttons, screenshots, and light/dark themes. [Browse the Markdown](Machines/README.md).

## Publish on GitHub

1. Add the project files to your repository's `main` branch, including `.github/workflows/pages.yml`. Do not upload `.venv/` or `site/`.
2. Under **Settings → Pages → Build and deployment**, choose **GitHub Actions**.
3. Run **Actions → Publish writeups**, or push another commit to `main`.
4. The deployment provides your site URL, usually `https://USERNAME.github.io/REPOSITORY/`.

Pushes to `main` or `master` build and publish automatically. Pull requests build without deploying. Only `Machines/` is included in the website. `ActiveMachines/` is outside the website build but remains visible if uploaded to a public repository.

## Preview locally

With Python 3.12 installed, run:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m mkdocs serve
```

Open the address printed by MkDocs. Check the production build with:

```powershell
.\.venv\Scripts\python.exe -m mkdocs build --strict
```

## Add a writeup

1. Copy [the template](templates/writeup.md) into the appropriate folder under `Machines/`.
2. Add screenshots using relative Markdown links; match filename capitalization exactly.
3. Add the page to `nav` in `mkdocs.yml` and the collection overview.
4. Preview, build, commit, and push.

Use `bash`, `python`, or `powershell` code fences for commands/scripts, `console` for transcripts, and `text` for plain output. Explain what each result tells you before the next step. Keep one top-level heading per page.
