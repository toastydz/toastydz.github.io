"""Validate local image/link targets in generated HTML, including filename case."""
from pathlib import Path
from html.parser import HTMLParser
from urllib.parse import urlsplit, unquote
import posixpath

root = Path(__file__).resolve().parents[1] / 'site'
files = {p.relative_to(root).as_posix() for p in root.rglob('*') if p.is_file()}
errors = []
class Links(HTMLParser):
    def handle_starttag(self, tag, attrs):
        for key, value in attrs:
            if key not in ('href', 'src') or not value:
                continue
            url = urlsplit(value)
            if url.scheme or url.netloc or not url.path or url.path.startswith('/'):
                continue
            target = posixpath.normpath(str(page.parent.relative_to(root)).replace('\\', '/') + '/' + unquote(url.path))
            if target not in files and target.rstrip('/') + '/index.html' not in files:
                errors.append(f'{page.relative_to(root)}: {value}')
for page in root.rglob('*.html'):
    Links().feed(page.read_text(encoding='utf-8'))
print('\n'.join(errors) if errors else f'All local links and images resolve across {len(list(root.rglob("*.html")))} HTML pages.')
raise SystemExit(bool(errors))
