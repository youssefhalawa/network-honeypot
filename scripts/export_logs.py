"""
Export captured honeypot data (Member 6)

    python scripts/export_logs.py                 # everything into data/exports/
    python scripts/export_logs.py --format jsonl  # only JSONL (Splunk / ELK)
    python scripts/export_logs.py --format csv    # one CSV per table (Excel)
    python scripts/export_logs.py --format misp   # MISP event JSON
    python scripts/export_logs.py --out /tmp/x    # choose the folder
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.config import Config  # noqa: E402
from app.storage.database import Database  # noqa: E402
from app.storage.exporters import TABLES, to_csv, to_jsonl, to_misp  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description='Export honeypot data')
    parser.add_argument('--format', choices=['jsonl', 'csv', 'misp', 'all'], default='all')
    parser.add_argument('--out', default=str(Path(Config.BASE_DIR) / 'data' / 'exports'))
    parser.add_argument('--db', default=Config.DATABASE_PATH, help='database file (default from .env)')
    args = parser.parse_args()

    if not Path(args.db).exists():
        print(f'[x] Database not found: {args.db}. Run the honeypot first.')
        return 1

    db = Database(args.db)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
    written = []

    if args.format in ('jsonl', 'all'):
        path = out / f'honeypot_events_{stamp}.jsonl'
        path.write_text(to_jsonl(db), encoding='utf-8')
        written.append(path)
    if args.format in ('csv', 'all'):
        for table in TABLES:
            path = out / f'{table}_{stamp}.csv'
            path.write_text(to_csv(db, table), encoding='utf-8')
            written.append(path)
    if args.format in ('misp', 'all'):
        path = out / f'misp_event_{stamp}.json'
        path.write_text(json.dumps(to_misp(db), indent=2, ensure_ascii=False), encoding='utf-8')
        written.append(path)

    for path in written:
        print(f'[✓] {path}  ({path.stat().st_size:,} bytes)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
