"""
Log exporters (Member 6) - used by scripts/export_logs.py and the dashboard.

  * JSONL : one JSON object per line, ready for Splunk / ELK ingestion
  * CSV   : one spreadsheet per table (opens in Excel)
  * MISP  : a MISP event (JSON) with attacker IPs, URLs, user agents and
            ATT&CK techniques, ready to import into a MISP instance
"""
import csv
import io
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterable, List

from app.core.classifiers import get_http_mitre, get_ssh_mitre

TABLES = ('sessions', 'auth_attempts', 'interactions', 'ip_intel')
URL_RE = re.compile(r'\b(?:https?|ftp)://[^\s\'"|;&]+', re.IGNORECASE)


def iter_events(db) -> Iterable[Dict]:
    """Flatten the database into events: one per session, login attempt and interaction."""
    intel = {row['ip_address']: row for row in db.iter_table('ip_intel')}
    sessions = {row['session_id']: row for row in db.iter_table('sessions')}

    def base(session_id):
        s = sessions.get(session_id, {})
        geo = intel.get(s.get('source_ip'), {})
        return {'session_id': session_id, 'src_ip': s.get('source_ip'), 'dest_port': s.get('dest_port'),
                'protocol': s.get('protocol'), 'country': geo.get('country_code')}

    for s in sessions.values():
        yield {**base(s['session_id']), 'event_type': 'session', 'timestamp': s['started_at'],
               'ended_at': s['ended_at'], 'duration_seconds': s['duration_seconds'],
               'user_agent': s['user_agent'], 'ssh_client_version': s['ssh_client_version'],
               'total_interactions': s['total_interactions']}
    for a in db.iter_table('auth_attempts'):
        yield {**base(a['session_id']), 'event_type': 'auth_attempt', 'timestamp': a['timestamp'],
               'username': a['username'], 'auth_method': a['auth_method'], 'success': bool(a['success'])}
    for i in db.iter_table('interactions'):
        event = {**base(i['session_id']), 'event_type': i['interaction_type'], 'timestamp': i['timestamp']}
        if i['interaction_type'] == 'http_request':
            event.update(http_method=i['http_method'], http_path=i['http_path'],
                         http_query=i['http_query_params'], attack_signature=i['attack_signature'],
                         mitre_technique=get_http_mitre(i['attack_signature'] or ''))
        else:
            event.update(command=i['command'], classification=i['command_classification'],
                         mitre_technique=get_ssh_mitre(i['command_classification'] or ''))
        yield event


def to_jsonl(db) -> str:
    events = sorted(iter_events(db), key=lambda e: e.get('timestamp') or '')
    return ''.join(json.dumps(e, ensure_ascii=False) + '\n' for e in events)


def to_csv(db, table: str) -> str:
    if table not in TABLES:
        raise ValueError(f'table must be one of {TABLES}')
    rows = list(db.iter_table(table))
    out = io.StringIO()
    if rows:
        writer = csv.DictWriter(out, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    return '﻿' + out.getvalue()   # BOM so Excel reads UTF-8 correctly


def to_misp(db) -> Dict:
    """Build one MISP event describing everything the honeypot saw."""
    now = datetime.now(timezone.utc)
    attributes: List[Dict] = []
    seen = set()

    def add(attr_type, category, value, comment='', to_ids=False):
        key = (attr_type, value)
        if not value or key in seen:
            return
        seen.add(key)
        attributes.append({'uuid': str(uuid.uuid4()), 'type': attr_type, 'category': category,
                           'value': str(value)[:1024], 'to_ids': to_ids, 'comment': comment})

    intel = {row['ip_address']: row for row in db.iter_table('ip_intel')}
    for s in db.iter_table('sessions'):
        geo = intel.get(s['source_ip'], {})
        if geo.get('country_code') in ('PRIVATE', 'RESERVED'):
            continue
        add('ip-src', 'Network activity', s['source_ip'],
            f"{s['protocol'].upper()} honeypot; country={geo.get('country_code') or '?'}", to_ids=True)
        add('user-agent', 'Network activity', s['user_agent'])
        add('text', 'Other', s['ssh_client_version'], 'SSH client version')

    techniques = set()
    for i in db.iter_table('interactions'):
        if i['interaction_type'] == 'http_request':
            technique = get_http_mitre(i['attack_signature'] or '')
            if i['attack_signature'] not in (None, 'benign', 'scan'):
                add('text', 'Payload delivery', f"{i['http_method']} {i['http_path']}", i['attack_signature'])
        else:
            technique = get_ssh_mitre(i['command_classification'] or '')
            for url in URL_RE.findall(i['command'] or ''):
                add('url', 'Payload delivery', url, 'URL used in attacker command', to_ids=True)
            if i['command_classification'] not in (None, 'benign', 'recon', 'unknown'):
                add('text', 'Artifacts dropped', i['command'], i['command_classification'])
        if technique:
            techniques.add(technique)

    usernames = sorted({a['username'] for a in db.iter_table('auth_attempts')})
    if usernames:
        add('text', 'Other', ', '.join(usernames[:200]), 'Usernames tried against the honeypot')

    tags = [{'name': 'tlp:amber'}, {'name': 'honeypot'}] + \
           [{'name': f'mitre-attack:{t}'} for t in sorted(techniques)]
    return {'Event': {
        'uuid': str(uuid.uuid4()),
        'info': f'Network honeypot activity export {now.strftime("%Y-%m-%d %H:%M UTC")}',
        'date': now.strftime('%Y-%m-%d'),
        'timestamp': str(int(now.timestamp())),
        'threat_level_id': '3',     # low
        'analysis': '2',            # completed
        'distribution': '0',        # your organisation only
        'Tag': tags,
        'Attribute': attributes,
    }}
