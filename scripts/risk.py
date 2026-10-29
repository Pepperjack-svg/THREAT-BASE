"""Transparent policy score, never an estimate of asset compromise probability."""
from datetime import datetime, timezone


DEFAULT_WEIGHTS = {'kev': 50, 'epss': 25, 'cvss': 15, 'exposure': 10, 'remediation_gap': 5, 'stale': 5}


def prioritize(records, weights=None, exposed=None):
    weights = weights or DEFAULT_WEIGHTS
    rejected = any(str(row.get('state', '')).upper() in ('REJECTED', 'WITHDRAWN') for row in records)
    kev = any(row.get('kev', {}).get('listed') for row in records if row.get('kev'))
    epss_rows = [r['epss'] for r in records if r.get('epss')]
    epss = max(epss_rows, key=lambda x: x['date']) if epss_rows else None
    scores = [float(m['baseScore']) for r in records for m in r.get('cvss', []) if m.get('baseScore') is not None]
    cvss = max(scores) if scores else None
    remediation = any(r['fixed_versions'] or any(ref.get('type') == 'remediation' for ref in r['references']) for r in records)
    stale = any(r.get('stale') for r in records)
    score = weights['kev'] * kev + weights['epss'] * (epss['epss'] if epss else 0) + weights['cvss'] * ((cvss or 0) / 10) + weights['exposure'] * (exposed is True)
    score += weights.get('remediation_gap', 0) * (not remediation) + weights.get('stale', 0) * stale
    return {'policy_score': round(score, 2) if records and not rejected else None, 'record_conflict_or_withdrawal': rejected,
            'confirmed_exploitation': kev, 'epss': epss, 'technical_cvss_max': cvss,
            'asset_exposure': exposed, 'remediation_available': remediation, 'stale_data': stale,
            'missing': [name for name, value in [('epss', epss), ('cvss', cvss), ('asset_exposure', exposed)] if value is None]}
