"""Loss-aware normalization. Source evidence remains separate; aliases are exact."""
import re
from scripts.common import CVE


def normalize(source, kind, identifier, raw):
    row = dict(id=identifier, source=source, aliases=[], title=None, description=None,
               published=None, modified=None, state=None, cvss=[], severity=None,
               cwes=[], vendors=[], products=[], packages=[], affected=[], cpes=[], fixed_versions=[],
               references=[], exploit_references=[], kev=None, epss=None, disputed=False)
    if kind == 'kev':
        row.update(title=raw.get('vulnerabilityName'), description=raw.get('shortDescription'),
                   vendors=[raw['vendorProject']] if raw.get('vendorProject') else [],
                   products=[raw['product']] if raw.get('product') else [], cwes=raw.get('cwes', []),
                   kev={'listed': True, 'date_added': raw.get('dateAdded'), 'due_date': raw.get('dueDate'), 'required_action': raw.get('requiredAction'), 'ransomware': raw.get('knownRansomwareCampaignUse')})
        row['references'] = [{'url': url, 'type': 'remediation'} for url in re.findall(r'https?://[^\s;]+', raw.get('notes', ''))]
    elif kind == 'epss':
        row['epss'] = {k: raw[k] for k in ('epss', 'percentile', 'date')}
    elif kind == 'cve':
        meta = raw['cveMetadata']
        if meta['cveId'] != identifier:
            raise ValueError('CVE identifier mismatch')
        cna = raw.get('containers', {}).get('cna', {})
        row['disputed'] = 'disputed' in [str(tag).lower() for tag in cna.get('tags', [])]
        row['affected'] = cna.get('affected', [])
        row.update(state=meta['state'], published=meta.get('datePublished'), modified=meta.get('dateUpdated'), title=cna.get('title'))
        descriptions = cna.get('descriptions', cna.get('rejectedReasons', []))
        row['description'] = next((d.get('value') for d in descriptions if d.get('lang', '').startswith('en')), None)
        for container in [cna] + raw.get('containers', {}).get('adp', []):
            row['references'].extend(container.get('references', []))
            for metric in container.get('metrics', []):
                row['cvss'].extend(value for key, value in metric.items() if key.startswith('cvssV') and isinstance(value, dict))
            for problem in container.get('problemTypes', []):
                row['cwes'].extend(d['cweId'] for d in problem.get('descriptions', []) if d.get('cweId'))
        for affected in cna.get('affected', []):
            if affected.get('vendor'):
                row['vendors'].append(affected['vendor'])
            if affected.get('product'):
                row['products'].append(affected['product'])
            row['cpes'].extend(affected.get('cpes', []))
            if affected.get('packageName'):
                row['packages'].append({'name': affected['packageName'], 'ecosystem': affected.get('collectionURL'), 'versions': affected.get('versions', []), 'default_status': affected.get('defaultStatus')})
    elif kind == 'nvd':
        if raw['id'] != identifier:
            raise ValueError('NVD identifier mismatch')
        row.update(state=raw.get('vulnStatus'), published=raw.get('published'), modified=raw.get('lastModified'))
        row['disputed'] = any('disputed' in group.get('tags', []) for group in raw.get('cveTags', []))
        row['description'] = next((d['value'] for d in raw.get('descriptions', []) if d['lang'] == 'en'), None)
        row['references'] = raw.get('references', [])
        for metrics in raw.get('metrics', {}).values():
            row['cvss'].extend({**m['cvssData'], 'assessment_source': m.get('source')} for m in metrics if m.get('cvssData'))
        for weakness in raw.get('weaknesses', []):
            row['cwes'].extend(d['value'] for d in weakness.get('description', []) if d['value'].startswith('CWE-'))
        def cpes(node):
            for match in node.get('cpeMatch', []):
                if match.get('vulnerable') and match.get('criteria'):
                    row['cpes'].append(match['criteria'])
                    parts = match['criteria'].split(':')
                    if len(parts) > 5:
                        row['vendors'].append(parts[3])
                        row['products'].append(parts[4])
            for child in node.get('nodes', []) + node.get('children', []):
                cpes(child)
        for configuration in raw.get('configurations', []):
            cpes(configuration)
    elif kind == 'github':
        if raw['ghsa_id'] != identifier:
            raise ValueError('GHSA identifier mismatch')
        row.update(title=raw.get('summary'), description=raw.get('description'), published=raw.get('published_at'), modified=raw.get('updated_at'), severity=raw.get('severity'), state='WITHDRAWN' if raw.get('withdrawn_at') else 'PUBLISHED')
        row['aliases'] = [x['value'] for x in raw.get('identifiers', []) if x.get('value')]
        if raw.get('cve_id'):
            row['aliases'].append(raw['cve_id'])
        row['cwes'] = [x['cwe_id'] for x in raw.get('cwes', [])]
        row['references'] = [{'url': ref} if isinstance(ref, str) else ref for ref in raw.get('references', [])]
        if raw.get('html_url'):
            row['references'].append({'url': raw['html_url'], 'type': 'advisory'})
        for cvss in [raw.get('cvss')] + list((raw.get('cvss_severities') or {}).values()):
            if cvss and cvss.get('vector_string'):
                row['cvss'].append({'vectorString': cvss['vector_string'], 'baseScore': cvss.get('score')})
        for vuln in raw.get('vulnerabilities', []):
            patched = vuln.get('first_patched_version')
            fixed = patched.get('identifier') if isinstance(patched, dict) else patched
            row['packages'].append({**vuln['package'], 'vulnerable_version_range': vuln.get('vulnerable_version_range'), 'fixed': fixed})
            if fixed:
                row['fixed_versions'].append(fixed)
    elif kind == 'osv':
        if raw['id'] != identifier:
            raise ValueError('OSV identifier mismatch')
        row.update(title=raw.get('summary'), description=raw.get('details'), published=raw.get('published'), modified=raw.get('modified'), aliases=raw.get('aliases', []), state='WITHDRAWN' if raw.get('withdrawn') else 'PUBLISHED', references=raw.get('references', []))
        for affected in raw.get('affected', []):
            row['packages'].append({**affected.get('package', {}), 'versions': affected.get('versions', []), 'ranges': affected.get('ranges', [])})
            for span in affected.get('ranges', []):
                row['fixed_versions'].extend(e['fixed'] for e in span.get('events', []) if 'fixed' in e)
        row['cwes'] = raw.get('database_specific', {}).get('cwe_ids', [])
        row['severity'] = raw.get('database_specific', {}).get('severity')
        row['cvss'] = [{'version': m.get('type'), 'vectorString': m['score']} for m in raw.get('severity', [])]
    elif kind == 'rss':
        row.update(title=raw.get('title'), description=raw.get('description') or raw.get('summary'), published=raw.get('pubDate') or raw.get('published'), modified=raw.get('updated'))
        row['references'] = [{'url': raw['link'], 'type': 'advisory'}] if raw.get('link') else []
        # Do not infer aliases from unstructured prose. RSS is advisory metadata only.
    elif kind == 'catalog':
        row.update(title=raw['name'], description=raw.get('description'), state=raw.get('status'))
    elif kind == 'stix':
        row.update(title=raw.get('name'), description=raw.get('description'), published=raw.get('created'), modified=raw.get('modified'))
        row['references'] = [{'url': r['url']} for r in raw.get('external_references', []) if r.get('url')]
    else:
        raise ValueError('Unsupported normalization kind')
    row['aliases'] = sorted(set([identifier] + row['aliases']))
    for key in ('vendors', 'products', 'cwes', 'cpes', 'fixed_versions'):
        row[key] = sorted(set(row[key]))
    for metric in row['cvss']:
        vector = metric.get('vectorString', '')
        if vector.startswith('CVSS:'):
            metric['version'] = vector.split('/')[0].split(':')[1]
        if metric.get('baseScore') is not None and not 0 <= float(metric['baseScore']) <= 10:
            raise ValueError('CVSS score outside valid range')
        if metric.get('baseSeverity'):
            row['severity'] = metric['baseSeverity']
    if row['severity']:
        row['severity'] = row['severity'].upper()
    row['exploit_references'] = [r for r in row['references'] if 'exploit' in [str(t).lower() for t in r.get('tags', [])] or str(r.get('type', '')).upper() == 'EXPLOIT']
    return row
