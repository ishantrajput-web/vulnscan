"""One evidence-based explanation/chart contract shared by every report format."""
from collections import Counter

from report.scoring import ORDER, summarize

PRIORITY = {'critical':'Review first', 'high':'Review first', 'medium':'Plan next', 'low':'Hardening', 'info':'Context'}
DEFINITIONS = [
    {'term':'Finding', 'meaning':'A configuration or exposure observation recorded by a check; it needs context and validation.'},
    {'term':'CVE match', 'meaning':'A known vulnerability correlated with a detected product version; a match is not proof of exploitability.'},
    {'term':'Risk indicator', 'meaning':'A weighted 0-100 sum of recorded signals, capped at 100. Higher means more observed risk, not a percentage chance of compromise.'},
    {'term':'Highest severity', 'meaning':'The strongest individual observation. It can differ from the weighted asset risk indicator.'},
    {'term':'Informational', 'meaning':'Context or a best-practice note. It contributes zero points to the risk indicator.'},
]


def explain(title, is_cve=False):
    text = title.lower()
    if is_cve:
        return ('An affected product version may contain a documented vulnerability. Version detection alone cannot establish whether the installed build is vulnerable.',
                'Confirm product/build and affected versions with the vendor advisory, account for back-ported fixes, apply the supported patch or mitigation, then re-test.')
    rules = [
        (('expires','expired'), 'Transport / TLS', 'A certificate that expires without renewal can trigger browser warnings and interrupt trusted HTTPS connections.', 'Check the live expiry date and renewal automation. After renewal, verify the certificate presented by every public endpoint.'),
        (('certificate','legacy tls','unencrypted','https','hsts','mixed content'), 'Transport / TLS', 'Transport weaknesses can reduce connection trust or allow insecure requests, depending on the browser and deployment.', 'Inspect the public HTTPS response and certificate, apply the stated transport fix, then verify again from an external client.'),
        (('cookie',), 'Browser defenses', 'Missing cookie protections can weaken defenses against credential exposure, script access or cross-site requests, depending on how the cookie is used.', 'Inspect the relevant Set-Cookie header, confirm the cookie purpose, apply suitable flags and test the sign-in flow.'),
        (('csp','content-security','clickjack','x-frame','x-content','permissions-policy','referrer-policy','cors'), 'Browser defenses', 'Browser security controls help limit the impact of unsafe content and cross-origin behavior. Missing controls are not proof that an attack succeeds.', 'Check the actual response header, test a policy compatible with the application, deploy it, then repeat the check.'),
        (('exposed','directory listing','phpinfo','actuator'), 'Files / exposure', 'An unintentionally public endpoint may reveal internal information or sensitive configuration.', 'Confirm the endpoint should not be public without copying secrets; restrict or remove it, rotate affected credentials if needed, then confirm access is denied.'),
        (('version disclosure',), 'Version disclosure', 'A disclosed version can help fingerprint software. Hiding it does not replace installing security updates.', 'Verify the response header, remove unnecessary version detail and confirm the software is maintained and patched.'),
        (('security.txt',), 'Disclosure process', 'A published security contact gives researchers a clear way to report issues; absence is a process note, not a demonstrated exploit.', 'Publish a valid security.txt with an actively monitored contact and verify that it can be retrieved.'),
        (('spf','dmarc'), 'Email DNS', 'Email policy records help receiving mail systems decide how to handle messages claiming to come from the domain.', 'Review the authoritative DNS records with the mail administrator, deploy the appropriate policy and verify the published TXT response.'),
    ]
    for words, _, why, verify in rules:
        if any(word in text for word in words): return why, verify
    return ('The scanner recorded a signal that may increase exposure. Its practical impact depends on configuration, reachability and business context.',
            'Validate the evidence, apply the recommended configuration or vendor fix, then repeat the same check and compare the result.')


def category(title, is_cve=False):
    if is_cve: return 'Known CVEs'
    t = title.lower()
    if any(x in t for x in ('expires','expired','tls','certificate','https','hsts','unencrypted','mixed content')): return 'Transport / TLS'
    if any(x in t for x in ('cookie','csp','content-security','clickjack','x-frame','x-content','permissions-policy','referrer-policy','cors')): return 'Browser defenses'
    if 'version disclosure' in t: return 'Version disclosure'
    if any(x in t for x in ('exposed','directory listing','phpinfo','actuator')): return 'Files / exposure'
    if 'security.txt' in t: return 'Disclosure process'
    if 'spf' in t or 'dmarc' in t: return 'Email DNS'
    return 'Network / other'


def assessment(result):
    summary = summarize(result)
    observations, assets = [], []
    def add(asset, item, cve=False):
        title = item.cve_id if cve else item.title
        why, verify = explain(title, cve)
        observations.append({'id':'OBS-%03d' % (len(observations)+1), 'asset':asset, 'kind':'cve_match' if cve else 'finding',
            'severity':item.severity, 'title':title, 'evidence':item.description if cve else item.detail,
            'recommended_action':verify if cve else (item.remediation or verify), 'why_it_matters':why,
            'how_to_verify':verify, 'category':category(title,cve), 'priority':PRIORITY.get(item.severity,'Context'),
            'source':item.source if cve else 'scanner observation', 'reference':item.url if cve else '',
            'validation':'Version match; applicability unverified' if cve else 'Observed signal; impact requires context'})
    for host in result.hosts:
        assets.append({'asset':host.ip, 'kind':'network host', 'risk_score':host.risk_score, 'risk_level':host.risk_level, 'status':'Network result recorded'})
        for port in host.ports:
            for item in port.findings: add(host.ip + ':' + str(port.port),item)
            for item in port.vulns: add(host.ip + ':' + str(port.port),item,True)
    for web in result.webs:
        unavailable = bool(web.error or web.status is None)
        assets.append({'asset':web.url, 'kind':'website', 'risk_score':None if unavailable else web.risk_score,
                       'risk_level':None if unavailable else web.risk_level, 'status':web.error or ('No HTTP response recorded' if unavailable else 'HTTP response recorded')})
        for item in web.findings: add(web.url,item)
        for item in web.vulns: add(web.url,item,True)
    observations.sort(key=lambda x: ORDER.index(x['severity']) if x['severity'] in ORDER else 4)
    incomplete = bool(result.meta.get('error') or result.meta.get('interrupted') or not summary['assets'] or any(w.error or w.status is None for w in result.webs))
    highest = next((s for s in ORDER if any(x['severity']==s for x in observations)), 'info')
    actions = []
    for item in observations:
        if item['severity']=='info': continue
        existing = next((a for a in actions if (a['title'],a['action'])==(item['title'],item['recommended_action'])),None)
        if existing:
            if item['asset'] not in existing['assets']: existing['assets'].append(item['asset'])
        else: actions.append({'title':item['title'], 'severity':item['severity'], 'priority':item['priority'],
                             'action':item['recommended_action'], 'verify':item['how_to_verify'], 'assets':[item['asset']]})
    counts = Counter(x['category'] for x in observations)
    severity = {'id':'severity', 'title':'Which observations need attention first?',
        'description':'Counts of recorded signals by severity. Configuration findings and CVE version matches are separate series; informational notes are included.',
        'unit':'observations', 'series':['Configuration / exposure','CVE version matches'],
        'rows':[{'label':s.capitalize(), 'values':[summary['finding_severity'][s],summary['cve_severity'][s]]} for s in ORDER]}
    categories = {'id':'categories', 'title':'Where are the observations concentrated?',
        'description':'All recorded findings and CVE matches grouped by topic. These are observation counts, not a complete inventory of checks or attacks.',
        'unit':'observations', 'series':['Recorded observations'],
        'rows':[{'label':k,'values':[v]} for k,v in sorted(counts.items(),key=lambda kv:(-kv[1],kv[0]))]}
    charts = [severity,categories]
    if result.webs:
        responded = sum(w.error is None and w.status is not None for w in result.webs)
        charts.append({'id':'responses', 'title':'Did the websites return usable responses?',
            'description':'Response availability only. A response is not a passed security test; unavailable targets must not be treated as safe.',
            'unit':'websites','series':['Websites'], 'rows':[{'label':'Response recorded','values':[responded]}, {'label':'No usable response','values':[len(result.webs)-responded]}]})
    actionable = sum(x['severity']!='info' for x in observations)
    if incomplete:
        conclusion = 'Assessment incomplete. Resolve errors or missing responses before drawing a security conclusion. An empty findings list does not establish safety.'
    elif actionable:
        conclusion = '%d non-informational finding(s) and CVE match(es) were recorded. Highest individual severity: %s. Validate and address the prioritized actions below.' % (actionable,highest)
    else:
        conclusion = 'No non-informational issues were recorded by the checks performed. Review the informational notes and scope limitations; this is not a security guarantee.'
    return {'version':2, 'status':'incomplete' if incomplete else 'evidence_collected', 'conclusion':conclusion,
            'highest_observation_severity':highest, 'aggregate_risk_indicator':None if incomplete else max([0]+[a['risk_score'] or 0 for a in assets]),
            'non_informational_observations':actionable, 'informational_observations':sum(x['severity']=='info' for x in observations),
            'observations':observations, 'actions':actions, 'assets':assets, 'charts':charts, 'glossary':DEFINITIONS,
            'reading_order':['Read the conclusion and response availability.', 'Use severity and topic charts to choose what to review.',
                             'Validate each observation, apply the recommended change, then repeat the same scan.'],
            'limitations':['Baseline, point-in-time checks only; not an authenticated penetration test or security certification.',
                           'CVE matches depend on observed versions and database coverage; back-ported fixes and hidden versions can affect accuracy.',
                           ('Hosted mode omits network scans, email DNS checks and live NVD queries; it uses the built-in CVE database.' if result.meta.get('mode')=='serverless' else 'Local checks and enrichment depend on the selected options, reachable scope and installed tools.'),
                           'Charts summarize recorded data, not all possible vulnerabilities. No historical trend is inferred from one scan.']}
