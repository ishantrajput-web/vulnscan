"""Build an eight-page, print-friendly project explanation from verified code and test evidence."""
import argparse
import json
from pathlib import Path
import sys
from xml.sax.saxutils import escape

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import Flowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from models import ScanResult, WebResult, HostResult, PortResult, Finding, Vulnerability
from report.insights import assessment
from report.pdf_report import EvidenceChart
from report.writer import write_reports

INK = colors.HexColor('#183729')
MUTED = colors.HexColor('#566557')
PALE = colors.HexColor('#f1f5ed')
LINE = colors.HexColor('#d9e1d4')
ST = {
 'label':ParagraphStyle('project-label',fontName='Courier',fontSize=8,leading=12,textColor=MUTED,spaceAfter=8),
 'title':ParagraphStyle('project-title',fontName='Helvetica-Bold',fontSize=35,leading=40,textColor=INK,spaceAfter=16),
 'h1':ParagraphStyle('project-h1',fontName='Helvetica-Bold',fontSize=24,leading=29,textColor=INK,spaceAfter=17,keepWithNext=True),
 'h2':ParagraphStyle('project-h2',fontName='Helvetica-Bold',fontSize=12,leading=16,textColor=INK,spaceBefore=12,spaceAfter=6,keepWithNext=True),
 'body':ParagraphStyle('project-body',fontName='Helvetica',fontSize=10,leading=14.4,textColor=colors.HexColor('#223129'),spaceAfter=9,splitLongWords=True),
 'small':ParagraphStyle('project-small',fontName='Helvetica',fontSize=8.5,leading=12,textColor=MUTED,spaceAfter=7,splitLongWords=True),
 'cell':ParagraphStyle('project-cell',fontName='Helvetica',fontSize=8.5,leading=12,textColor=INK,splitLongWords=True),
 'head':ParagraphStyle('project-head',fontName='Helvetica-Bold',fontSize=8,leading=12,textColor=colors.white),
 'callout':ParagraphStyle('project-callout',fontName='Helvetica',fontSize=10,leading=15,textColor=INK,backColor=PALE,borderPadding=12,spaceBefore=13,spaceAfter=21),
}


def text(value):
    return escape(str(value)).replace('\n','<br/>')


def p(value, style='body'):
    return Paragraph(text(value),ST[style])


def table(rows, widths):
    data=[[p(value,'head' if i==0 else 'cell') for value in row] for i,row in enumerate(rows)]
    t=Table(data,colWidths=widths,repeatRows=1,hAlign='LEFT')
    t.setStyle(TableStyle([('BACKGROUND',(0,0),(-1,0),INK),('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,PALE]),
      ('VALIGN',(0,0),(-1,-1),'TOP'),('LEFTPADDING',(0,0),(-1,-1),9),('RIGHTPADDING',(0,0),(-1,-1),9),
      ('TOPPADDING',(0,0),(-1,-1),8),('BOTTOMPADDING',(0,0),(-1,-1),8),('LINEBELOW',(0,0),(-1,-1),.4,LINE)]))
    return t


class Architecture(Flowable):
    def __init__(self,width):
        super().__init__(); self.width=width; self.height=185
    def draw(self):
        c=self.canv; gap=18; box=(self.width-2*gap)/3; bh=58
        labels=[('Browser interface','HTML / CSS / JavaScript'),('Public WSGI API','Validation + request limits'),('Cloud worker','One bounded scan request'),
                ('Browser workspace','Downloads + IndexedDB'),('Report writers','PDF / HTML / JSON / DOCX'),('Shared result model','Evidence + risk scoring')]
        positions=[(i*(box+gap),110) for i in range(3)]+[(i*(box+gap),20) for i in range(3)]
        for (title,sub),(x,y) in zip(labels,positions):
            c.setFillColor(PALE);c.setStrokeColor(LINE);c.roundRect(x,y,box,bh,6,fill=1,stroke=1)
            c.setFillColor(INK);c.setFont('Helvetica-Bold',9);c.drawString(x+9,y+35,title)
            para=Paragraph(text(sub),ST['small']);para.wrap(box-18,40);para.drawOn(c,x+9,y+10)
        def arrow(x1,y1,x2,y2):
            c.setStrokeColor(INK);c.setFillColor(INK);c.setLineWidth(1);c.line(x1,y1,x2,y2)
            path=c.beginPath()
            if x2>x1: path.moveTo(x2,y2);path.lineTo(x2-5,y2+3);path.lineTo(x2-5,y2-3)
            elif x2<x1:path.moveTo(x2,y2);path.lineTo(x2+5,y2+3);path.lineTo(x2+5,y2-3)
            else:path.moveTo(x2,y2);path.lineTo(x2-3,y2+5);path.lineTo(x2+3,y2+5)
            path.close();c.drawPath(path,fill=1,stroke=0)
        arrow(box,139,box+gap,139);arrow(2*box+gap,139,2*(box+gap),139)
        arrow(2*(box+gap)+box/2,110,2*(box+gap)+box/2,78)
        arrow(2*(box+gap),49,2*box+gap,49);arrow(box+gap,49,box,49)


def read_scan(path):
    d=json.loads(Path(path).read_text(encoding='utf-8'))
    def finding(v):return Finding(**v)
    def cve(v):return Vulnerability(**v)
    webs=[]
    for value in d.get('webs',[]):
        value=dict(value);value['findings']=[finding(v) for v in value.get('findings',[])];value['vulns']=[cve(v) for v in value.get('vulns',[])];webs.append(WebResult(**value))
    hosts=[]
    for value in d.get('hosts',[]):
        value=dict(value);ports=[]
        for port in value.pop('ports',[]):
            port=dict(port);port['findings']=[finding(v) for v in port.get('findings',[])];port['vulns']=[cve(v) for v in port.get('vulns',[])];ports.append(PortResult(**port))
        hosts.append(HostResult(ports=ports,**value))
    names=('scan_id','tool_version','targets','started','finished','duration_s','meta')
    return ScanResult(hosts=hosts,webs=webs,**{k:d[k] for k in names if k in d})


def footer(c,doc):
    c.saveState();w,h=A4
    c.setStrokeColor(LINE);c.line(18*mm,h-16*mm,w-18*mm,h-16*mm)
    c.setFillColor(INK);c.setFont('Helvetica-Bold',9);c.drawString(18*mm,h-12*mm,'VULNSCAN / PROJECT REPORT')
    c.setFont('Courier',7);c.setFillColor(MUTED);c.drawRightString(w-18*mm,h-12*mm,'DESIGN, IMPLEMENTATION & EVALUATION')
    c.line(18*mm,15*mm,w-18*mm,15*mm);c.setFont('Helvetica',8)
    c.drawString(18*mm,10*mm,'Educational project documentation | 01 November 2026')
    c.drawRightString(w-18*mm,10*mm,'%d / 8'%doc.page);c.restoreState()


def build(scan_json, output, test_log):
    result=read_scan(scan_json);a=assessment(result)
    tests=Path(test_log).read_text(encoding='utf-8-sig',errors='replace')
    import re
    match=re.search(r'Ran (\d+) tests',tests);total=int(match.group(1)) if match else 0
    skipped_match=re.search(r'OK \(skipped=(\d+)\)',tests);skipped=int(skipped_match.group(1)) if skipped_match else 0
    if not total or 'FAILED' in tests or not re.search(r'^OK',tests,re.M):raise ValueError('A successful, recorded local test run is required.')
    doc=SimpleDocTemplate(str(output),pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=24*mm,bottomMargin=23*mm,
                         title='VulnScan - Project Report',author='VulnScan Project',subject='Introduction, design, implementation, testing and evaluation')
    W=doc.width;S=[]
    def page(n,title):
        if S:S.append(PageBreak())
        S.extend([p('%02d / PROJECT EXPLANATION'%n,'label'),p(title,'h1')])
    def h(value):S.append(p(value,'h2'))
    def b(value):S.append(p(value))
    def note(value):S.append(p(value,'callout'))

    # PAGE 1 - A useful cover, not an empty title page.
    S.extend([Spacer(1,16),p('COMPUTER SCIENCE / SOFTWARE PROJECT','label'),p('VulnScan','title'),
              p('Network & Website\nVulnerability Scanner','h1'),p('A practical tool for collecting security observations, explaining their meaning and producing an actionable report.','callout')])
    h('Project abstract')
    b('VulnScan is a Python-based security assessment project with a browser dashboard and a command-line interface. It checks selected website and network signals, converts the collected evidence into structured results, and produces PDF, HTML, JSON and Word reports. The public website provides bounded scans of one public HTTP(S) target; the local application supports broader network assessment.')
    b('The project focuses on understandable reporting as well as detection. Each report separates observed facts from version-based CVE matches, explains why a finding matters, recommends a next step and states the limits of the assessment. Only systems owned by the operator or covered by written permission should be tested.')
    S.append(table([['PROJECT AT A GLANCE','IMPLEMENTED APPROACH'],['Core language','Python 3.9+; hosted runtime pinned to Python 3.12'],['User interfaces','Vanilla HTML, CSS and JavaScript dashboard; Python CLI'],['Hosting and storage','Vercel WSGI function; browser IndexedDB for public history'],['Outputs','PDF, HTML, JSON and DOCX assessment reports'],['Project type','Baseline assessment and reporting; not an exploitation framework']],[W*.30,W*.70]))
    h('How this document is organized')
    S.append(p('2 Problem and objectives  |  3 Technology and architecture  |  4 Working process\n5 Features and modules  |  6 Input and output  |  7 Testing and results  |  8 Conclusion and future scope','small'))

    page(2,'The problem, and the objective.')
    h('1. Introduction and problem statement')
    b('A website can load correctly while still exposing weak browser policies, a certificate approaching expiry, unnecessary version information or a sensitive public file. Checking these signals manually across different tools can be repetitive, and raw technical output is difficult for a beginner to interpret.')
    b('VulnScan brings selected checks into one workflow: choose an authorized target, collect evidence, organize the observations, and explain the next action. It helps a user begin a security review; it does not replace a complete professional assessment.')
    h('2. Project objectives')
    for item in ['Make a simple interface for entering an authorized website or local network target.',
                 'Detect selected transport, browser-security, file-exposure and service/version signals.',
                 'Correlate detected product versions with known CVE records, while flagging matches for validation.',
                 'Produce consistent, understandable reports with labelled charts and practical remediation guidance.',
                 'Handle invalid input, unavailable services and missing optional tools without claiming that a failed scan is safe.']:
        b('- '+item)
    h('3. Implemented scope: two different operating modes')
    S.append(table([['CAPABILITY','PUBLIC WEBSITE MODE','LOCAL APPLICATION'],['Target','One public HTTP(S) website; ports 80/443','IP, range, CIDR, hostname or website'],['Network checks','Not performed','Discovery, TCP ports, banners; optional Nmap'],['CVE data','Built-in offline database','Built-in database; optional NVD enrichment'],['Reports/history','Returned to browser; IndexedDB history','Reports saved in the output directory']],[W*.22,W*.39,W*.39]))
    note('Scope boundary: no brute force, login bypass, exploit execution, authenticated application testing or business-logic assessment is implemented. A clean result is not a security guarantee.')

    page(3,'The technology and architecture.')
    S.append(table([['TECHNOLOGY','ROLE IN THIS PROJECT'],['Python standard library','HTTP/TLS requests, sockets, asyncio, subprocesses, JSON, temporary files, ZIP/XML and data classes.'],['HTML, CSS and JavaScript','Responsive form, scan activity view, severity/search filters and report downloads.'],['ReportLab','Optional PDF generation with text, tables and vector charts.'],['OOXML + zipfile','DOCX creation without a mandatory Word library.'],['IndexedDB','Stores the last 20 public scan records in the current browser and origin.'],['Vercel + WSGI','Hosts the public HTTP application; api/index.py exposes the app callable.'],['Git + GitHub Actions','Version control and a 3 operating-system x 3 Python-version test matrix.']],[W*.28,W*.72]))
    h('Public request architecture')
    S.append(Architecture(W))
    b('The browser sends a JSON request to the WSGI API. The API validates it and starts a child process for a bounded scan. The worker collects website evidence, performs offline CVE matching and finalizes risk scores. Report writers serialize the same result, and the response returns report bytes to the browser.')
    S.append(p('Local mode uses the same models and report writers, but main.py and engine.py run the configurable network/website pipeline. Public mode does not run the full local network workflow. No persistent server-side database is configured.','small'))

    page(4,'How the project works, step by step.')
    steps=[('1. Receive the input','The operator enters a target. Public mode accepts one HTTP(S) URL; local mode can parse IP addresses, CIDR ranges, hostnames and mixed target lists.'),
           ('2. Confirm permission','The user confirms ownership or written permission. Public targets also require the phrase I HAVE PERMISSION. The server validates these values before scanning.'),
           ('3. Validate and bound the request','Hosted mode restricts ports to 80/443, rejects non-public connection addresses, and validates DNS answers at connection time. Per-instance request and concurrency limits bound work.'),
           ('4. Collect the evidence','Website checks inspect HTTP responses, headers, cookies, certificate details and a fixed set of exposure paths. Local network mode can first discover hosts, scan TCP ports and read banners.'),
           ('5. Correlate and score','Detected products and versions are matched against CVE data. Findings and CVE records are stored separately, then weighted to produce a capped 0-100 risk indicator.'),
           ('6. Explain and export','A shared report model builds conclusions, topic/severity chart data, explanations, priorities and verification steps. PDF, HTML, JSON and DOCX writers preserve the underlying evidence.'),
           ('7. Return, store and review','Hosted results and report files are returned in one response; browser history is saved in IndexedDB. In local mode, reports are written to disk and the dashboard polls job status.')]
    for title,description in steps:h(title);b(description)
    note('Public execution is synchronous within one HTTP request. A scan child process has a 90-second timeout; the Vercel function is configured for 120 seconds. The animation indicates activity, not fabricated percentages or live per-check progress.')

    page(5,'Features, modules and responsibilities.')
    S.append(table([['MODULE / FILE','WHAT IT DOES'],['main.py','Parses CLI options, confirms authorization, runs doctor/compare commands and starts local UI mode.'],['engine.py + models.py','Coordinates the local pipeline; defines shared dataclasses and finalizes findings/risk scores.'],['scanner/webcheck.py','Collects HTTP/TLS evidence, checks browser headers and known exposure paths, and enforces public-only connections in hosted mode.'],['scanner/cve.py','Performs version-based CVE lookup using built-in data, cache and optional NVD queries.'],['scanner/discovery.py, portscan.py, banner.py','Local host discovery, concurrent TCP connect scanning and service/banner collection.'],['report/insights.py + scoring.py','Produces plain-language conclusions, action priorities, labelled chart data and weighted risk summaries.'],['report/*_report.py + json_export.py','Generates readable PDF/HTML/DOCX reports and a structured JSON export.'],['webui/cloud.py + cloud_worker.py','Validates public API requests, applies per-instance limits and executes a bounded website scan.'],['webui/app.js + server.py','Browser interaction/IndexedDB; local-only token-protected dashboard and job API.'],['tests/ + .github/workflows/ci.yml','Automated security, export, API and end-to-end checks across configured platforms.']],[W*.42,W*.58]))
    h('Reliability and security decisions')
    b('The local server binds to loopback and requires a launch token. Public mode has no account or access-key requirement, but retains explicit permission confirmation. Private/metadata addresses are blocked, request bodies are bounded, and temporary report files are removed after the response is prepared.')
    S.append(p('Important limit: public rate limits are held in memory per function instance. They reset on cold starts and do not coordinate globally. Browser history can be cleared or evicted and is not a cloud backup.','small'))

    page(6,'From input to useful output.')
    h('Input contract')
    S.append(table([['INPUT','MEANING / VALIDATION'],['target','Public mode: one HTTP(S) URL without embedded credentials, on port 80 or 443.'],['authorized','Must be true: the operator confirms ownership or written permission.'],['phrase','Public authorization phrase: I HAVE PERMISSION.'],['Local options','Port selection, discovery, offline mode, Nmap and output format; availability depends on the local environment.']],[W*.24,W*.76]))
    h('Output formats and their purpose')
    S.append(table([['FORMAT','HOW A USER USES IT'],['PDF','Print or share an executive summary, charts, action plan and full technical evidence.'],['HTML','Open a self-contained readable report in a browser; charts include numerical data tables.'],['JSON','Reuse raw evidence, summary, explanations and labelled chart datasets in another tool.'],['DOCX','Edit an explanatory report in Word/WPS/LibreOffice; native table bars visualize counts.']],[W*.19,W*.81]))
    h('Structured result: a simple view')
    note('ScanResult -> targets + timestamps + HostResult[] + WebResult[] + metadata\nWebResult -> URL + response/TLS details + findings[] + CVE matches[]\nAssessment -> conclusion + actions[] + observations[] + charts[] + glossary')
    S.append(p('Scoring detail: per website/service, add CVE points (capped at 60) and finding points, then cap the score at 100. Critical/high/medium/low/info weights are 20/10/4/1/0 for CVEs and 20/8/3/1/0 for findings. Host scores combine their service/web points. Critical or high observations force at least that risk level; other numeric thresholds are 70, 40, 15 and 1.','small'))
    h('How to interpret the charts')
    b('Severity compares configuration/exposure findings with CVE version matches. Topics show where recorded observations are concentrated. Response availability shows whether websites returned usable evidence; it is not a count of passed checks. Each chart has a unit, source and explanation.')
    b('For example, a missing browser header is recorded with its evidence, why the header matters, a recommended configuration change and a way to verify the change. A CVE match separately states that applicability is unverified.')

    page(7,'Testing, demonstration and results.')
    note('Recorded local verification: %d tests ran; %d passed and %d was skipped. The skipped case requires an OpenSSL CLI that was unavailable in this environment. A skip is not counted as a pass.'%(total,total-skipped,skipped))
    S.append(table([['TEST AREA','WHAT WAS VERIFIED'],['Authorization and API','Missing permission, invalid input, non-JSON/cross-site requests, rate limits and worker timeout behavior.'],['Connection safety','Private/loopback/metadata and rebinding answers are blocked before a connection is made.'],['Report correctness','Chart totals agree with evidence; all formats retain explanations and full descriptions; failed responses are marked incomplete.'],['Local integration','Fake services on localhost exercise discovery/HTTP behavior, reports, comparison and policy exit codes.'],['Document robustness','Hostile text is escaped; long PDF evidence and XML parts remain valid.']],[W*.28,W*.72]))
    h('A real, dated demonstration')
    b('A self-scan of '+result.targets+' started at '+result.started+'. The site returned a usable HTTP response with no website scan error. This demonstrates the pipeline on one authorized target.')
    chart=dict(a['charts'][0]);chart['series']=['Recorded observations'];chart['rows']=[{'label':row['label'],'values':[sum(row['values'])]} for row in chart['rows']]
    S.append(EvidenceChart(chart,W));S.append(p('Recorded observations by severity, including informational notes. Configuration findings and CVE matches are combined in this demonstration chart.','small'))
    b('This run recorded %d non-informational observations, %d informational notes and %d CVE version matches. The informational notes were: %s. These are dated observations; deployment settings can change.'%(a['non_informational_observations'],a['informational_observations'],sum(o['kind']=='cve_match' for o in a['observations']),'; '.join(o['title'] for o in a['observations'] if o['severity']=='info') or 'none'))

    page(8,'Conclusion, limits and next steps.')
    h('Conclusion')
    b('VulnScan demonstrates an end-to-end assessment workflow: validated input, evidence collection, version correlation, structured data, readable analysis and multiple report outputs. Its main value is connecting technical signals to an understandable explanation and a practical next action. The public deployment and local application serve different, clearly bounded use cases.')
    h('What the project does not prove')
    b('A successful scan proves that selected checks completed; it does not prove that a website is safe or compliant. CVE correlation can be wrong when versions are hidden or fixes are back-ported. A failed check is unknown, not a pass. The built-in database has finite coverage, and hosted scans omit local network and email-DNS features.')
    h('Future improvements - proposed, not implemented')
    for item in ['Platform-wide rate limiting and bot controls, with durable job coordination for larger workloads.',
                 'A broader, maintained vulnerability-data pipeline and stronger applicability/confidence tracking.',
                 'Persistent accounts/history with explicit privacy, retention and access policies.',
                 'User-approved authenticated assessment workflows and clearer measurements of per-check coverage.']:b('- '+item)
    h('Short answers for a project demonstration')
    S.append(table([['QUESTION','CLEAR ANSWER'],['Why Python?','Its standard library supports networking, concurrency and structured data while keeping core dependencies small.'],['Why separate hosted and local modes?','Cloud functions are bounded requests; local network access and long-lived jobs need a different execution model.'],['Is a CVE match a confirmed exploit?','No. It is a version-based lead that must be checked against the installed build and vendor guidance.'],['How are reports kept consistent?','All exporters use the same result dataclasses and shared assessment/chart contract.']],[W*.38,W*.62]))
    h('Implementation references')
    S.append(p('Repository: https://github.com/ishantrajput-web/vulnscan\nCore sources: main.py; engine.py; models.py; scanner/webcheck.py; scanner/cve.py; webui/cloud.py; webui/cloud_worker.py; report/insights.py; report/scoring.py; report/writer.py.\nVerification sources: tests/; .github/workflows/ci.yml; recorded local test log and the dated self-scan used on page 7.','small'))
    S.append(p('Reproduce: python -m unittest discover -s tests -v. CI is configured for Windows, Ubuntu and macOS with Python 3.9, 3.12 and 3.14. These tests verify selected behaviors, not complete detection accuracy.','small'))
    Path(output).parent.mkdir(parents=True,exist_ok=True)
    doc.build(S,onFirstPage=footer,onLaterPages=footer)
    if doc.page != 8:
        raise ValueError('Expected exactly eight project-report pages; review content and layout before delivery.')
    return str(output)


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--scan-json',required=True);parser.add_argument('--test-log',required=True)
    parser.add_argument('--output',default='output/pdf/VulnScan_Project_Report.pdf');args=parser.parse_args()
    print(build(args.scan_json,args.output,args.test_log))
