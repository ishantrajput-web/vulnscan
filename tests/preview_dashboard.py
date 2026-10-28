"""Local UI-only preview using explicitly synthetic results; does not scan websites."""
import base64
import tempfile
import time
from wsgiref.simple_server import make_server

from report.scoring import summarize
from report.writer import write_reports
from tests.report_fixture import sample_result
from webui import cloud
from webui.server import PHRASE


def preview_scan(body):
    if body.get('authorized') is not True or str(body.get('phrase','')).strip().upper() != PHRASE:
        return 400, {'error':'Confirm ownership and type I HAVE PERMISSION.', 'code':'permission'}
    if body.get('target') != 'https://demo.example':
        return 400, {'error':'This local design preview accepts only https://demo.example. It does not scan real targets.'}
    time.sleep(2)
    result = sample_result()
    with tempfile.TemporaryDirectory() as folder:
        files, notes = write_reports(result, folder, ['json','html','docx','pdf'])
        reports = {}
        for fmt, path in files.items():
            with open(path,'rb') as stream: reports[fmt] = base64.b64encode(stream.read()).decode('ascii')
    data = result.to_dict(); data['summary'] = summarize(result)
    return 200, {'id':result.scan_id,'result':data,'reports':reports,'files':list(reports),
                 'notes':['Illustrative sample fixture. No real target was scanned.'] + notes}


if __name__ == '__main__':
    cloud.execute_scan = preview_scan
    make_server('127.0.0.1', 8877, cloud.app).serve_forever()
