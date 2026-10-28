"""Synthetic report fixture: never scans a target and never represents a real assessment."""
from models import Finding, ScanResult, Vulnerability, WebResult
from engine import finalize


def sample_result():
    web = WebResult(url='https://demo.example', host_ip='203.0.113.10', final_url='https://demo.example/',
                    status=200, title='Illustrative storefront', server='nginx/1.18.0',
                    tls={'checked':True,'valid':True,'version':'TLSv1.3','cipher':'TLS_AES_256_GCM_SHA384',
                         'issuer':'Example certificate issuer','days_left':12,'not_after':'2026-11-09'},
                    techs=[{'product':'nginx','version':'1.18.0','source':'Server header'}],
                    findings=[Finding('high','TLS certificate expires in 12 days','The presented certificate is approaching its expiry date. This is illustrative fixture data.', 'Renew the certificate and verify automatic renewal and expiry monitoring.'),
                              Finding('medium','HSTS header missing','No Strict-Transport-Security response header was observed on the HTTPS endpoint.', 'After validating HTTPS coverage, send Strict-Transport-Security: max-age=31536000; includeSubDomains.'),
                              Finding('low','Content-Security-Policy missing','No CSP response header was observed.','Develop a policy for required origins, test in report-only mode, then enforce it.'),
                              Finding('low','Version disclosure in server header','Server: nginx/1.18.0','Disable server version disclosure and keep the installed server patched.'),
                              Finding('info','No security.txt published','No researcher contact file was observed.','Publish /.well-known/security.txt with a monitored contact address.')],
                    vulns=[Vulnerability('CVE-SAMPLE-0001','Illustrative version correlation used to demonstrate report layout. This is not a real CVE or a confirmed vulnerability.',7.5,'high','synthetic fixture','https://example.com/advisory')])
    result = ScanResult('20261028-150000-abcd','2.0.0',web.url,'2026-10-28 15:00:00 UTC',
                        finished='2026-10-28 15:00:08 UTC',duration_s=8.4,webs=[web],
                        meta={'mode':'serverless','sample':True,'dns_checks':False,'cve_source':'synthetic fixture'})
    finalize(result)
    return result
