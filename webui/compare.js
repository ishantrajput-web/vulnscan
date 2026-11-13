/* Browser-local comparison. Scan history and report content never need uploading. */
(function (root) {
'use strict';
function compareWebsites(oldScan, newScan) {
  const key = (url) => { const u = new URL(url); u.hash = ''; return u.href; };
  const index = (scan) => new Map((scan.webs || []).map(w => [key(w.url), w]));
  const before = index(oldScan), after = index(newScan), output = {};
  const observations = (w) => {
    const entries = new Map();
    (w.findings || []).forEach(f => entries.set(f.check_id ? f.check_id + '::' + (f.rule_id || f.title) : f.title, {title:f.title,severity:f.severity,check_id:f.check_id || '',kind:'finding'}));
    (w.vulns || []).forEach(v => entries.set('cve.' + v.cve_id, {title:v.cve_id,severity:v.severity,check_id:'',kind:'potential_cve'}));
    return entries;
  };
  [...new Set([...before.keys(), ...after.keys()])].sort().forEach(url => {
    const a = before.get(url) || {}, b = after.get(url) || {};
    const checks = new Map((b.checks || []).map(c => [c.id,c]));
    const previous = observations(a), current = observations(b);
    const rows = {new:[],resolved:[],still_present:[],not_verified:[]};
    const uncertain = !!((newScan.meta || {}).interrupted || (newScan.meta || {}).error || b.error || b.status == null);
    [...new Set([...previous.keys(), ...current.keys()])].sort().forEach(identity => {
      const item = current.get(identity) || previous.get(identity);
      const state = current.has(identity) ? (previous.has(identity) ? 'still_present' : 'new') :
        (!uncertain && (checks.get(item.check_id) || {}).status === 'no_issue' ? 'resolved' : 'not_verified');
      rows[state].push(item);
    });
    rows.response = uncertain ? 'not_verified' : 'response_recorded'; output[url] = rows;
  });
  return output;
}
if (typeof module !== 'undefined') module.exports = {compareWebsites};
else root.VulnScanCompare = compareWebsites;
})(typeof window === 'undefined' ? globalThis : window);
