const {compareWebsites} = require('../webui/compare.js');
const cases = JSON.parse(require('node:fs').readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(cases.map(({oldScan,newScan}) => compareWebsites(oldScan,newScan))));
