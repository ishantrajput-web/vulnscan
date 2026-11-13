const {compareWebsites} = require('../webui/compare.js');
let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', part => { input += part; });
process.stdin.on('end', () => {
  const {oldScan,newScan} = JSON.parse(input);
  process.stdout.write(JSON.stringify(compareWebsites(oldScan,newScan)));
});
