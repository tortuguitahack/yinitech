const http = require('http');
const server = http.createServer((req, res) => {
  res.writeHead(200, {'Content-Type': 'application/json'});
  res.end(JSON.stringify({test: 'direct server works'}));
});
server.listen(5101, () => console.log('Test server on 5101'));