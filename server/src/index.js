'use strict';

const { createApp } = require('./app');

const port = Number(process.env.PORT || 7100);
const host = process.env.HOST || '127.0.0.1';

const server = createApp();
server.listen(port, host, () => {
  console.log('');
  console.log('  RevScan license server');
  console.log(`  admin UI : http://${host}:${port}`);
  console.log(`  admin key: ${server.revscan.adminKey}`);
  console.log(`  data     : ${server.revscan.dataFile}`);
  console.log('');
});
