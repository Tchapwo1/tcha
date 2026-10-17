import * as readline from 'readline';

const rl = readline.createInterface({ input: process.stdin });

rl.on('line', (line) => {
  try {
    const msg = JSON.parse(line);
    // Echo back standard success response
    const response = {
      jsonrpc: '2.0',
      id: msg.id,
      result: {
        status: 'echoed',
        receivedMethod: msg.method,
      },
    };
    process.stdout.write(JSON.stringify(response) + '\n');
  } catch (err) {
    // ignore malformed lines
  }
});
