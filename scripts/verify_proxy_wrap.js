import { spawn } from 'child_process';
import * as readline from 'readline';

async function testProxyWrap() {
  console.log('[Test] Starting Tcha Wrap integration verification...');

  // Spawn node with our clean, platform-independent mock server
  const proxy = spawn('node', ['dist/cli/index.js', 'wrap', 'node', 'scripts/mock_mcp_server.js'], {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  const responses = [];
  const rl = readline.createInterface({ input: proxy.stdout });
  rl.on('line', (line) => {
    try {
      responses.push(JSON.parse(line));
    } catch (e) {}
  });

  const send = (obj) => {
    proxy.stdin.write(JSON.stringify(obj) + '\n');
  };

  // Wait 400ms for startup
  await new Promise((r) => setTimeout(r, 400));

  // 1. SSRF Probe
  send({
    jsonrpc: '2.0',
    id: 1,
    method: 'tools/call',
    params: { name: 'fetch_webpage', arguments: { url: 'http://169.254.169.254/metadata' } },
  });

  // 2. Traversal Probe
  send({
    jsonrpc: '2.0',
    id: 2,
    method: 'tools/call',
    params: { name: 'read_config', arguments: { filepath: '../../../../etc/shadow' } },
  });

  // 3. Destructive Tier 3 Tool Probe (No approval token)
  send({
    jsonrpc: '2.0',
    id: 3,
    method: 'tools/call',
    params: { name: 'delete_database', arguments: { cluster: 'prod-main' } },
  });

  // 4. Safe Read-Only Tool
  send({
    jsonrpc: '2.0',
    id: 4,
    method: 'tools/call',
    params: { name: 'get_system_status', arguments: { detailed: true } },
  });

  // Wait 1000ms for proxy processing
  await new Promise((r) => setTimeout(r, 1000));
  proxy.kill();

  console.log(`[Test] Received ${responses.length} responses.`);

  const ssrfResp = responses.find((r) => r.id === 1);
  const travResp = responses.find((r) => r.id === 2);
  const hitlResp = responses.find((r) => r.id === 3);
  const safeResp = responses.find((r) => r.id === 4);

  if (!ssrfResp || ssrfResp.error?.code !== -32001) {
    console.error('FAILED: SSRF was not intercepted with code -32001', ssrfResp);
    process.exit(1);
  }
  console.log('✓ SSRF intercepted with code -32001');

  if (!travResp || travResp.error?.code !== -32001) {
    console.error('FAILED: Path traversal was not intercepted with code -32001', travResp);
    process.exit(1);
  }
  console.log('✓ Path traversal intercepted with code -32001');

  if (!hitlResp || hitlResp.error?.code !== -32001 || !hitlResp.error?.data?.challenge) {
    console.error('FAILED: Destructive tool was not suspended with HITL challenge', hitlResp);
    process.exit(1);
  }
  console.log('✓ Destructive tool suspended with code -32001 and HMAC challenge emitted');

  if (!safeResp || !safeResp.result) {
    console.error('FAILED: Safe tool was not forwarded through to downstream', safeResp);
    process.exit(1);
  }
  console.log('✓ Safe tool forwarded cleanly through proxy');

  console.log('\n[PASS] In-Line MCP Reverse Proxy passed all 4 integration tests!');
}

testProxyWrap().catch((err) => {
  console.error(err);
  process.exit(1);
});
