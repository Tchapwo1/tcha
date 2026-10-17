/**
 * Tcha Protection Pro 2.0 — Live Target Case Study:
 * Wrapping @modelcontextprotocol/server-filesystem in the In-Line STDIO Firewall
 */

import { spawn } from 'child_process';
import * as readline from 'readline';
import * as path from 'path';

async function runLiveCaseStudy() {
  console.log('\n======================================================================');
  console.log('🛡️  Tcha Protection Pro 2.0 — Live Target Case Study');
  console.log('   Target: @modelcontextprotocol/server-filesystem (Official MCP Server)');
  console.log('======================================================================\n');

  const targetDir = path.resolve('specs');
  console.log(`[Target Config] Sandboxed Root: ${targetDir}`);
  console.log('[Tcha Action] Wrapping server via: `tcha wrap npx -y @modelcontextprotocol/server-filesystem`\n');

  const proxy = spawn('node', [
    'dist/cli/index.js',
    'wrap',
    'npx',
    '-y',
    '@modelcontextprotocol/server-filesystem',
    targetDir
  ], {
    stdio: ['pipe', 'pipe', 'inherit'],
  });

  const interceptedResponses = [];
  const rl = readline.createInterface({ input: proxy.stdout });
  rl.on('line', (line) => {
    try {
      const parsed = JSON.parse(line);
      interceptedResponses.push(parsed);
    } catch (e) {
      // Non-JSON logging
    }
  });

  const sendJsonRpc = (req) => {
    proxy.stdin.write(JSON.stringify(req) + '\n');
  };

  // Wait 3000ms for NPX and server to initialize
  await new Promise((r) => setTimeout(r, 3000));

  console.log('[Scenario 1] Attacker executes Path Traversal against host root...');
  sendJsonRpc({
    jsonrpc: '2.0',
    id: 101,
    method: 'tools/call',
    params: {
      name: 'read_file',
      arguments: { path: '../../../../Windows/System32/drivers/etc/hosts' }
    }
  });

  console.log('[Scenario 2] Attacker invokes destructive file deletion without authorization...');
  sendJsonRpc({
    jsonrpc: '2.0',
    id: 102,
    method: 'tools/call',
    params: {
      name: 'delete_file',
      arguments: { path: 'specs/01_PRD.md' }
    }
  });

  console.log('[Scenario 3] Attacker attempts SSRF metadata exfiltration through tool param...');
  sendJsonRpc({
    jsonrpc: '2.0',
    id: 103,
    method: 'tools/call',
    params: {
      name: 'write_file',
      arguments: {
        path: 'specs/exfil.txt',
        url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'
      }
    }
  });

  // Wait 2500ms for responses to resolve
  await new Promise((r) => setTimeout(r, 2500));
  proxy.kill();

  console.log('\n======================================================================');
  console.log('📊 Case Study Audit Interception Results:');
  console.log('======================================================================');

  const r1 = interceptedResponses.find((r) => r.id === 101);
  const r2 = interceptedResponses.find((r) => r.id === 102);
  const r3 = interceptedResponses.find((r) => r.id === 103);

  console.log(`\n1. Path Traversal Result:`);
  console.log(`   JSON-RPC Error Code: ${r1?.error?.code || 'None'}`);
  console.log(`   Message: ${r1?.error?.message}`);
  console.log(`   Verdict: ${r1?.error?.code === -32001 ? 'PARRIED BY TCHA (PASS)' : 'FAILED'}`);

  console.log(`\n2. Destructive Action Result:`);
  console.log(`   JSON-RPC Error Code: ${r2?.error?.code || 'None'}`);
  console.log(`   Threat Type: ${r2?.error?.data?.threat_type}`);
  console.log(`   HMAC Challenge Emitted: ${r2?.error?.data?.challenge ? 'YES' : 'NO'}`);
  console.log(`   Verdict: ${r2?.error?.code === -32001 ? 'SUSPENDED BY TCHA (PASS)' : 'FAILED'}`);

  console.log(`\n3. SSRF Metadata Exfiltration Result:`);
  console.log(`   JSON-RPC Error Code: ${r3?.error?.code || 'None'}`);
  console.log(`   Message: ${r3?.error?.message}`);
  console.log(`   Verdict: ${r3?.error?.code === -32001 ? 'BLOCKED BY TCHA (PASS)' : 'FAILED'}`);

  if (r1?.error?.code === -32001 && r2?.error?.code === -32001 && r3?.error?.code === -32001) {
    console.log('\n[PASS] Official MCP Filesystem Server successfully shielded by Tcha Protection Pro 2.0!\n');
  } else {
    console.error('\n[FAIL] One or more probes failed interception.\n');
    process.exit(1);
  }
}

runLiveCaseStudy().catch((err) => {
  console.error(err);
  process.exit(1);
});
