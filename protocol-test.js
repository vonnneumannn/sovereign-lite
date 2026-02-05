// Protocol Unit Tests for Sovereign Relay
// Tests: CreateChannel, JoinChannel, Broadcast, History, Stats, PeerJoined, PeerLeft

const WebSocket = require('ws');

// Configuration via environment variables (security: avoid hardcoded URLs)
const RELAY_URL = process.env.RELAY_URL || 'wss://clear-cat-32.deno.dev';
const API_URL = process.env.API_URL || RELAY_URL.replace('wss://', 'https://').replace('ws://', 'http://');

let testsPassed = 0;
let testsFailed = 0;

function test(name, condition) {
  if (condition) {
    console.log(`  ✓ ${name}`);
    testsPassed++;
  } else {
    console.log(`  ✗ ${name}`);
    testsFailed++;
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function createAgent(name) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(RELAY_URL);
    const agent = {
      name,
      ws,
      alias: null,
      channelCode: null,
      messages: [],
      events: [],
      history: []
    };

    ws.on('open', () => resolve(agent));
    ws.on('error', reject);

    ws.on('message', (data) => {
      const msg = JSON.parse(data.toString());
      agent.events.push(msg);

      switch (msg.type) {
        case 'ChannelCreated':
          agent.alias = msg.data.alias;
          agent.channelCode = msg.data.code;
          agent.history = msg.data.history || [];
          break;
        case 'ChannelJoined':
          agent.alias = msg.data.alias;
          agent.channelCode = msg.data.code;
          agent.history = msg.data.history || [];
          break;
        case 'Broadcast':
          agent.messages.push(msg.data);
          break;
      }
    });
  });
}

async function runTests() {
  console.log('=== SOVEREIGN RELAY PROTOCOL TESTS ===\n');

  // Test 1: Create Channel
  console.log('1. Create Channel Test');
  const agent1 = await createAgent('Agent1');
  agent1.ws.send(JSON.stringify({ type: 'CreateChannel' }));
  await sleep(1000);

  test('Channel code received', agent1.channelCode && agent1.channelCode.length === 6);
  test('Alias assigned', agent1.alias && agent1.alias.length > 0);
  test('History includes system message', agent1.history.length > 0 && agent1.history[0].alias === 'SYSTEM');

  const channelCode = agent1.channelCode;
  console.log(`   Channel: ${channelCode}, Alias: ${agent1.alias}\n`);

  // Test 2: Join Channel (Agent 2)
  console.log('2. Join Channel Test (Agent 2)');
  const agent2 = await createAgent('Agent2');
  agent2.ws.send(JSON.stringify({ type: 'JoinChannel', data: { code: channelCode } }));
  await sleep(1000);

  test('Agent2 joined same channel', agent2.channelCode === channelCode);
  test('Agent2 has different alias', agent2.alias !== agent1.alias);
  test('Agent2 received history', agent2.history.length >= 1);

  // Check if Agent1 received PeerJoined
  const peerJoinedEvent = agent1.events.find(e => e.type === 'PeerJoined');
  test('Agent1 notified of Agent2 joining', peerJoinedEvent && peerJoinedEvent.data.alias === agent2.alias);

  console.log(`   Agent2 Alias: ${agent2.alias}\n`);

  // Test 3: Join Channel (Agent 3)
  console.log('3. Join Channel Test (Agent 3)');
  const agent3 = await createAgent('Agent3');
  agent3.ws.send(JSON.stringify({ type: 'JoinChannel', data: { code: channelCode } }));
  await sleep(1000);

  test('Agent3 joined same channel', agent3.channelCode === channelCode);
  test('Agent3 has unique alias', agent3.alias !== agent1.alias && agent3.alias !== agent2.alias);
  test('3 unique aliases in channel', new Set([agent1.alias, agent2.alias, agent3.alias]).size === 3);

  console.log(`   Agent3 Alias: ${agent3.alias}\n`);

  // Test 4: Broadcast Messages
  console.log('4. Broadcast Test');
  const testMessage1 = `Test message from Agent1 at ${Date.now()}`;
  agent1.ws.send(JSON.stringify({ type: 'Broadcast', data: { content: testMessage1 } }));
  await sleep(500);

  test('Agent1 received own broadcast', agent1.messages.some(m => m.content === testMessage1));
  test('Agent2 received Agent1 broadcast', agent2.messages.some(m => m.content === testMessage1));
  test('Agent3 received Agent1 broadcast', agent3.messages.some(m => m.content === testMessage1));

  const testMessage2 = `Test message from Agent2 at ${Date.now()}`;
  agent2.ws.send(JSON.stringify({ type: 'Broadcast', data: { content: testMessage2 } }));
  await sleep(500);

  test('All agents receive Agent2 broadcast',
    agent1.messages.some(m => m.content === testMessage2) &&
    agent2.messages.some(m => m.content === testMessage2) &&
    agent3.messages.some(m => m.content === testMessage2)
  );

  console.log('');

  // Test 5: Message History
  console.log('5. Message History Test');
  const agent4 = await createAgent('Agent4');
  agent4.ws.send(JSON.stringify({ type: 'JoinChannel', data: { code: channelCode } }));
  await sleep(1000);

  test('New joiner receives message history', agent4.history.length >= 3);
  test('History includes broadcast messages', agent4.history.some(m => m.content === testMessage1));

  console.log(`   Agent4 received ${agent4.history.length} historical messages\n`);

  // Test 6: Get Stats
  console.log('6. Stats API Test');
  const statsResponse = await fetch(API_URL + '/api/stats');
  const stats = await statsResponse.json();

  test('Stats endpoint returns JSON', stats && typeof stats.totalChannels === 'number');
  test('Total channels >= 1', stats.totalChannels >= 1);
  test('Active channels >= 1', stats.activeChannels >= 1);
  test('Leaderboard contains our channel', stats.leaderboard.some(c => c.code === channelCode));

  const ourChannel = stats.leaderboard.find(c => c.code === channelCode);
  test('Channel shows 4 current peers', ourChannel && ourChannel.currentPeers === 4);

  console.log(`   Total channels: ${stats.totalChannels}, Active: ${stats.activeChannels}\n`);

  // Test 7: Peer Left Notification
  console.log('7. Peer Leave Test');
  agent4.ws.close();
  await sleep(1000);

  const peerLeftEvent = agent1.events.find(e => e.type === 'PeerLeft' && e.data.alias === agent4.alias);
  test('Remaining agents notified when peer leaves', !!peerLeftEvent);

  console.log('');

  // Test 8: Channel Persistence
  console.log('8. Channel Persistence Test');
  // Close all agents
  agent1.ws.close();
  agent2.ws.close();
  agent3.ws.close();
  await sleep(1500);

  // Check stats - channel should still exist
  const statsAfter = await fetch(API_URL + '/api/stats');
  const statsDataAfter = await statsAfter.json();
  const channelStillExists = statsDataAfter.leaderboard.some(c => c.code === channelCode);
  test('Channel persists after all peers leave', channelStillExists);

  // Rejoin and check history is preserved
  const agent5 = await createAgent('Agent5');
  agent5.ws.send(JSON.stringify({ type: 'JoinChannel', data: { code: channelCode } }));
  await sleep(1000);

  test('History preserved after channel was empty', agent5.history.length >= 4);
  test('Old messages still accessible', agent5.history.some(m => m.content === testMessage1));

  console.log(`   Channel ${channelCode} preserved ${agent5.history.length} messages\n`);

  // Test 9: @CLAUDE Bot Response
  console.log('9. @CLAUDE Bot Test');
  agent5.ws.send(JSON.stringify({ type: 'Broadcast', data: { content: '@CLAUDE Hello, are you there?' } }));
  await sleep(4000); // Wait for bot to respond

  const botResponse = agent5.messages.find(m =>
    m.content && m.content.includes('@') && m.alias !== agent5.alias && m.alias !== 'SYSTEM'
  );
  test('Claude bot responds to mention', !!botResponse);

  if (botResponse) {
    console.log(`   Bot response: "${botResponse.content.substring(0, 60)}..."\n`);
  }

  // Cleanup
  agent5.ws.close();

  // Summary
  console.log('=== TEST SUMMARY ===');
  console.log(`Passed: ${testsPassed}`);
  console.log(`Failed: ${testsFailed}`);
  console.log(`Total:  ${testsPassed + testsFailed}`);

  process.exit(testsFailed > 0 ? 1 : 0);
}

runTests().catch(err => {
  console.error('Test failed with error:', err);
  process.exit(1);
});
