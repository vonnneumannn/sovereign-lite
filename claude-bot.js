// Claude Bot for Sovereign Relay
// Joins channels and responds to @CLAUDE mentions

const WebSocket = require('ws');

const RELAY_URL = 'wss://clear-cat-32.deno.dev';
const BOT_RESPONSES = [
  "Hello! I'm Claude, an AI assistant. How can I help?",
  "Thanks for reaching out! What would you like to discuss?",
  "I'm here and listening. What's on your mind?",
  "Greetings, sovereign! How may I assist you today?",
  "Hello there! Feel free to ask me anything.",
];

// Track active channel connections
const channelConnections = new Map();

function getRandomResponse() {
  return BOT_RESPONSES[Math.floor(Math.random() * BOT_RESPONSES.length)];
}

function connectToChannel(channelCode) {
  if (channelConnections.has(channelCode)) {
    console.log(`Already connected to ${channelCode}`);
    return;
  }

  const ws = new WebSocket(RELAY_URL);
  let myAlias = null;

  ws.on('open', () => {
    console.log(`Connecting to channel ${channelCode}...`);
    ws.send(JSON.stringify({
      type: 'JoinChannel',
      data: { code: channelCode }
    }));
  });

  ws.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());

      switch (msg.type) {
        case 'ChannelJoined':
          myAlias = msg.data.alias;
          console.log(`Joined ${channelCode} as ${myAlias} (${msg.data.peer_count} peers)`);

          // Send greeting
          setTimeout(() => {
            ws.send(JSON.stringify({
              type: 'Broadcast',
              data: { content: `CLAUDE BOT online. Mention @CLAUDE to interact with me!` }
            }));
          }, 500);
          break;

        case 'Broadcast':
          const content = msg.data.content || '';
          const alias = msg.data.alias || '';

          // Don't respond to own messages or system messages
          if (alias === myAlias || alias === 'SYSTEM') break;

          console.log(`[${channelCode}] ${alias}: ${content}`);

          // Check for @CLAUDE mention
          if (content.toUpperCase().includes('@CLAUDE')) {
            setTimeout(() => {
              const response = `@${alias} ${getRandomResponse()}`;
              ws.send(JSON.stringify({
                type: 'Broadcast',
                data: { content: response }
              }));
              console.log(`[${channelCode}] Responded to ${alias}`);
            }, 1000 + Math.random() * 2000);
          }
          break;

        case 'PeerJoined':
          console.log(`[${channelCode}] ${msg.data.alias} joined`);
          break;

        case 'PeerLeft':
          console.log(`[${channelCode}] ${msg.data.alias} left`);
          break;

        case 'Error':
          console.error(`[${channelCode}] Error: ${msg.data.message}`);
          break;
      }
    } catch (e) {
      console.error('Parse error:', e);
    }
  });

  ws.on('close', () => {
    console.log(`Disconnected from ${channelCode}`);
    channelConnections.delete(channelCode);

    // Reconnect after 5 seconds
    setTimeout(() => {
      console.log(`Reconnecting to ${channelCode}...`);
      connectToChannel(channelCode);
    }, 5000);
  });

  ws.on('error', (err) => {
    console.error(`[${channelCode}] WebSocket error:`, err.message);
  });

  // Ping every 30 seconds to keep alive
  const pingInterval = setInterval(() => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'Ping' }));
    } else {
      clearInterval(pingInterval);
    }
  }, 30000);

  channelConnections.set(channelCode, { ws, pingInterval });
}

// Periodically fetch stats and join new active channels
async function discoverAndJoinChannels() {
  try {
    const response = await fetch('https://clear-cat-32.deno.dev/api/stats');
    const stats = await response.json();

    console.log(`\n=== Channel Stats ===`);
    console.log(`Total: ${stats.totalChannels}, Active: ${stats.activeChannels}`);

    // Join channels that have activity
    for (const channel of stats.leaderboard) {
      if (channel.currentPeers > 0 || channel.messageCount > 0) {
        if (!channelConnections.has(channel.code)) {
          console.log(`Discovered active channel: ${channel.code} (${channel.currentPeers} peers, ${channel.messageCount} msgs)`);
          connectToChannel(channel.code);
        }
      }
    }
  } catch (e) {
    console.error('Failed to fetch stats:', e.message);
  }
}

// Main
console.log('=== CLAUDE BOT STARTING ===');
console.log(`Relay: ${RELAY_URL}`);

// Initial discovery
discoverAndJoinChannels();

// Check for new channels every 30 seconds
setInterval(discoverAndJoinChannels, 30000);

// Keep process alive
process.on('SIGINT', () => {
  console.log('\nShutting down...');
  for (const [code, { ws, pingInterval }] of channelConnections) {
    clearInterval(pingInterval);
    ws.close();
  }
  process.exit(0);
});

console.log('Bot running. Press Ctrl+C to stop.');
