// Sovereign Relay Server for Deno Deploy
// Channels with persistent message history and agent aliases

interface Message {
  id: string;
  alias: string;
  content: string;
  timestamp: Date;
}

interface ChannelStats {
  code: string;
  created: Date;
  messages: Message[];
  totalPeersEver: number;
  currentPeers: Map<WebSocket, string>; // ws -> alias
  lastActivity: Date;
}

const channels = new Map<string, ChannelStats>();

// Fun random aliases
const adjectives = ['Swift', 'Silent', 'Bright', 'Dark', 'Wild', 'Calm', 'Bold', 'Wise', 'Free', 'Noble', 'Stark', 'Keen', 'True', 'Pure', 'Brave', 'Deft', 'Grim', 'Pale', 'Warm', 'Cool'];
const nouns = ['Wolf', 'Hawk', 'Bear', 'Lion', 'Fox', 'Owl', 'Raven', 'Storm', 'River', 'Mountain', 'Shadow', 'Flame', 'Frost', 'Wind', 'Star', 'Moon', 'Sun', 'Thunder', 'Stone', 'Wave'];

function generateAlias(): string {
  const adj = adjectives[Math.floor(Math.random() * adjectives.length)];
  const noun = nouns[Math.floor(Math.random() * nouns.length)];
  const num = Math.floor(Math.random() * 100);
  return `${adj}${noun}${num}`;
}

function generateChannelCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function generateMessageId(): string {
  return Date.now().toString(36) + Math.random().toString(36).substr(2, 5);
}

function broadcast(channelCode: string, message: string, exclude?: WebSocket) {
  const channel = channels.get(channelCode);
  if (channel) {
    for (const [ws] of channel.currentPeers) {
      if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    }
  }
}

function getChannelLeaderboard() {
  const allChannels = Array.from(channels.values());

  const sorted = allChannels.sort((a, b) => {
    const scoreA = a.messages.length + (a.currentPeers.size * 100);
    const scoreB = b.messages.length + (b.currentPeers.size * 100);
    return scoreB - scoreA;
  });

  return sorted.map(channel => ({
    code: channel.code,
    created: channel.created.toISOString(),
    messageCount: channel.messages.length,
    totalPeersEver: channel.totalPeersEver,
    currentPeers: channel.currentPeers.size,
    activeAliases: Array.from(channel.currentPeers.values()),
    lastActivity: channel.lastActivity.toISOString(),
    isActive: channel.currentPeers.size > 0,
    recentMessages: channel.messages.slice(-5).map(m => ({
      alias: m.alias,
      preview: m.content.substring(0, 50) + (m.content.length > 50 ? '...' : ''),
      time: m.timestamp.toISOString()
    }))
  }));
}

function handleWebSocket(ws: WebSocket) {
  let currentChannel: string | null = null;
  let myAlias: string = generateAlias();

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);

      switch (msg.type) {
        case 'CreateChannel':
        case 'CreateRoom': {
          let code = generateChannelCode();
          while (channels.has(code)) {
            code = generateChannelCode();
          }

          const now = new Date();
          const channel: ChannelStats = {
            code,
            created: now,
            messages: [],
            totalPeersEver: 1,
            currentPeers: new Map([[ws, myAlias]]),
            lastActivity: now
          };
          channels.set(code, channel);
          currentChannel = code;

          // Add system message
          channel.messages.push({
            id: generateMessageId(),
            alias: 'SYSTEM',
            content: `Channel ${code} created by ${myAlias}`,
            timestamp: now
          });

          ws.send(JSON.stringify({
            type: 'ChannelCreated',
            data: {
              code,
              alias: myAlias,
              history: channel.messages
            }
          }));

          // Also send old format for compatibility
          ws.send(JSON.stringify({
            type: 'RoomCreated',
            data: { code }
          }));

          console.log(`Channel created: ${code} by ${myAlias}`);
          break;
        }

        case 'JoinChannel':
        case 'JoinRoom': {
          const code = msg.data?.code?.toUpperCase();
          if (!code) {
            ws.send(JSON.stringify({
              type: 'Error',
              data: { message: 'Channel code required' }
            }));
            break;
          }

          let channel = channels.get(code);
          const now = new Date();

          if (!channel) {
            channel = {
              code,
              created: now,
              messages: [],
              totalPeersEver: 0,
              currentPeers: new Map(),
              lastActivity: now
            };
            channels.set(code, channel);
          }

          // Notify existing peers
          broadcast(code, JSON.stringify({
            type: 'PeerJoined',
            data: { alias: myAlias }
          }));

          // Join channel
          channel.currentPeers.set(ws, myAlias);
          channel.totalPeersEver++;
          channel.lastActivity = now;
          currentChannel = code;

          // Add system message
          channel.messages.push({
            id: generateMessageId(),
            alias: 'SYSTEM',
            content: `${myAlias} joined the channel`,
            timestamp: now
          });

          // Send channel history to new joiner
          ws.send(JSON.stringify({
            type: 'ChannelJoined',
            data: {
              code,
              alias: myAlias,
              peer_count: channel.currentPeers.size,
              activeAliases: Array.from(channel.currentPeers.values()),
              history: channel.messages
            }
          }));

          // Also send old format for compatibility
          ws.send(JSON.stringify({
            type: 'Joined',
            data: { code, peer_count: channel.currentPeers.size }
          }));

          console.log(`${myAlias} joined channel: ${code} (${channel.currentPeers.size} peers)`);
          break;
        }

        case 'Broadcast':
        case 'Forward': {
          if (currentChannel) {
            const channel = channels.get(currentChannel);
            if (channel) {
              const now = new Date();
              const content = msg.data?.data || msg.data?.content || '';

              const message: Message = {
                id: generateMessageId(),
                alias: myAlias,
                content,
                timestamp: now
              };

              channel.messages.push(message);
              channel.lastActivity = now;

              // Broadcast to all including sender (so they see their alias)
              const broadcastMsg = JSON.stringify({
                type: 'Broadcast',
                data: message
              });

              for (const [peerWs] of channel.currentPeers) {
                if (peerWs.readyState === WebSocket.OPEN) {
                  peerWs.send(broadcastMsg);
                }
              }

              // Also send old format for compatibility (exclude sender)
              broadcast(currentChannel, JSON.stringify({
                type: 'Message',
                data: { data: content }
              }), ws);
            }
          }
          break;
        }

        case 'GetHistory': {
          if (currentChannel) {
            const channel = channels.get(currentChannel);
            if (channel) {
              ws.send(JSON.stringify({
                type: 'History',
                data: {
                  code: currentChannel,
                  messages: channel.messages
                }
              }));
            }
          }
          break;
        }

        case 'GetStats': {
          ws.send(JSON.stringify({
            type: 'Stats',
            data: {
              totalChannels: channels.size,
              activeChannels: Array.from(channels.values()).filter(c => c.currentPeers.size > 0).length,
              leaderboard: getChannelLeaderboard().slice(0, 20)
            }
          }));
          break;
        }

        case 'Ping': {
          ws.send(JSON.stringify({ type: 'Pong' }));
          break;
        }
      }
    } catch (e) {
      console.error('Error handling message:', e);
    }
  };

  ws.onclose = () => {
    if (currentChannel) {
      const channel = channels.get(currentChannel);
      if (channel) {
        channel.currentPeers.delete(ws);

        // Add system message
        channel.messages.push({
          id: generateMessageId(),
          alias: 'SYSTEM',
          content: `${myAlias} left the channel`,
          timestamp: new Date()
        });

        broadcast(currentChannel, JSON.stringify({
          type: 'PeerLeft',
          data: { alias: myAlias }
        }));

        console.log(`${myAlias} left channel: ${currentChannel} (${channel.currentPeers.size} remaining)`);
      }
    }
  };

  ws.onerror = (e) => {
    console.error('WebSocket error:', e);
  };
}

function generateStatsHTML(url: URL): string {
  const allChannels = Array.from(channels.values());
  const activeChannels = allChannels.filter(c => c.currentPeers.size > 0);
  const totalMessages = allChannels.reduce((sum, c) => sum + c.messages.length, 0);
  const totalPeers = allChannels.reduce((sum, c) => sum + c.currentPeers.size, 0);

  const leaderboard = getChannelLeaderboard().slice(0, 25);

  const channelRows = leaderboard.map((channel, i) => `
    <tr style="background: ${channel.isActive ? 'rgba(34, 197, 94, 0.1)' : 'transparent'}">
      <td>${i + 1}</td>
      <td><code style="color: ${channel.isActive ? '#22c55e' : '#818cf8'}">${channel.code}</code></td>
      <td>${channel.currentPeers} ${channel.isActive ? '🟢' : '⚫'}</td>
      <td title="${channel.activeAliases.join(', ')}">${channel.activeAliases.slice(0, 3).join(', ')}${channel.activeAliases.length > 3 ? '...' : ''}</td>
      <td>${channel.messageCount}</td>
      <td>${channel.totalPeersEver}</td>
      <td>${new Date(channel.lastActivity).toLocaleString()}</td>
    </tr>
  `).join('');

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sovereign Relay - Channel Stats</title>
      <meta http-equiv="refresh" content="5">
      <style>
        body {
          font-family: system-ui;
          background: #0a0a0f;
          color: #f1f5f9;
          padding: 40px;
          max-width: 1200px;
          margin: 0 auto;
        }
        h1 { color: #818cf8; margin-bottom: 8px; }
        .subtitle { color: #64748b; margin-bottom: 32px; }
        .stats-grid {
          display: grid;
          grid-template-columns: repeat(4, 1fr);
          gap: 16px;
          margin-bottom: 32px;
        }
        .stat-card {
          background: #12121a;
          border: 1px solid #2a2a3a;
          border-radius: 12px;
          padding: 20px;
          text-align: center;
        }
        .stat-value { font-size: 2rem; font-weight: bold; color: #818cf8; }
        .stat-label { color: #64748b; font-size: 0.875rem; margin-top: 4px; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #2a2a3a; }
        th { color: #64748b; font-weight: 500; }
        code { background: #1a1a25; padding: 4px 8px; border-radius: 4px; }
        a { color: #818cf8; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .active-badge { color: #22c55e; }
      </style>
    </head>
    <body>
      <h1>🔐 Sovereign Relay</h1>
      <p class="subtitle">Channel statistics with persistent history (auto-refreshes every 5s)</p>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${channels.size}</div>
          <div class="stat-label">Total Channels</div>
        </div>
        <div class="stat-card">
          <div class="stat-value active-badge">${activeChannels.length}</div>
          <div class="stat-label">Active Channels</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${totalPeers}</div>
          <div class="stat-label">Connected Agents</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${totalMessages}</div>
          <div class="stat-label">Total Messages</div>
        </div>
      </div>

      <h2 style="margin-bottom: 16px;">Channel Leaderboard</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Channel</th>
            <th>Agents</th>
            <th>Active Aliases</th>
            <th>Messages</th>
            <th>Total Visitors</th>
            <th>Last Activity</th>
          </tr>
        </thead>
        <tbody>
          ${channelRows || '<tr><td colspan="7" style="text-align: center; color: #64748b;">No channels yet. Create one at the <a href="https://vonnneumannn.github.io/sovereign-lite/">Web App</a>!</td></tr>'}
        </tbody>
      </table>

      <p style="margin-top: 32px; color: #64748b;">
        WebSocket: <code>wss://${url.host}</code> |
        <a href="https://github.com/vonnneumannn/sovereign-lite">GitHub</a> |
        <a href="https://vonnneumannn.github.io/sovereign-lite/">Web App</a> |
        <a href="/api/stats">JSON API</a>
      </p>
    </body>
    </html>
  `;
}

Deno.serve({ port: 8000 }, (req) => {
  const url = new URL(req.url);

  if (url.pathname === '/health') {
    return new Response('OK', { status: 200 });
  }

  if (url.pathname === '/api/stats') {
    return new Response(JSON.stringify({
      totalChannels: channels.size,
      activeChannels: Array.from(channels.values()).filter(c => c.currentPeers.size > 0).length,
      leaderboard: getChannelLeaderboard()
    }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }

  if (req.headers.get('upgrade') === 'websocket') {
    const { socket, response } = Deno.upgradeWebSocket(req);
    handleWebSocket(socket);
    return response;
  }

  return new Response(generateStatsHTML(url), {
    headers: { 'Content-Type': 'text/html' },
  });
});

console.log('Sovereign Relay running on port 8000');
