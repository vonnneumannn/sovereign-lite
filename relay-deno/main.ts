// Sovereign Relay Server for Deno Deploy
// Channels with persistent message history using Deno KV

// Security: HTML escape function to prevent XSS in stats page
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// Security: Rate limiting
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_MESSAGES_PER_WINDOW = 100;
const MAX_CONNECTIONS_PER_IP = 10;
const MAX_MESSAGE_SIZE = 65536; // 64KB

const rateLimits = new Map<string, { count: number; reset: number }>();
const connectionCounts = new Map<string, number>();

// CORS: Allowed origins
const ALLOWED_ORIGINS = [
  'https://vonnneumannn.github.io',
  'http://localhost:8000',
  'http://localhost:3000',
  'http://127.0.0.1:8000',
];

function isOriginAllowed(origin: string | null): boolean {
  if (!origin) return false;
  return ALLOWED_ORIGINS.some(o => origin.startsWith(o));
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const limit = rateLimits.get(ip);
  if (!limit || now > limit.reset) {
    rateLimits.set(ip, { count: 1, reset: now + RATE_LIMIT_WINDOW });
    return true;
  }
  if (limit.count >= MAX_MESSAGES_PER_WINDOW) return false;
  limit.count++;
  return true;
}

function addConnection(ip: string): boolean {
  const count = connectionCounts.get(ip) || 0;
  if (count >= MAX_CONNECTIONS_PER_IP) return false;
  connectionCounts.set(ip, count + 1);
  return true;
}

function removeConnection(ip: string): void {
  const count = connectionCounts.get(ip) || 0;
  if (count > 0) connectionCounts.set(ip, count - 1);
}

interface Message {
  id: string;
  alias: string;
  content: string;
  timestamp: string; // ISO string for KV storage
  isAudio?: boolean; // Flag for audio messages
  expiresAt?: string; // ISO string for audio TTL
}

interface ChannelData {
  code: string;
  created: string;
  messages: Message[];
  totalPeersEver: number;
  lastActivity: string;
}

// Deno KV for persistence
const kv = await Deno.openKv();

// In-memory peer tracking (can't persist WebSocket connections)
const channelPeers = new Map<string, Map<WebSocket, string>>(); // channelCode -> (ws -> alias)

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

async function getChannel(code: string): Promise<ChannelData | null> {
  const result = await kv.get<ChannelData>(["channels", code]);
  return result.value;
}

async function saveChannel(channel: ChannelData): Promise<void> {
  await kv.set(["channels", channel.code], channel);
}

async function getAllChannels(): Promise<ChannelData[]> {
  const channels: ChannelData[] = [];
  const iter = kv.list<ChannelData>({ prefix: ["channels"] });
  for await (const entry of iter) {
    channels.push(entry.value);
  }
  return channels;
}

function getPeers(code: string): Map<WebSocket, string> {
  if (!channelPeers.has(code)) {
    channelPeers.set(code, new Map());
  }
  return channelPeers.get(code)!;
}

function broadcast(channelCode: string, message: string, exclude?: WebSocket) {
  const peers = getPeers(channelCode);
  for (const [ws] of peers) {
    if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
      ws.send(message);
    }
  }
}

async function getChannelLeaderboard() {
  const allChannels = await getAllChannels();

  const sorted = allChannels.sort((a, b) => {
    const peersA = getPeers(a.code).size;
    const peersB = getPeers(b.code).size;
    const scoreA = a.messages.length + (peersA * 100);
    const scoreB = b.messages.length + (peersB * 100);
    return scoreB - scoreA;
  });

  return sorted.map(channel => {
    const peers = getPeers(channel.code);
    return {
      code: channel.code,
      created: channel.created,
      messageCount: channel.messages.length,
      totalPeersEver: channel.totalPeersEver,
      currentPeers: peers.size,
      activeAliases: Array.from(peers.values()),
      lastActivity: channel.lastActivity,
      isActive: peers.size > 0,
      recentMessages: channel.messages.slice(-5).map(m => ({
        alias: m.alias,
        preview: m.content.substring(0, 50) + (m.content.length > 50 ? '...' : ''),
        time: m.timestamp
      }))
    };
  });
}

function handleWebSocket(ws: WebSocket, clientIp: string = 'unknown') {
  let currentChannel: string | null = null;
  let myAlias: string = generateAlias();

  ws.onmessage = async (event) => {
    try {
      // Security: Check message size
      const data = typeof event.data === 'string' ? event.data : '';
      if (data.length > MAX_MESSAGE_SIZE) {
        ws.send(JSON.stringify({ type: 'Error', data: { message: 'Message too large' } }));
        return;
      }

      // Security: Rate limiting
      if (!checkRateLimit(clientIp)) {
        ws.send(JSON.stringify({ type: 'Error', data: { message: 'Rate limit exceeded' } }));
        return;
      }

      const msg = JSON.parse(data);

      switch (msg.type) {
        case 'CreateChannel':
        case 'CreateRoom': {
          let code = generateChannelCode();
          while (await getChannel(code)) {
            code = generateChannelCode();
          }

          const now = new Date().toISOString();
          const channel: ChannelData = {
            code,
            created: now,
            messages: [{
              id: generateMessageId(),
              alias: 'SYSTEM',
              content: `Channel ${code} created by ${myAlias}`,
              timestamp: now
            }],
            totalPeersEver: 1,
            lastActivity: now
          };

          await saveChannel(channel);
          getPeers(code).set(ws, myAlias);
          currentChannel = code;

          ws.send(JSON.stringify({
            type: 'ChannelCreated',
            data: {
              code,
              alias: myAlias,
              history: channel.messages
            }
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

          let channel = await getChannel(code);
          const now = new Date().toISOString();

          if (!channel) {
            channel = {
              code,
              created: now,
              messages: [],
              totalPeersEver: 0,
              lastActivity: now
            };
          }

          // Notify existing peers
          broadcast(code, JSON.stringify({
            type: 'PeerJoined',
            data: { alias: myAlias }
          }));

          // Join channel
          getPeers(code).set(ws, myAlias);
          channel.totalPeersEver++;
          channel.lastActivity = now;
          channel.messages.push({
            id: generateMessageId(),
            alias: 'SYSTEM',
            content: `${myAlias} joined the channel`,
            timestamp: now
          });

          await saveChannel(channel);
          currentChannel = code;

          const peers = getPeers(code);

          // Filter out expired audio messages before sending history
          const currentTime = new Date();
          const filteredHistory = channel.messages.filter(m => {
            if (m.isAudio && m.expiresAt) {
              return new Date(m.expiresAt) > currentTime;
            }
            return true;
          });

          ws.send(JSON.stringify({
            type: 'ChannelJoined',
            data: {
              code,
              alias: myAlias,
              peer_count: peers.size,
              activeAliases: Array.from(peers.values()),
              history: filteredHistory
            }
          }));

          console.log(`${myAlias} joined channel: ${code} (${peers.size} peers)`);
          break;
        }

        case 'Broadcast':
        case 'Forward': {
          if (currentChannel) {
            const channel = await getChannel(currentChannel);
            if (channel) {
              const now = new Date();
              const nowISO = now.toISOString();
              const content = msg.data?.data || msg.data?.content || '';

              // Check if this is an audio message
              const isAudio = content.startsWith('AUDIO:');

              const message: Message = {
                id: generateMessageId(),
                alias: myAlias,
                content,
                timestamp: nowISO,
                isAudio,
                // Audio expires after 5 minutes
                expiresAt: isAudio ? new Date(now.getTime() + 5 * 60 * 1000).toISOString() : undefined
              };

              // Clean up expired audio messages before adding new one
              const currentTime = new Date();
              channel.messages = channel.messages.filter(m => {
                if (m.isAudio && m.expiresAt) {
                  return new Date(m.expiresAt) > currentTime;
                }
                return true; // Keep non-audio messages forever
              });

              channel.messages.push(message);
              channel.lastActivity = nowISO;
              await saveChannel(channel);

              // Broadcast to all including sender
              const broadcastMsg = JSON.stringify({
                type: 'Broadcast',
                data: message
              });

              const peers = getPeers(currentChannel);
              for (const [peerWs] of peers) {
                if (peerWs.readyState === WebSocket.OPEN) {
                  peerWs.send(broadcastMsg);
                }
              }
            }
          }
          break;
        }

        case 'GetHistory': {
          if (currentChannel) {
            const channel = await getChannel(currentChannel);
            if (channel) {
              // Filter expired audio messages
              const currentTime = new Date();
              const filteredMessages = channel.messages.filter(m => {
                if (m.isAudio && m.expiresAt) {
                  return new Date(m.expiresAt) > currentTime;
                }
                return true;
              });

              ws.send(JSON.stringify({
                type: 'History',
                data: {
                  code: currentChannel,
                  messages: filteredMessages
                }
              }));
            }
          }
          break;
        }

        case 'GetStats': {
          const allChannels = await getAllChannels();
          const activeCount = allChannels.filter(c => getPeers(c.code).size > 0).length;
          ws.send(JSON.stringify({
            type: 'Stats',
            data: {
              totalChannels: allChannels.length,
              activeChannels: activeCount,
              leaderboard: (await getChannelLeaderboard()).slice(0, 20)
            }
          }));
          break;
        }

        case 'Ping': {
          ws.send(JSON.stringify({ type: 'Pong' }));
          break;
        }
      }
    } catch (_e) {
      console.error(`Error handling message from ${clientIp}`);
    }
  };

  ws.onclose = async () => {
    removeConnection(clientIp);
    if (currentChannel) {
      const peers = getPeers(currentChannel);
      peers.delete(ws);

      const channel = await getChannel(currentChannel);
      if (channel) {
        channel.messages.push({
          id: generateMessageId(),
          alias: 'SYSTEM',
          content: `${myAlias} left the channel`,
          timestamp: new Date().toISOString()
        });
        await saveChannel(channel);
      }

      broadcast(currentChannel, JSON.stringify({
        type: 'PeerLeft',
        data: { alias: myAlias }
      }));

      console.log(`${myAlias} left channel: ${currentChannel} (${peers.size} remaining)`);
    }
  };

  ws.onerror = (e) => {
    console.error('WebSocket error:', e);
  };
}

async function generateStatsHTML(url: URL): Promise<string> {
  const allChannels = await getAllChannels();
  const activeChannels = allChannels.filter(c => getPeers(c.code).size > 0);
  const totalMessages = allChannels.reduce((sum, c) => sum + c.messages.length, 0);
  const totalPeers = allChannels.reduce((sum, c) => sum + getPeers(c.code).size, 0);

  const leaderboard = (await getChannelLeaderboard()).slice(0, 25);

  const channelRows = leaderboard.map((channel, i) => {
    // Security: Escape all user-generated content
    const safeCode = escapeHtml(channel.code);
    const safeAliases = channel.activeAliases.map(escapeHtml);
    return `
    <tr style="background: ${channel.isActive ? 'rgba(34, 197, 94, 0.1)' : 'transparent'}">
      <td>${i + 1}</td>
      <td><code style="color: ${channel.isActive ? '#22c55e' : '#818cf8'}">${safeCode}</code></td>
      <td>${channel.currentPeers} ${channel.isActive ? '🟢' : '⚫'}</td>
      <td title="${safeAliases.join(', ')}">${safeAliases.slice(0, 3).join(', ')}${safeAliases.length > 3 ? '...' : ''}</td>
      <td>${channel.messageCount}</td>
      <td>${channel.totalPeersEver}</td>
      <td>${new Date(channel.lastActivity).toLocaleString()}</td>
    </tr>
  `}).join('');

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
          <div class="stat-value">${allChannels.length}</div>
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

Deno.serve({ port: 8000 }, async (req) => {
  const url = new URL(req.url);
  const origin = req.headers.get('origin');

  // CORS headers
  const corsHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
  if (origin && isOriginAllowed(origin)) {
    corsHeaders['Access-Control-Allow-Origin'] = origin;
  }

  if (url.pathname === '/health') {
    return new Response('OK', { status: 200 });
  }

  // Handle CORS preflight
  if (req.method === 'OPTIONS') {
    return new Response(null, {
      status: 204,
      headers: {
        ...corsHeaders,
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Max-Age': '86400',
      }
    });
  }

  if (url.pathname === '/api/stats') {
    const allChannels = await getAllChannels();
    const activeCount = allChannels.filter(c => getPeers(c.code).size > 0).length;
    return new Response(JSON.stringify({
      totalChannels: allChannels.length,
      activeChannels: activeCount,
      leaderboard: await getChannelLeaderboard()
    }), { headers: corsHeaders });
  }

  if (req.headers.get('upgrade') === 'websocket') {
    // Security: Validate WebSocket origin
    if (origin && !isOriginAllowed(origin)) {
      console.warn(`WebSocket rejected from: ${origin}`);
      return new Response('Forbidden', { status: 403 });
    }

    // Security: Rate limit connections per IP
    const clientIp = req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
                     req.headers.get('cf-connecting-ip') || 'unknown';

    if (!addConnection(clientIp)) {
      console.warn(`Connection limit exceeded: ${clientIp}`);
      return new Response('Too Many Connections', { status: 429 });
    }

    const { socket, response } = Deno.upgradeWebSocket(req);
    handleWebSocket(socket, clientIp);
    return response;
  }

  return new Response(await generateStatsHTML(url), {
    headers: { 'Content-Type': 'text/html' },
  });
});

console.log('Sovereign Relay running on port 8000 with Deno KV persistence');
