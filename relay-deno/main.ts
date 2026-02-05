// Sovereign Relay Server for Deno Deploy
// Deploy: https://dash.deno.com -> New Project -> Import from GitHub

interface RoomStats {
  code: string;
  created: Date;
  totalMessages: number;
  totalPeersEver: number;
  currentPeers: Set<WebSocket>;
  lastActivity: Date;
}

const rooms = new Map<string, RoomStats>();

function generateRoomCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function broadcast(roomCode: string, message: string, exclude?: WebSocket) {
  const room = rooms.get(roomCode);
  if (room) {
    for (const ws of room.currentPeers) {
      if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    }
  }
}

function getRoomLeaderboard() {
  const allRooms = Array.from(rooms.values());

  // Sort by activity (messages + current peers)
  const sorted = allRooms.sort((a, b) => {
    const scoreA = a.totalMessages + (a.currentPeers.size * 100);
    const scoreB = b.totalMessages + (b.currentPeers.size * 100);
    return scoreB - scoreA;
  });

  return sorted.map(room => ({
    code: room.code,
    created: room.created.toISOString(),
    totalMessages: room.totalMessages,
    totalPeersEver: room.totalPeersEver,
    currentPeers: room.currentPeers.size,
    lastActivity: room.lastActivity.toISOString(),
    isActive: room.currentPeers.size > 0
  }));
}

function handleWebSocket(ws: WebSocket) {
  let currentRoom: string | null = null;

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);

      switch (msg.type) {
        case 'CreateRoom': {
          let code = generateRoomCode();
          while (rooms.has(code)) {
            code = generateRoomCode();
          }

          const now = new Date();
          rooms.set(code, {
            code,
            created: now,
            totalMessages: 0,
            totalPeersEver: 1,
            currentPeers: new Set([ws]),
            lastActivity: now
          });
          currentRoom = code;

          ws.send(JSON.stringify({
            type: 'RoomCreated',
            data: { code }
          }));

          console.log(`Room created: ${code}`);
          break;
        }

        case 'JoinRoom': {
          const code = msg.data?.code?.toUpperCase();
          if (!code) {
            ws.send(JSON.stringify({
              type: 'Error',
              data: { message: 'Room code required' }
            }));
            break;
          }

          let room = rooms.get(code);
          const now = new Date();

          if (!room) {
            room = {
              code,
              created: now,
              totalMessages: 0,
              totalPeersEver: 0,
              currentPeers: new Set(),
              lastActivity: now
            };
            rooms.set(code, room);
          }

          // Notify existing peers
          broadcast(code, JSON.stringify({ type: 'PeerJoined' }));

          // Join room
          room.currentPeers.add(ws);
          room.totalPeersEver++;
          room.lastActivity = now;
          currentRoom = code;

          ws.send(JSON.stringify({
            type: 'Joined',
            data: { code, peer_count: room.currentPeers.size }
          }));

          console.log(`Client joined room: ${code} (${room.currentPeers.size} peers)`);
          break;
        }

        case 'Forward': {
          if (currentRoom) {
            const room = rooms.get(currentRoom);
            if (room) {
              room.totalMessages++;
              room.lastActivity = new Date();
            }
            broadcast(currentRoom, JSON.stringify({
              type: 'Message',
              data: { data: msg.data?.data }
            }), ws);
          }
          break;
        }

        case 'GetStats': {
          ws.send(JSON.stringify({
            type: 'Stats',
            data: {
              totalRooms: rooms.size,
              activeRooms: Array.from(rooms.values()).filter(r => r.currentPeers.size > 0).length,
              leaderboard: getRoomLeaderboard().slice(0, 20)
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
    if (currentRoom) {
      const room = rooms.get(currentRoom);
      if (room) {
        room.currentPeers.delete(ws);
        broadcast(currentRoom, JSON.stringify({ type: 'PeerLeft' }));
        console.log(`Peer left room: ${currentRoom} (${room.currentPeers.size} remaining)`);
      }
    }
  };

  ws.onerror = (e) => {
    console.error('WebSocket error:', e);
  };
}

function generateStatsHTML(url: URL): string {
  const allRooms = Array.from(rooms.values());
  const activeRooms = allRooms.filter(r => r.currentPeers.size > 0);
  const totalMessages = allRooms.reduce((sum, r) => sum + r.totalMessages, 0);
  const totalPeers = allRooms.reduce((sum, r) => sum + r.currentPeers.size, 0);

  const leaderboard = getRoomLeaderboard().slice(0, 25);

  const roomRows = leaderboard.map((room, i) => `
    <tr style="background: ${room.isActive ? 'rgba(34, 197, 94, 0.1)' : 'transparent'}">
      <td>${i + 1}</td>
      <td><code style="color: ${room.isActive ? '#22c55e' : '#818cf8'}">${room.code}</code></td>
      <td>${room.currentPeers} ${room.isActive ? '🟢' : '⚫'}</td>
      <td>${room.totalMessages}</td>
      <td>${room.totalPeersEver}</td>
      <td>${new Date(room.lastActivity).toLocaleString()}</td>
    </tr>
  `).join('');

  return `
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sovereign Relay - Stats</title>
      <meta http-equiv="refresh" content="10">
      <style>
        body {
          font-family: system-ui;
          background: #0a0a0f;
          color: #f1f5f9;
          padding: 40px;
          max-width: 1000px;
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
      <p class="subtitle">Real-time room statistics (auto-refreshes every 10s)</p>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-value">${rooms.size}</div>
          <div class="stat-label">Total Rooms</div>
        </div>
        <div class="stat-card">
          <div class="stat-value active-badge">${activeRooms.length}</div>
          <div class="stat-label">Active Rooms</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${totalPeers}</div>
          <div class="stat-label">Connected Peers</div>
        </div>
        <div class="stat-card">
          <div class="stat-value">${totalMessages}</div>
          <div class="stat-label">Total Messages</div>
        </div>
      </div>

      <h2 style="margin-bottom: 16px;">Room Leaderboard</h2>
      <table>
        <thead>
          <tr>
            <th>#</th>
            <th>Room Code</th>
            <th>Peers Now</th>
            <th>Messages</th>
            <th>Total Visitors</th>
            <th>Last Activity</th>
          </tr>
        </thead>
        <tbody>
          ${roomRows || '<tr><td colspan="6" style="text-align: center; color: #64748b;">No rooms yet. Create one at the <a href="https://vonnneumannn.github.io/sovereign-lite/">Web App</a>!</td></tr>'}
        </tbody>
      </table>

      <p style="margin-top: 32px; color: #64748b;">
        WebSocket: <code>wss://${url.host}</code> |
        <a href="https://github.com/vonnneumannn/sovereign-lite">GitHub</a> |
        <a href="https://vonnneumannn.github.io/sovereign-lite/">Web App</a>
      </p>
    </body>
    </html>
  `;
}

Deno.serve({ port: 8000 }, (req) => {
  const url = new URL(req.url);

  // Health check
  if (url.pathname === '/health') {
    return new Response('OK', { status: 200 });
  }

  // JSON API for stats
  if (url.pathname === '/api/stats') {
    return new Response(JSON.stringify({
      totalRooms: rooms.size,
      activeRooms: Array.from(rooms.values()).filter(r => r.currentPeers.size > 0).length,
      leaderboard: getRoomLeaderboard()
    }), {
      headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
    });
  }

  // WebSocket upgrade
  if (req.headers.get('upgrade') === 'websocket') {
    const { socket, response } = Deno.upgradeWebSocket(req);
    handleWebSocket(socket);
    return response;
  }

  // Stats page (HTML)
  return new Response(generateStatsHTML(url), {
    headers: { 'Content-Type': 'text/html' },
  });
});

console.log('Sovereign Relay running on port 8000');
