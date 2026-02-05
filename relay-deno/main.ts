// Sovereign Relay Server for Deno Deploy
// Deploy: https://dash.deno.com -> New Project -> Import from GitHub

const rooms = new Map<string, Set<WebSocket>>();

function generateRoomCode(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // No confusing chars
  let code = '';
  for (let i = 0; i < 6; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

function broadcast(roomCode: string, message: string, exclude?: WebSocket) {
  const room = rooms.get(roomCode);
  if (room) {
    for (const ws of room) {
      if (ws !== exclude && ws.readyState === WebSocket.OPEN) {
        ws.send(message);
      }
    }
  }
}

function handleWebSocket(ws: WebSocket) {
  let currentRoom: string | null = null;

  ws.onmessage = (event) => {
    try {
      const msg = JSON.parse(event.data);

      switch (msg.type) {
        case 'CreateRoom': {
          // Generate unique room code
          let code = generateRoomCode();
          while (rooms.has(code)) {
            code = generateRoomCode();
          }

          // Create room and join
          rooms.set(code, new Set([ws]));
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

          if (!room) {
            // Auto-create room if it doesn't exist (for flexibility)
            room = new Set();
            rooms.set(code, room);
          }

          // Notify existing peers
          broadcast(code, JSON.stringify({ type: 'PeerJoined' }));

          // Join room
          room.add(ws);
          currentRoom = code;

          ws.send(JSON.stringify({
            type: 'Joined',
            data: { code, peer_count: room.size }
          }));

          console.log(`Client joined room: ${code} (${room.size} peers)`);
          break;
        }

        case 'Forward': {
          if (currentRoom) {
            broadcast(currentRoom, JSON.stringify({
              type: 'Message',
              data: { data: msg.data?.data }
            }), ws);
          }
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
        room.delete(ws);

        // Notify remaining peers
        broadcast(currentRoom, JSON.stringify({ type: 'PeerLeft' }));

        // Keep room persistent - don't delete even if empty
        console.log(`Peer left room: ${currentRoom} (${room.size} remaining)`);
      }
    }
  };

  ws.onerror = (e) => {
    console.error('WebSocket error:', e);
  };
}

Deno.serve({ port: 8000 }, (req) => {
  const url = new URL(req.url);

  // Health check
  if (url.pathname === '/health') {
    return new Response('OK', { status: 200 });
  }

  // WebSocket upgrade
  if (req.headers.get('upgrade') === 'websocket') {
    const { socket, response } = Deno.upgradeWebSocket(req);
    handleWebSocket(socket);
    return response;
  }

  // Info page
  return new Response(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Sovereign Relay</title>
      <style>
        body { font-family: system-ui; background: #0a0a0f; color: #f1f5f9; padding: 40px; text-align: center; }
        h1 { color: #818cf8; }
        code { background: #1a1a25; padding: 4px 8px; border-radius: 4px; }
        a { color: #818cf8; }
      </style>
    </head>
    <body>
      <h1>🔐 Sovereign Relay Server</h1>
      <p>WebSocket relay for end-to-end encrypted communication.</p>
      <p>Connect via: <code>wss://${url.host}</code></p>
      <p><a href="https://github.com/vonnneumannn/sovereign-lite">GitHub</a> | <a href="https://vonnneumannn.github.io/sovereign-lite/">Web App</a></p>
      <p style="color: #64748b; margin-top: 40px;">Active rooms: ${rooms.size}</p>
    </body>
    </html>
  `, {
    headers: { 'Content-Type': 'text/html' },
  });
});

console.log('Sovereign Relay running on port 8000');
