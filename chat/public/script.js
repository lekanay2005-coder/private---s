const socket = io();

const usernameEl = document.getElementById('username');
const setNameBtn = document.getElementById('setName');
const roomEl = document.getElementById('room');
const joinRoomBtn = document.getElementById('joinRoom');
const leaveRoomBtn = document.getElementById('leaveRoom');
const messagesEl = document.getElementById('messages');
const messageEl = document.getElementById('message');
const sendBtn = document.getElementById('send');
const toUserEl = document.getElementById('toUser');
const switchPublicBtn = document.getElementById('switchPublic');
const chatHeaderEl = document.getElementById('chatHeader');

let currentRoom = null;
let currentMode = 'public'; // 'public' or 'group'

function timeFmt(ts) {
  const d = new Date(ts);
  return d.toLocaleTimeString();
}

function appendMessage(text, cls, ts) {
  const d = document.createElement('div');
  let prefix = '';
  if (ts) prefix = `[${timeFmt(ts)}] `;
  d.textContent = prefix + text;
  d.className = cls || '';
  messagesEl.appendChild(d);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

function updateChatHeader() {
  if (currentMode === 'public') {
    chatHeaderEl.textContent = '📢 Public Chat (Global)';
  } else {
    chatHeaderEl.textContent = `🔒 Group: ${currentRoom}`;
  }
}

// Auto-join public chat on load
socket.on('connect', () => {
  currentMode = 'public';
  currentRoom = 'public';
  socket.emit('create or join', 'public', (res) => {
    if (res && res.ok) {
      appendMessage('Connected to public chat', 'system');
      updateChatHeader();
      loadChatHistory('public');
    }
  });
});

function loadChatHistory(room) {
  fetch(`/history/${encodeURIComponent(room)}`)
    .then(r => r.ok ? r.json() : [])
    .then(rows => {
      rows.forEach((row) => {
        if (row.to_user) {
          appendMessage(`(private) ${row.from_user}: ${row.msg}`, 'private', row.ts);
        } else {
          appendMessage(`${row.from_user}: ${row.msg}`, 'msg', row.ts);
        }
      });
    })
    .catch(e => console.error('history load failed', e));
}

setNameBtn.addEventListener('click', () => {
  const name = usernameEl.value.trim();
  if (!name) return alert('Enter a name');
  socket.emit('set username', name, (res) => {
    if (res && res.ok) appendMessage(`Username set to ${name}`, 'system');
    else appendMessage(`Failed to set username: ${res && res.error}`, 'system');
  });
});

switchPublicBtn.addEventListener('click', async () => {
  if (currentMode === 'public') return;
  
  if (currentRoom) {
    socket.emit('leave room', currentRoom);
  }
  
  currentMode = 'public';
  currentRoom = 'public';
  messagesEl.innerHTML = '';
  socket.emit('create or join', 'public', (res) => {
    if (res && res.ok) {
      appendMessage('Switched to public chat', 'system');
      updateChatHeader();
      loadChatHistory('public');
    }
  });
});

joinRoomBtn.addEventListener('click', async () => {
  const room = roomEl.value.trim();
  if (!room) return alert('Enter a room name');
  
  if (currentMode === 'public' && currentRoom === 'public') {
    socket.emit('leave room', 'public');
  }
  
  currentMode = 'group';
  currentRoom = room;
  messagesEl.innerHTML = '';
  socket.emit('create or join', room, (res) => {
    if (res && res.ok) {
      appendMessage(`Joined group: ${room}`, 'system');
      updateChatHeader();
      loadChatHistory(room);
    }
  });
});

leaveRoomBtn.addEventListener('click', () => {
  const room = roomEl.value.trim();
  if (!room) return alert('Enter a room name');
  socket.emit('leave room', room, (res) => {
    if (res && res.ok) appendMessage(`Left room ${room}`, 'system');
  });
});

sendBtn.addEventListener('click', () => {
  const msg = messageEl.value.trim();
  if (!msg) return;
  const to = toUserEl.value.trim();
  
  if (to) {
    // Private message
    socket.emit('chat message', { room: null, msg, to });
  } else if (currentMode === 'public') {
    // Public chat
    socket.emit('chat message', { room: 'public', msg, to: null });
  } else {
    // Group chat
    socket.emit('chat message', { room: currentRoom, msg, to: null });
  }
  messageEl.value = '';
});

socket.on('system message', (txt) => appendMessage(txt, 'system'));
socket.on('chat message', (data) => {
  const label = data.room === 'public' ? '📢' : `🔒 ${data.room}`;
  appendMessage(`${data.from}: ${data.msg}`, 'msg', data.ts);
});
socket.on('private message', (data) => appendMessage(`(private) ${data.from}: ${data.msg}`, 'private', data.ts));
