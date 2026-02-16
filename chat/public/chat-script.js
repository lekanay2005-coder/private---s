const token = localStorage.getItem('token');
if (!token) {
  window.location.href = '/login.html';
}

const socket = io({
  auth: { token }
});

const userDisplayNameEl = document.getElementById('userDisplayName');
const logoutBtn = document.getElementById('logoutBtn');
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
let isAdmin = false;
let adminPanelEl = null;
let typingTimeout = null;
const typingUsers = new Set();

// Toast notification system
function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: ${type === 'error' ? '#d32f2f' : type === 'success' ? '#28a745' : '#667eea'};
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0,0,0,0.2);
    z-index: 2000;
    animation: slideInRight 0.3s ease-out;
    font-weight: 500;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.animation = 'slideOutRight 0.3s ease-in';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Add CSS animations if not exist
if (!document.getElementById('toastStyles')) {
  const style = document.createElement('style');
  style.id = 'toastStyles';
  style.textContent = `
    @keyframes slideInRight {
      from { transform: translateX(400px); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOutRight {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(400px); opacity: 0; }
    }
  `;
  document.head.appendChild(style);
}

// Check if user is admin by decoding token
function checkAdminStatus() {
  const token = localStorage.getItem('token');
  if (!token) return;
  
  try {
    const payload = JSON.parse(atob(token.split('.')[1]));
    isAdmin = payload.isAdmin === true;
    if (isAdmin) {
      createAdminPanel();
      loadAdminStats();
    }
  } catch (e) {
    console.error('Error decoding token:', e);
  }
}

// Create admin panel UI
function createAdminPanel() {
  const headerDiv = document.querySelector('header > div');
  if (!headerDiv) return;
  
  // Add admin badge
  const adminBadge = document.createElement('span');
  adminBadge.style.cssText = 'background: #ff6b6b; color: white; padding: 4px 12px; border-radius: 20px; font-weight: 600; font-size: 12px; margin-left: 10px;';
  adminBadge.textContent = '⭐ ADMIN';
  userDisplayNameEl.appendChild(adminBadge);
  
  // Create admin panel button
  const adminBtn = document.createElement('button');
  adminBtn.id = 'adminPanelBtn';
  adminBtn.textContent = '⚙️ Admin Panel';
  adminBtn.style.cssText = 'background: #ff6b6b; color: white; margin-left: 10px; padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-weight: 600;';
  
  adminBtn.addEventListener('click', toggleAdminPanel);
  userDisplayNameEl.parentElement.appendChild(adminBtn);
}

// Toggle admin panel
function toggleAdminPanel() {
  if (!adminPanelEl) {
    adminPanelEl = document.createElement('div');
    adminPanelEl.id = 'adminPanel';
    adminPanelEl.style.cssText = `
      position: fixed;
      top: 100px;
      right: 20px;
      width: 350px;
      background: white;
      border: 2px solid #ff6b6b;
      border-radius: 8px;
      padding: 20px;
      box-shadow: 0 10px 40px rgba(0,0,0,0.3);
      z-index: 1000;
      max-height: 500px;
      overflow-y: auto;
      font-family: Arial, sans-serif;
    `;
    
    adminPanelEl.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px;">
        <h3 style="margin: 0; color: #ff6b6b;">⚙️ Admin Panel</h3>
        <button id="closeAdminPanel" style="background: none; border: none; font-size: 20px; cursor: pointer;">✕</button>
      </div>
      <div style="border-top: 2px solid #eee; padding-top: 12px;">
        <div style="margin-bottom: 16px;">
          <strong>📊 Statistics</strong>
          <div id="adminStats" style="font-size: 13px; line-height: 1.8; color: #666; margin-top: 8px;">
            <p>Loading...</p>
          </div>
        </div>
        <div style="border-top: 1px solid #eee; padding-top: 12px;">
          <strong>🎤 Broadcast</strong>
          <div style="margin-top: 8px;">
            <input id="announcementInput" type="text" placeholder="Type announcement..." style="width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 8px;">
            <button id="broadcastBtn" style="width: 100%; background: #ff6b6b; color: white; padding: 8px; border: none; border-radius: 4px; cursor: pointer; font-weight: 600;">Send Announcement</button>
          </div>
        </div>
        <div style="border-top: 1px solid #eee; padding-top: 12px; margin-top: 12px;">
          <strong>� All Messages</strong>
          <div style="margin-top: 8px;">
            <button id="viewMessagesBtn" style="width: 100%; background: #667eea; color: white; padding: 8px; border: none; border-radius: 4px; cursor: pointer; margin-bottom: 8px;">View All Messages (Last 50)</button>
            <div id="messagesView" style="display: none; max-height: 300px; overflow-y: auto; background: #f9f9f9; border: 1px solid #ddd; border-radius: 4px; padding: 8px; font-size: 12px; line-height: 1.6;"></div>
          </div>
        </div>
        <div style="border-top: 1px solid #eee; padding-top: 12px; margin-top: 12px;">
          <strong>�🗑️ Dangerous Actions</strong>
          <div style="margin-top: 8px;">
            <button id="clearAllMsgsBtn" style="width: 100%; background: #ff9999; color: white; padding: 8px; border: none; border-radius: 4px; cursor: pointer; margin-bottom: 8px;">Clear ALL Messages</button>
            <button id="clearRoomMsgsBtn" style="width: 100%; background: #ff9999; color: white; padding: 8px; border: none; border-radius: 4px; cursor: pointer;">Clear Room Messages</button>
          </div>
        </div>
      </div>
    `;
    
    document.body.appendChild(adminPanelEl);
    
    // Event listeners
    document.getElementById('closeAdminPanel').addEventListener('click', () => {
      adminPanelEl.style.display = 'none';
    });
    
    document.getElementById('broadcastBtn').addEventListener('click', () => {
      const msg = document.getElementById('announcementInput').value.trim();
      if (!msg) return alert('Enter message');
      socket.emit('admin announce', msg, (res) => {
        if (res && res.ok) {
          document.getElementById('announcementInput').value = '';
          alert('✅ Announcement sent!');
        }
      });
    });
    
    document.getElementById('viewMessagesBtn').addEventListener('click', () => {
      const token = localStorage.getItem('token');
      const messagesView = document.getElementById('messagesView');
      
      if (messagesView.style.display === 'none') {
        messagesView.style.display = 'block';
        messagesView.innerHTML = '<p style="color: #999;">Loading...</p>';
        
        fetch('/admin/messages?limit=50&offset=0', {
          headers: { 'Authorization': `Bearer ${token}` }
        })
          .then(r => r.json())
          .then(data => {
            if (data.messages && data.messages.length > 0) {
              const html = data.messages.map(msg => {
                const type = msg.to_user ? '🔒 Private' : msg.room ? '📢 Room' : '💬 Global';
                const room = msg.room ? `<strong style="color: #667eea;">${msg.room}</strong>` : '<em>__all__</em>';
                const target = msg.to_user ? `→ <strong>${msg.to_user}</strong>` : '';
                return `<div style="border-bottom: 1px solid #e0e0e0; padding-bottom: 6px; margin-bottom: 6px;">
                  <strong>${msg.from_user}</strong> ${target} [${type}] ${room}<br>
                  <em style="color: #999;">${new Date(msg.ts).toLocaleString()}</em><br>
                  <span style="color: #333;">"${msg.msg}"</span>
                </div>`;
              }).join('');
              messagesView.innerHTML = html;
            } else {
              messagesView.innerHTML = '<p style="color: #999;">No messages found</p>';
            }
          })
          .catch(err => {
            messagesView.innerHTML = '<p style="color: #d32f2f;">Error loading messages</p>';
          });
      } else {
        messagesView.style.display = 'none';
      }
    });
    
    document.getElementById('clearAllMsgsBtn').addEventListener('click', () => {
      if (confirm('⚠️ ARE YOU SURE? This will delete ALL messages!')) {
        fetch('/admin/messages', { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } })
          .then(r => r.json())
          .then(d => {
            alert(d.message || 'Done');
            appendMessage('Admin cleared all messages', 'system');
          });
      }
    });
    
    document.getElementById('clearRoomMsgsBtn').addEventListener('click', () => {
      const room = currentRoom || 'public';
      if (confirm(`Clear messages in "${room}"?`)) {
        fetch(`/admin/messages/${room}`, { method: 'DELETE', headers: { 'Authorization': `Bearer ${token}` } })
          .then(r => r.json())
          .then(d => {
            alert(d.message || 'Done');
            appendMessage(`Admin cleared messages in ${room}`, 'system');
          });
      }
    });
  }
  
  adminPanelEl.style.display = adminPanelEl.style.display === 'none' ? 'block' : 'none';
}

// Load admin statistics
function loadAdminStats() {
  const token = localStorage.getItem('token');
  fetch('/admin/stats', { headers: { 'Authorization': `Bearer ${token}` } })
    .then(r => r.json())
    .then(data => {
      const statsEl = document.getElementById('adminStats');
      if (statsEl) {
        statsEl.innerHTML = `
          <p>👥 Users: <strong>${data.totalUsers}</strong></p>
          <p>💬 Messages: <strong>${data.totalMessages}</strong></p>
          <p>🏠 Rooms: <strong>${data.totalRooms}</strong></p>
          <p>🟢 Online: <strong>${data.onlineUsers}</strong></p>
        `;
      }
    })
    .catch(console.error);
}

// Display logged-in user
const displayName = localStorage.getItem('displayName');
if (displayName) {
  userDisplayNameEl.textContent = `👤 ${displayName}`;
}

// Check admin status and create panel if admin
checkAdminStatus();

logoutBtn.addEventListener('click', () => {
  localStorage.removeItem('token');
  localStorage.removeItem('displayName');
  window.location.href = '/login.html';
});

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
  if (!name) return showToast('Enter a name', 'error');
  socket.emit('set username', name, (res) => {
    if (res && res.ok) {
      showToast(`Username set to ${name}`, 'success');
      appendMessage(`✓ Username set to ${name}`, 'system');
    } else {
      showToast(`Failed: ${res && res.error}`, 'error');
      appendMessage(`✗ Failed to set username: ${res && res.error}`, 'system');
    }
  });
});

// Status selector
const statusSelect = document.getElementById('statusSelect');
if (statusSelect) {
  statusSelect.addEventListener('change', (e) => {
    const status = e.target.value;
    socket.emit('set status', status, (res) => {
      if (res && res.ok) {
        showToast(`Status: ${status}`, 'success');
      }
    });
  });
}

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
  if (!msg) return showToast('Type a message first', 'error');
  if (msg.length > 500) return showToast('Message is too long (max 500 chars)', 'error');
  
  const to = toUserEl.value.trim();
  
  if (to) {
    // Private message
    socket.emit('chat message', { room: null, msg, to });
    showToast(`Message sent to ${to}`, 'success');
  } else if (currentMode === 'public') {
    // Public chat
    socket.emit('chat message', { room: 'public', msg, to: null });
  } else {
    // Group chat
    socket.emit('chat message', { room: currentRoom, msg, to: null });
  }
  messageEl.value = '';
  socket.emit('stop typing', { room: currentRoom, to });
  typingUsers.delete(socket.id);
  updateTypingDisplay();
});

// Typing indicator
messageEl.addEventListener('input', () => {
  const to = toUserEl.value.trim();
  socket.emit('typing', currentMode === 'public' ? { room: 'public' } : to ? { to } : { room: currentRoom });
  
  clearTimeout(typingTimeout);
  typingTimeout = setTimeout(() => {
    socket.emit('stop typing', currentMode === 'public' ? { room: 'public' } : to ? { to } : { room: currentRoom });
  }, 2000);
});

socket.on('system message', (txt) => appendMessage(txt, 'system'));
socket.on('chat message', (data) => {
  const label = data.room === 'public' ? '📢' : `🔒 ${data.room}`;
  appendMessage(`${data.from}: ${data.msg}`, 'msg', data.ts);
});
socket.on('private message', (data) => appendMessage(`(private) ${data.from}: ${data.msg}`, 'private', data.ts));

// Typing indicators
socket.on('user typing', (data) => {
  typingUsers.add(data.username || data.from);
  updateTypingDisplay();
});

socket.on('user stop typing', (data) => {
  typingUsers.delete(data.username);
  updateTypingDisplay();
});

// User status changes
socket.on('user status', (data) => {
  appendMessage(`${data.username} is now ${data.status}`, 'system');
});

// Typing display
function updateTypingDisplay() {
  const typingEl = document.getElementById('typingIndicator');
  if (typingUsers.size === 0) {
    if (typingEl) typingEl.remove();
  } else {
    if (!typingEl) {
      const div = document.createElement('div');
      div.id = 'typingIndicator';
      div.style.cssText = 'font-size: 12px; color: #999; padding: 4px 8px; font-style: italic;';
      messagesEl.parentElement.insertBefore(div, messagesEl);
    }
    const users = Array.from(typingUsers).slice(0, 2).join(', ');
    const more = typingUsers.size > 2 ? ` +${typingUsers.size - 2}` : '';
    document.getElementById('typingIndicator').textContent = `✍️ ${users}${more} is typing...`;
  }
}

socket.on('connect_error', (error) => {
  appendMessage(`⚠️ Connection error: ${error.message}`, 'system');
  showToast('Connection error - attempting to reconnect...', 'error');
  if (error.message === 'No token' || error.message === 'Invalid token') {
    localStorage.removeItem('token');
    window.location.href = '/login.html';
  }
});

socket.on('disconnect', () => {
  appendMessage('⚠️ Disconnected. Reconnecting...', 'system');
  showToast('Disconnected from server', 'error');
});

socket.on('reconnect', () => {
  appendMessage('✅ Reconnected to server', 'system');
  showToast('Reconnected successfully!', 'success');
});
