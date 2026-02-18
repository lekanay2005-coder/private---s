document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements
  const appLoading = document.getElementById('app-loading');
  const mainContent = document.getElementById('main-content');
  const userDisplayName = document.getElementById('userDisplayName');
  const logoutBtn = document.getElementById('logoutBtn');
  const roomsList = document.getElementById('rooms');
  const usersList = document.getElementById('users');
  const messages = document.getElementById('messages');
  const messageForm = document.getElementById('message-form');
  const messageInput = document.getElementById('message-input');
  const newRoomNameInput = document.getElementById('new-room-name');
  const createRoomBtn = document.getElementById('create-room-btn');
  const typingIndicator = document.getElementById('typing-indicator');
  const chatTitle = document.getElementById('chat-title');
  const themeToggle = document.getElementById('theme-toggle');
  const wallpaperUrlInput = document.getElementById('wallpaper-url');
  const setWallpaperBtn = document.getElementById('set-wallpaper-btn');
  const wallpaperContainer = document.getElementById('wallpaper-container');
  const dmModal = document.getElementById('dm-modal');
  const dmRecipient = document.getElementById('dm-recipient');
  const dmInput = document.getElementById('dm-input');
  const dmForm = document.getElementById('dm-form');
  const dmCloseBtn = dmModal.querySelector('.close-btn');

  // State
  let currentRoom = null;
  let currentUser = null;
  let currentUserId = null;
  let socket;
  let currentDmRecipient = null;

  // Check for auth token
  const token = localStorage.getItem('fun-chat-token');
  if (!token) {
    window.location.href = '/login.html';
    return;
  }

  // Initialize Socket.io
  socket = io({ auth: { token } });

  // ============ SOCKET.IO EVENT HANDLERS ==============

  socket.on('connect', () => {
    console.log('Connected to server');
    appLoading.style.display = 'none';
    document.getElementById('app').style.display = 'flex';
    currentUser = localStorage.getItem('fun-chat-displayName');
    currentUserId = parseInt(localStorage.getItem('fun-chat-userId'));
    userDisplayName.textContent = currentUser;
    socket.emit('set username', currentUser);
    fetchAllUsers();
    applyWallpaper();
    joinRoom('general');
  });

  socket.on('disconnect', () => {
    showSystemMessage('Disconnected from server. Reconnecting...');
  });

  socket.on('connect_error', (err) => {
    if (err.message === 'Invalid token') {
        localStorage.clear();
        window.location.href = '/login.html';
    }
  });

  socket.on('chat message', (data) => {
    if (data.room === currentRoom) {
      addMessage(data.from, data.msg, false, data.ts);
    }
  });
  
  socket.on('private message', (data) => {
    const isOwn = data.from === currentUser;
    if ((isOwn && data.to === currentDmRecipient?.displayName) || (!isOwn && data.from === currentDmRecipient?.displayName)) {
        addDmMessage(data.from, data.msg, isOwn, data.ts);
    } else {
        showSystemMessage(`You have a new private message from ${data.from}`);
    }
  });

  socket.on('system message', (msg) => {
    showSystemMessage(msg);
  });

  socket.on('user status', (data) => {
    updateUserStatus(data.userId, data.status);
  });

  socket.on('typing', (data) => {
      if(data.room === currentRoom && data.user !== currentUser) {
          typingIndicator.textContent = `${data.user} is typing...`;
          setTimeout(() => {
              typingIndicator.textContent = '';
          }, 3000);
      }
  });

  // ============ UI & EVENT LISTENERS ==============

  logoutBtn.addEventListener('click', () => {
    localStorage.clear();
    socket.disconnect();
    window.location.href = '/login.html';
  });

  messageForm.addEventListener('submit', (e) => {
    e.preventDefault();
    const msg = messageInput.value.trim();
    if (msg && currentRoom) {
      socket.emit('chat message', { room: currentRoom, msg });
      addMessage(currentUser, msg, true, Date.now());
      messageInput.value = '';
    }
  });

    messageInput.addEventListener('input', () => {
        if (currentRoom) {
            socket.emit('typing', { room: currentRoom, user: currentUser });
        }
    });

  createRoomBtn.addEventListener('click', () => {
    const newRoomName = newRoomNameInput.value.trim();
    if (newRoomName) {
      joinRoom(newRoomName);
      newRoomNameInput.value = '';
    }
  });

  dmCloseBtn.addEventListener('click', () => {
      dmModal.style.display = 'none';
      currentDmRecipient = null;
  });

  dmForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const msg = dmInput.value.trim();
      if (msg && currentDmRecipient?.id) {
          socket.emit('chat message', { to: currentDmRecipient.id, msg });
          addDmMessage(currentUser, msg, true, Date.now());
          dmInput.value = '';
      }
  });

  setWallpaperBtn.addEventListener('click', () => {
      const url = wallpaperUrlInput.value.trim();
      if (url) {
          localStorage.setItem('fun-chat-wallpaper', url);
          applyWallpaper();
          wallpaperUrlInput.value = '';
      }
  });
  
  themeToggle.addEventListener('click', () => {
      document.body.classList.toggle('dark-theme');
      localStorage.setItem('fun-chat-theme', document.body.classList.contains('dark-theme') ? 'dark' : 'light');
  });

  // ============ HELPER FUNCTIONS ==============

  function applyWallpaper() {
      const savedWallpaper = localStorage.getItem('fun-chat-wallpaper');
      if (savedWallpaper) {
          wallpaperContainer.style.backgroundImage = `url(${savedWallpaper})`;
      }
  }

  function applyTheme() {
      const savedTheme = localStorage.getItem('fun-chat-theme');
      if (savedTheme === 'dark') {
          document.body.classList.add('dark-theme');
      }
  }

  async function fetchAllUsers() {
    try {
        const res = await fetch('/users', { headers: { 'Authorization': `Bearer ${token}` } });
        if (!res.ok) throw new Error('Failed to fetch users');
        const users = await res.json();
        renderUsers(users);
    } catch (err) {
        console.error(err);
    }
  }

  function renderUsers(users) {
    usersList.innerHTML = '';
    users.forEach(user => {
        const li = document.createElement('li');
        li.dataset.userId = user.id;
        li.dataset.username = user.displayName;
        li.innerHTML = `
            <span class="status-circle ${user.isOnline ? 'status-online' : 'status-offline'}"></span>
            ${user.displayName} <span class="user-id">#${user.id}</span>
        `;
        if(user.id !== currentUserId) {
            li.addEventListener('click', () => openDm(user.id, user.displayName));
        }
        usersList.appendChild(li);
    });
  }

  async function openDm(userId, displayName) {
      currentDmRecipient = { id: userId, displayName };
      dmRecipient.textContent = `Chat with ${displayName}`;
      dmModal.style.display = 'flex';
      document.getElementById('dm-messages').innerHTML = ''; 

      try {
        const res = await fetch(`/history/private/${userId}`, { headers: { 'Authorization': `Bearer ${token}` } });
        const history = await res.json();
        history.forEach(item => addDmMessage(item.from_user, item.msg, item.from_user === currentUser, item.ts));
      } catch (err) {
          console.error('Failed to fetch DM history:', err);
      }
  }

  function updateUserStatus(userId, status) {
    const userEl = usersList.querySelector(`[data-user-id="${userId}"] .status-circle`);
    if (userEl) {
        userEl.className = `status-circle status-${status === 'online' ? 'online' : 'offline'}`;
    }
  }

  function joinRoom(roomName) {
    if (currentRoom) {
      socket.emit('leave room', currentRoom);
      const oldRoomEl = roomsList.querySelector(`[data-room="${currentRoom}"]`);
      if(oldRoomEl) oldRoomEl.classList.remove('active');
    }

    socket.emit('create or join', roomName, (ack) => {
      if (ack.ok) {
        currentRoom = roomName;
        messages.innerHTML = '';
        chatTitle.textContent = `# ${roomName}`;
        showSystemMessage(`Joined room: ${roomName}`);
        
        let roomEl = roomsList.querySelector(`[data-room="${roomName}"]`);
        if (!roomEl) {
            roomEl = document.createElement('li');
            roomEl.dataset.room = roomName;
            roomEl.textContent = `# ${roomName}`;
            roomEl.addEventListener('click', () => joinRoom(roomName));
            roomsList.appendChild(roomEl);
        }
        roomEl.classList.add('active');
        fetchHistory(roomName);
      }
    });
  }

  async function fetchHistory(room) {
      try {
          const res = await fetch(`/history/${room}`);
          const history = await res.json();
          history.forEach(item => addMessage(item.from_user, item.msg, item.from_user === currentUser, item.ts));
      } catch (err) {
          console.error('Failed to fetch history:', err);
      }
  }

  function addMessage(from, text, isOwn, timestamp) {
    const messageEl = document.createElement('div');
    messageEl.classList.add('message', isOwn ? 'own' : 'other');
    const ts = new Date(timestamp).toLocaleTimeString();
    messageEl.innerHTML = `
      <div class="meta"><span class="author">${from}</span><span class="timestamp">${ts}</span></div>
      <div class="text">${text}</div>
    `;
    messages.appendChild(messageEl);
    messages.scrollTop = messages.scrollHeight;
  }

  function addDmMessage(from, text, isOwn, timestamp) {
    const messagesContainer = document.getElementById('dm-messages');
    const messageEl = document.createElement('div');
    const ts = new Date(timestamp).toLocaleTimeString();
    messageEl.classList.add('message', isOwn ? 'own' : 'other');
    messageEl.innerHTML = `
      <div class="meta"><span class="author">${from}</span><span class="timestamp">${ts}</span></div>
      <div class="text">${text}</div>
    `;
    messagesContainer.appendChild(messageEl);
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  function showSystemMessage(msg) {
    const messageEl = document.createElement('div');
    messageEl.classList.add('system-message');
    messageEl.textContent = msg;
    messages.appendChild(messageEl);
    messages.scrollTop = messages.scrollHeight;
  }

  // Initial setup
  applyTheme();
  
});