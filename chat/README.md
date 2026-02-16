# Fun Chat - Application

Modern real-time chat with JWT authentication, group messaging, and persistent storage.

## Quick Start

```bash
npm install
npm start
# Open http://localhost:3000
```

## Features Implemented

✅ **JWT Authentication** - Secure user accounts with bcrypt hashing  
✅ **Public Chat** - Real-time global messaging  
✅ **Group Rooms** - Create and manage private chat rooms  
✅ **Private Messages** - Direct user-to-user messaging  
✅ **Message History** - SQLite persistence with history loading  
✅ **Admin Management** - Admin promoted users with setup keys  

## Configuration

Edit environment variables for production deployment:

```bash
PORT                 # Server port (default: 3000)
JWT_SECRET          # Secret for JWT signing (CHANGE THIS IN PRODUCTION)
ADMIN_SETUP_KEY     # Key for admin setup (CHANGE THIS IN PRODUCTION)
```

## Scaling Considerations

For production with multiple processes:
- Use Redis adapter with Socket.io for message distribution
- Deploy to cloud database instead of local SQLite
- Enable HTTPS/TLS for secure connections
- Add rate limiting and input validation
- Implement proper error logging and monitoring
