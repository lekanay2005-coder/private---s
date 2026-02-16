#!/usr/bin/env node

/**
 * Admin Setup Script
 * Creates or promotes a user to admin status
 * Usage: node setup-admin.js <email> [displayName] [password]
 */

const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const args = process.argv.slice(2);
const email = args[0];
const displayName = args[1] || 'Admin User';
const password = args[2] || 'admin123456';

if (!email) {
  console.error('Usage: node setup-admin.js <email> [displayName] [password]');
  console.error('Example: node setup-admin.js lekanay2005@gmail.com "Lekan Ayomide"');
  process.exit(1);
}

const dbFile = path.join(__dirname, 'chat.db');
const db = new sqlite3.Database(dbFile, async (err) => {
  if (err) {
    console.error('Error opening database:', err);
    process.exit(1);
  }

  // Ensure table exists
  db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    created_at INTEGER
  )`, async (err) => {
    if (err) {
      console.error('Error creating table:', err);
      db.close();
      process.exit(1);
    }

    try {
      const hash = await bcrypt.hash(password, 10);
      
      db.run(
        'INSERT OR REPLACE INTO accounts(email, display_name, password_hash, is_admin, created_at) VALUES(?, ?, ?, 1, ?)',
        [email, displayName, hash, Date.now()],
        function(err) {
          if (err) {
            console.error('Error setting up admin account:', err);
            db.close();
            process.exit(1);
          }

          console.log('✅ Admin account created/updated successfully!');
          console.log(`   Email: ${email}`);
          console.log(`   Display Name: ${displayName}`);
          console.log(`   Password: ${password}`);
          console.log(`   Is Admin: Yes`);
          console.log(`   ID: ${this.lastID}`);
          
          db.close(() => {
            console.log('\n✨ Setup complete! You can now login with these credentials.');
          });
        }
      );
    } catch (e) {
      console.error('Error hashing password:', e);
      db.close();
      process.exit(1);
    }
  });
});
