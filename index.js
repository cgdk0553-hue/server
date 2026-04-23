const express = require('express');
const cors = require('cors');
const Database = require('better-sqlite3');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());

// =============================
// データベース設定
// =============================
const db = new Database('users.db');

// 既存のテーブル（名前・年齢）
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    age INTEGER
  )
`);

// 🆕 ログイン用テーブルを追加
db.exec(`
  CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )
`);

// =============================
// 秘密鍵（JWT用）
// =============================
const SECRET_KEY = 'my-secret-key-123';

// =============================
// ミドルウェア（トークン確認）
// =============================
function authenticate(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'トークンがありません' });

  try {
    req.user = jwt.verify(token, SECRET_KEY); // トークンを検証
    next(); // 問題なければ次へ進む
  } catch {
    res.status(403).json({ error: 'トークンが無効です' });
  }
}

// =============================
// 既存のルート（変更なし）
// =============================
app.get('/users', (req, res) => {
  const users = db.prepare('SELECT * FROM users').all();
  res.json(users);
});

app.post('/users', (req, res) => {
  const { name, age } = req.body;
  db.prepare('INSERT INTO users (name, age) VALUES (?, ?)').run(name, age);
  res.json({ message: '追加しました！' });
});

// =============================
// 🆕 新規登録
// =============================
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'ユーザー名とパスワードを入力してください' });
  }

  const hashed = bcrypt.hashSync(password, 10); // パスワードを暗号化

  try {
    db.prepare('INSERT INTO accounts (username, password) VALUES (?, ?)').run(username, hashed);
    res.json({ message: '登録成功！' });
  } catch {
    res.status(400).json({ error: 'そのユーザー名はすでに使われています' });
  }
});

// =============================
// 🆕 ログイン
// =============================
app.post('/login', (req, res) => {
  const { username, password } = req.body;

  const account = db.prepare('SELECT * FROM accounts WHERE username = ?').get(username);
  if (!account) {
    return res.status(401).json({ error: 'ユーザー名またはパスワードが違います' });
  }

  const isMatch = bcrypt.compareSync(password, account.password); // パスワード照合
  if (!isMatch) {
    return res.status(401).json({ error: 'ユーザー名またはパスワードが違います' });
  }

  // トークン発行
  const token = jwt.sign({ userId: account.id, username: account.username }, SECRET_KEY, { expiresIn: '24h' });
  res.json({ message: 'ログイン成功！', token });
});

// =============================
// 🆕 認証が必要なルートの例
// =============================
app.get('/private', authenticate, (req, res) => {
  res.json({ message: `${req.user.username}さん、ログイン済みです！` });
});

// =============================
// サーバー起動
// =============================
app.listen(3001, () => {
  console.log('サーバー起動中：http://localhost:3001');
});