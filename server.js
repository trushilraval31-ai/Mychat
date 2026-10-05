const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
require("dotenv").config();

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || "CHANGE_THIS_TO_A_LONG_RANDOM_SECRET";

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

const DATA_DIR = path.join(__dirname, "data");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const MESSAGES_FILE = path.join(DATA_DIR, "messages.json");

if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, "[]");
}

if (!fs.existsSync(MESSAGES_FILE)) {
  fs.writeFileSync(MESSAGES_FILE, "[]");
}

function readJSON(file) {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8"));
  } catch {
    return [];
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

function createToken(user) {
  return jwt.sign(
    {
      id: user.id,
      username: user.username
    },
    JWT_SECRET,
    {
      expiresIn: "30d"
    }
  );
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization;

  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({
      success: false,
      message: "Authentication required"
    });
  }

  const token = header.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({
      success: false,
      message: "Invalid or expired token"
    });
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    displayName: user.displayName,
    avatar: user.avatar || null,
    about: user.about || "",
    online: user.online || false,
    lastSeen: user.lastSeen || null
  };
}

/* =========================
   BASIC ROUTES
========================= */

app.get("/", (req, res) => {
  res.json({
    success: true,
    app: "MyChat",
    message: "MyChat server is running",
    version: "1.0.0"
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    time: new Date().toISOString()
  });
});

/* =========================
   REGISTER
========================= */

app.post("/api/register", async (req, res) => {
  try {
    const { username, password, displayName } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    if (username.length < 3) {
      return res.status(400).json({
        success: false,
        message: "Username must contain at least 3 characters"
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must contain at least 6 characters"
      });
    }

    const users = readJSON(USERS_FILE);

    const normalizedUsername = username.toLowerCase().trim();

    const existingUser = users.find(
      (user) => user.username === normalizedUsername
    );

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "Username already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    const user = {
      id: Date.now().toString(),
      username: normalizedUsername,
      password: hashedPassword,
      displayName:
        displayName && displayName.trim()
          ? displayName.trim()
          : username.trim(),
      avatar: null,
      about: "Hey there! I am using MyChat.",
      online: false,
      lastSeen: new Date().toISOString(),
      createdAt: new Date().toISOString()
    };

    users.push(user);
    writeJSON(USERS_FILE, users);

    const token = createToken(user);

    res.status(201).json({
      success: true,
      message: "Account created",
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("REGISTER ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

/* =========================
   LOGIN
========================= */

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        success: false,
        message: "Username and password are required"
      });
    }

    const users = readJSON(USERS_FILE);

    const normalizedUsername = username.toLowerCase().trim();

    const user = users.find(
      (u) => u.username === normalizedUsername
    );

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    const passwordCorrect = await bcrypt.compare(
      password,
      user.password
    );

    if (!passwordCorrect) {
      return res.status(401).json({
        success: false,
        message: "Invalid username or password"
      });
    }

    user.online = true;
    user.lastSeen = new Date().toISOString();

    writeJSON(USERS_FILE, users);

    const token = createToken(user);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: publicUser(user)
    });
  } catch (error) {
    console.error("LOGIN ERROR:", error);

    res.status(500).json({
      success: false,
      message: "Server error"
    });
  }
});

/* =========================
   CURRENT USER
========================= */

app.get("/api/me", authMiddleware, (req, res) => {
  const users = readJSON(USERS_FILE);

  const user = users.find((u) => u.id === req.user.id);

  if (!user) {
    return res.status(404).json({
      success: false,
      message: "User not found"
    });
  }

  res.json({
    success: true,
    user: publicUser(user)
  });
});

/* =========================
   USER SEARCH
========================= */

app.get("/api/users", authMiddleware, (req, res) => {
  const users = readJSON(USERS_FILE);

  const search = (req.query.search || "").toLowerCase().trim();

  let result = users.filter(
    (user) => user.id !== req.user.id
  );

  if (search) {
    result = result.filter(
      (user) =>
        user.username.includes(search) ||
        user.displayName.toLowerCase().includes(search)
    );
  }

  result = result.slice(0, 50);

  res.json({
    success: true,
    users: result.map(publicUser)
  });
});

/* =========================
   GET CHAT HISTORY
========================= */

app.get(
  "/api/messages/:userId",
  authMiddleware,
  (req, res) => {
    const messages = readJSON(MESSAGES_FILE);

    const myId = req.user.id;
    const otherId = req.params.userId;

    const conversation = messages.filter(
      (message) =>
        (message.senderId === myId &&
          message.receiverId === otherId) ||
        (message.senderId === otherId &&
          message.receiverId === myId)
    );

    res.json({
      success: true,
      messages: conversation
    });
  }
);

/* =========================
   SOCKET AUTH
========================= */

io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;

    if (!token) {
      return next(
        new Error("Authentication token required")
      );
    }

    const decoded = jwt.verify(token, JWT_SECRET);

    socket.user = decoded;

    next();
  } catch {
    next(new Error("Invalid authentication token"));
  }
});

/* =========================
   ONLINE USERS
========================= */

function setUserOnline(userId, online) {
  const users = readJSON(USERS_FILE);

  const user = users.find((u) => u.id === userId);

  if (!user) return;

  user.online = online;
  user.lastSeen = new Date().toISOString();

  writeJSON(USERS_FILE, users);
}

function getOnlineUsers() {
  const users = readJSON(USERS_FILE);

  return users
    .filter((user) => user.online)
    .map(publicUser);
}

/* =========================
   SOCKET CONNECTION
========================= */

io.on("connection", (socket) => {
  const userId = socket.user.id;

  console.log(
    `CONNECTED: ${socket.user.username} (${socket.id})`
  );

  socket.join(`user:${userId}`);

  setUserOnline(userId, true);

  io.emit("users:online", getOnlineUsers());

  socket.emit("connection:success", {
    success: true,
    userId
  });

  /* =========================
     SEND MESSAGE
  ========================= */

  socket.on("message:send", (data, callback) => {
    try {
      const { receiverId, text } = data || {};

      if (!receiverId || !text || !text.trim()) {
        if (callback) {
          callback({
            success: false,
            message: "Receiver and message are required"
          });
        }

        return;
      }

      const messages = readJSON(MESSAGES_FILE);

      const message = {
        id:
          Date.now().toString() +
          "-" +
          Math.random().toString(36).slice(2, 8),

        senderId: userId,

        receiverId,

        text: text.trim(),

        type: "text",

        createdAt: new Date().toISOString()
      };

      messages.push(message);

      writeJSON(MESSAGES_FILE, messages);

      io.to(`user:${receiverId}`).emit(
        "message:new",
        message
      );

      socket.emit("message:new", message);

      if (callback) {
        callback({
          success: true,
          message
        });
      }
    } catch (error) {
      console.error("MESSAGE ERROR:", error);

      if (callback) {
        callback({
          success: false,
          message: "Message could not be sent"
        });
      }
    }
  });

  /* =========================
     TYPING
  ========================= */

  socket.on("typing:start", ({ receiverId }) => {
    if (!receiverId) return;

    io.to(`user:${receiverId}`).emit("typing:start", {
      userId
    });
  });

  socket.on("typing:stop", ({ receiverId }) => {
    if (!receiverId) return;

    io.to(`user:${receiverId}`).emit("typing:stop", {
      userId
    });
  });

  /* =========================
     READ MESSAGE
  ========================= */

  socket.on("message:read", ({ messageId }) => {
    if (!messageId) return;

    const messages = readJSON(MESSAGES_FILE);

    const message = messages.find(
      (m) => m.id === messageId
    );

    if (!message) return;

    if (message.receiverId !== userId) return;

    message.read = true;
    message.readAt = new Date().toISOString();

    writeJSON(MESSAGES_FILE, messages);

    io.to(`user:${message.senderId}`).emit(
      "message:read",
      {
        messageId,
        readAt: message.readAt
      }
    );
  });

  /* =========================
     VOICE / VIDEO CALL SIGNALING
  ========================= */

  socket.on("call:offer", ({ receiverId, offer, callType }) => {
    if (!receiverId || !offer) return;

    io.to(`user:${receiverId}`).emit("call:incoming", {
      callerId: userId,
      callerUsername: socket.user.username,
      offer,
      callType: callType || "voice"
    });
  });

  socket.on("call:answer", ({ callerId, answer }) => {
    if (!callerId || !answer) return;

    io.to(`user:${callerId}`).emit("call:answered", {
      answer,
      receiverId: userId
    });
  });

  socket.on("call:ice", ({ receiverId, candidate }) => {
    if (!receiverId || !candidate) return;

    io.to(`user:${receiverId}`).emit("call:ice", {
      senderId: userId,
      candidate
    });
  });

  socket.on("call:end", ({ receiverId }) => {
    if (!receiverId) return;

    io.to(`user:${receiverId}`).emit("call:ended", {
      userId
    });
  });

  socket.on("call:reject", ({ callerId }) => {
    if (!callerId) return;

    io.to(`user:${callerId}`).emit("call:rejected", {
      userId
    });
  });

  /* =========================
     DISCONNECT
  ========================= */

  socket.on("disconnect", () => {
    console.log(
      `DISCONNECTED: ${socket.user.username} (${socket.id})`
    );

    setUserOnline(userId, false);

    io.emit("users:online", getOnlineUsers());
  });
});

/* =========================
   ERROR HANDLING
========================= */

app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: "Route not found"
  });
});

/* =========================
   START SERVER
========================= */

server.listen(PORT, "0.0.0.0", () => {
  console.log("");
  console.log("================================");
  console.log("        MYCHAT SERVER");
  console.log("================================");
  console.log(`Server running on port ${PORT}`);
  console.log(`Local: http://localhost:${PORT}`);
  console.log("");
});
