const cors = require("cors");
require("dotenv").config();

const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const express = require("express");
const fs = require("fs");
const JWT_SECRET = process.env.JWT_SECRET;
const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

const file = "users.json";

// users.json না থাকলে তৈরি করবে
if (!fs.existsSync(file)) {
  fs.writeFileSync(file, "[]");
}

// সব User দেখাবে
app.get("/users", (req, res) => {
const users = JSON.parse(fs.readFileSync(file, "utf8"));

  res.json({
    success: true,
    users: users
  });
});

// নতুন User Save করবে
app.post("/users", (req, res) => {
  const { name, age } = req.body;

  if (!name || !age) {
    return res.status(400).json({
      success: false,
      message: "Name and age are required"
    });
  }

  const users = JSON.parse(fs.readFileSync(file, "utf8"));

  const newUser = {
    id: users.length + 1,
    name: name,
    age: age
  };

  users.push(newUser);

  fs.writeFileSync(
    file,
    JSON.stringify(users, null, 2)
  );

  res.json({
    success: true,
    message: "User saved successfully",
    user: newUser
  });
});

// User Update
app.put("/users/:id", (req, res) => {
  const id = Number(req.params.id);
  const { name, age } = req.body;

  const users = JSON.parse(fs.readFileSync(file, "utf8"));

  const userIndex = users.findIndex(user => user.id === id);

  if (userIndex === -1) {
    return res.status(404).json({
      success: false,
      message: "User not found"
    });
  }

  users[userIndex].name = name;
  users[userIndex].age = age;

  fs.writeFileSync(
    file,
    JSON.stringify(users, null, 2)
  );

  res.json({
    success: true,
    message: "User updated successfully",
    user: users[userIndex]
  });
});

// User Delete
app.delete("/users/:id", (req, res) => {
  const id = Number(req.params.id);

  const users = JSON.parse(fs.readFileSync(file, "utf8"));

  const userIndex = users.findIndex(user => user.id === id);

  if (userIndex === -1) {
    return res.status(404).json({
      success: false,
      message: "User not found"
    });
  }

  const deletedUser = users.splice(userIndex, 1)[0];

  fs.writeFileSync(
    file,
    JSON.stringify(users, null, 2)
  );

  res.json({
    success: true,
    message: "User deleted successfully",
    user: deletedUser
  });
});

// Register API
// Secure Register API
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required"
    });
  }

  const users = JSON.parse(fs.readFileSync(file, "utf8"));

  const existingUser = users.find(
    user => user.username === username
  );

  if (existingUser) {
    return res.status(409).json({
      success: false,
      message: "Username already exists"
    });
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const newUser = {
    id: users.length + 1,
    username: username,
    password: hashedPassword,
    role: "user"
  };

  users.push(newUser);

  fs.writeFileSync(
    file,
    JSON.stringify(users, null, 2)
  );

  res.json({
    success: true,
    message: "Registration successful",
    user: {
      id: newUser.id,
      username: newUser.username,
    }
  });
});

// Secure Login API with JWT
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({
      success: false,
      message: "Username and password are required"
    });
  }

  const users = JSON.parse(fs.readFileSync(file, "utf8"));

  const user = users.find(
    user => user.username === username
  );

  if (!user) {
    return res.status(401).json({
      success: false,
      message: "Invalid username or password"
    });
  }

  const passwordMatch = await bcrypt.compare(
    password,
    user.password
  );

  if (!passwordMatch) {
    return res.status(401).json({
      success: false,
      message: "Invalid username or password"
    });
  }

  const token = jwt.sign(
    {
      id: user.id,
      username: user.username,
      role: user.role || "user"
    },
    JWT_SECRET,
    {
      expiresIn: "1h"
    }
  );

  res.json({
    success: true,
    message: "Login successful",
    token: token,
    user: {
      id: user.id,
      username: user.username,
      role: user.role || "user"
    }
  });
});
// JWT Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "Access token required"
    });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({
        success: false,
        message: "Invalid or expired token"
      });
    }

    req.user = user;
    next();
  });
}

// Protected Profile API
app.get("/profile", authenticateToken, (req, res) => {
  res.json({
    success: true,
    message: "Welcome to your profile",
    user: req.user
  });
});

// Protected: সব User দেখা
app.get("/admin/users", authenticateToken,requireAdmin, (req, res) => {
  const users = JSON.parse(fs.readFileSync(file, "utf8"));

  const safeUsers = users.map(user => ({
    id: user.id,
    username: user.username
  }));

  res.json({
    success: true,
    users: safeUsers
  });
});
function requireAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      success: false,
      message: "Admin access required"
    });
  }

  next();
} 
// Server চালু
app.listen(process.env.PORT || 3000, () => {
  console.log("API running");
});

