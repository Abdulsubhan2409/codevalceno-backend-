const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();

app.use(cors({
  origin: ["http://localhost:5173", "http://localhost:3000", "http://localhost:8080"],
  credentials: true,
}));
app.use(express.json());

// ─── DB Pool ─────────────────────────────────────────────────────────────────
const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || "3306"),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

// ─── Nodemailer Transporter ───────────────────────────────────────────────────
const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// ─── Auth Middleware ──────────────────────────────────────────────────────────
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || "secret");
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
};

// ─── SETUP: Create tables + seed admin ───────────────────────────────────────
async function setupDatabase() {
  const conn = await db.getConnection();
  try {
    await conn.query(`
      CREATE TABLE IF NOT EXISTS admins (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS projects (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(200) NOT NULL,
        type VARCHAR(50),
        country VARCHAR(100),
        status VARCHAR(50) DEFAULT 'In Progress',
        tech JSON,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS contact_submissions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        full_name VARCHAR(120) NOT NULL,
        email VARCHAR(255) NOT NULL,
        company VARCHAR(120),
        phone VARCHAR(40),
        project_type VARCHAR(100),
        budget_range VARCHAR(50),
        message TEXT,
        status VARCHAR(20) DEFAULT 'unread',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS team_members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(120) NOT NULL,
        role VARCHAR(100),
        email VARCHAR(255),
        status VARCHAR(20) DEFAULT 'Active',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS blog_posts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        content TEXT,
        status VARCHAR(20) DEFAULT 'Draft',
        views INT DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    await conn.query(`
      CREATE TABLE IF NOT EXISTS pages (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        content TEXT,
        status VARCHAR(20) DEFAULT 'Published',
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      )
    `);

    // Seed default admin if not exists
    const [rows] = await conn.query("SELECT id FROM admins WHERE email = ?", [
      "admin@codevalceno.com",
    ]);
    if (rows.length === 0) {
      const hash = await bcrypt.hash("admin123", 10);
      await conn.query("INSERT INTO admins (email, password_hash) VALUES (?, ?)", [
        "admin@codevalceno.com",
        hash,
      ]);
      console.log("✅ Default admin created: admin@codevalceno.com / admin123");
    }

    console.log("✅ Database tables ready");
  } finally {
    conn.release();
  }
}

// ════════════════════════════════════════════════════════════════════════════
// AUTH ROUTES
// ════════════════════════════════════════════════════════════════════════════

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password)
    return res.status(400).json({ error: "Email and password required" });

  try {
    const [rows] = await db.query("SELECT * FROM admins WHERE email = ?", [email]);
    if (rows.length === 0)
      return res.status(401).json({ error: "Invalid credentials" });

    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });

    const token = jwt.sign(
      { id: rows[0].id, email: rows[0].email },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "1h" }
    );

    res.json({ token, email: rows[0].email });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// PROJECTS ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/projects
app.get("/api/projects", auth, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM projects ORDER BY created_at DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/projects
app.post("/api/projects", auth, async (req, res) => {
  const { title, type, country, status, tech } = req.body;
  try {
    const [result] = await db.query(
      "INSERT INTO projects (title, type, country, status, tech) VALUES (?, ?, ?, ?, ?)",
      [title, type, country, status || "In Progress", JSON.stringify(tech || [])]
    );
    res.status(201).json({ id: result.insertId, message: "Project created" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/projects/:id
app.put("/api/projects/:id", auth, async (req, res) => {
  const { title, type, country, status, tech } = req.body;
  try {
    await db.query(
      "UPDATE projects SET title=?, type=?, country=?, status=?, tech=? WHERE id=?",
      [title, type, country, status, JSON.stringify(tech || []), req.params.id]
    );
    res.json({ message: "Project updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/projects/:id
app.delete("/api/projects/:id", auth, async (req, res) => {
  try {
    await db.query("DELETE FROM projects WHERE id=?", [req.params.id]);
    res.json({ message: "Project deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// MESSAGES ROUTES
// ════════════════════════════════════════════════════════════════════════════

// ✅ PUBLIC — Contact form submission (no auth needed)
app.post("/api/messages", async (req, res) => {
  const { full_name, email, company, phone, project_type, budget_range, message } = req.body;
  if (!full_name || !email)
    return res.status(400).json({ error: "Name and email are required" });
  try {
    await db.query(
      "INSERT INTO contact_submissions (full_name, email, company, phone, project_type, budget_range, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [full_name, email, company || "", phone || "", project_type || "", budget_range || "", message || ""]
    );
    res.status(201).json({ message: "Message received. We'll be in touch soon!" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/messages — Admin only
app.get("/api/messages", auth, async (req, res) => {
  try {
    const [rows] = await db.query(
      "SELECT * FROM contact_submissions ORDER BY created_at DESC"
    );
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PATCH /api/messages/:id/status
app.patch("/api/messages/:id/status", auth, async (req, res) => {
  const { status } = req.body;
  if (!status) return res.status(400).json({ error: "Status is required" });
  try {
    await db.query("UPDATE contact_submissions SET status=? WHERE id=?", [
      status,
      req.params.id,
    ]);
    res.json({ message: "Status updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ✅ NEW — POST /api/messages/:id/reply — Send email reply to user
app.post("/api/messages/:id/reply", auth, async (req, res) => {
  const { replyText, toEmail, toName } = req.body;
  if (!replyText || !toEmail)
    return res.status(400).json({ error: "replyText and toEmail are required" });

  try {
    await mailer.sendMail({
      from: `"CodeValceno" <${process.env.EMAIL_USER}>`,
      to: toEmail,
      subject: "Re: Your inquiry — CodeValceno",
      text: replyText,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #00e5ff;">CodeValceno</h2>
          <p>Hi ${toName || "there"},</p>
          <p>${replyText.replace(/\n/g, "<br/>")}</p>
          <br/>
          <p style="color: #888;">— CodeValceno Team</p>
          <hr style="border: none; border-top: 1px solid #eee;" />
          <p style="font-size: 12px; color: #aaa;">This email was sent in response to your inquiry on codevalceno.com</p>
        </div>
      `,
    });

    // Mark message as replied in DB
    await db.query(
      "UPDATE contact_submissions SET status=? WHERE id=?",
      ["replied", req.params.id]
    );

    res.json({ success: true, message: "Reply sent successfully!" });
  } catch (err) {
    console.error("❌ Email send error:", err);
    res.status(500).json({ error: "Failed to send email: " + err.message });
  }
});

// DELETE /api/messages/:id
app.delete("/api/messages/:id", auth, async (req, res) => {
  try {
    await db.query("DELETE FROM contact_submissions WHERE id=?", [req.params.id]);
    res.json({ message: "Message deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// TEAM ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/team
app.get("/api/team", auth, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM team_members ORDER BY created_at DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/team
app.post("/api/team", auth, async (req, res) => {
  const { name, role, email, status } = req.body;
  try {
    const [result] = await db.query(
      "INSERT INTO team_members (name, role, email, status) VALUES (?, ?, ?, ?)",
      [name, role, email, status || "Active"]
    );
    res.status(201).json({ id: result.insertId, message: "Member added" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/team/:id
app.put("/api/team/:id", auth, async (req, res) => {
  const { name, role, email, status } = req.body;
  try {
    await db.query(
      "UPDATE team_members SET name=?, role=?, email=?, status=? WHERE id=?",
      [name, role, email, status, req.params.id]
    );
    res.json({ message: "Member updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/team/:id
app.delete("/api/team/:id", auth, async (req, res) => {
  try {
    await db.query("DELETE FROM team_members WHERE id=?", [req.params.id]);
    res.json({ message: "Member deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// BLOG ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/blog
app.get("/api/blog", auth, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM blog_posts ORDER BY created_at DESC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/blog
app.post("/api/blog", auth, async (req, res) => {
  const { title, content, status } = req.body;
  try {
    const [result] = await db.query(
      "INSERT INTO blog_posts (title, content, status) VALUES (?, ?, ?)",
      [title, content || "", status || "Draft"]
    );
    res.status(201).json({ id: result.insertId, message: "Post created" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/blog/:id
app.put("/api/blog/:id", auth, async (req, res) => {
  const { title, content, status } = req.body;
  try {
    await db.query(
      "UPDATE blog_posts SET title=?, content=?, status=? WHERE id=?",
      [title, content, status, req.params.id]
    );
    res.json({ message: "Post updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/blog/:id
app.delete("/api/blog/:id", auth, async (req, res) => {
  try {
    await db.query("DELETE FROM blog_posts WHERE id=?", [req.params.id]);
    res.json({ message: "Post deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// PAGES ROUTES
// ════════════════════════════════════════════════════════════════════════════

// GET /api/pages
app.get("/api/pages", auth, async (req, res) => {
  try {
    const [rows] = await db.query("SELECT * FROM pages ORDER BY id ASC");
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/pages
app.post("/api/pages", auth, async (req, res) => {
  const { name, slug, content, status } = req.body;
  try {
    const [result] = await db.query(
      "INSERT INTO pages (name, slug, content, status) VALUES (?, ?, ?, ?)",
      [name, slug, content || "", status || "Published"]
    );
    res.status(201).json({ id: result.insertId, message: "Page created" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PUT /api/pages/:id
app.put("/api/pages/:id", auth, async (req, res) => {
  const { name, slug, content, status } = req.body;
  try {
    await db.query(
      "UPDATE pages SET name=?, slug=?, content=?, status=? WHERE id=?",
      [name, slug, content, status, req.params.id]
    );
    res.json({ message: "Page updated" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/pages/:id
app.delete("/api/pages/:id", auth, async (req, res) => {
  try {
    await db.query("DELETE FROM pages WHERE id=?", [req.params.id]);
    res.json({ message: "Page deleted" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ════════════════════════════════════════════════════════════════════════════
// STATS ROUTE
// ════════════════════════════════════════════════════════════════════════════

// GET /api/stats
app.get("/api/stats", auth, async (req, res) => {
  try {
    const [[{ projects }]] = await db.query("SELECT COUNT(*) as projects FROM projects");
    const [[{ messages }]] = await db.query("SELECT COUNT(*) as messages FROM contact_submissions");
    const [[{ unread }]] = await db.query("SELECT COUNT(*) as unread FROM contact_submissions WHERE status='unread'");
    const [[{ team }]] = await db.query("SELECT COUNT(*) as team FROM team_members");
    const [[{ posts }]] = await db.query("SELECT COUNT(*) as posts FROM blog_posts");
    res.json({ projects, messages, unread, team, posts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 4000;
setupDatabase()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`🚀 CodeValceno API running at http://localhost:${PORT}`);
      console.log(`   Auth:     POST /api/auth/login`);
      console.log(`   Projects: GET/POST/PUT/DELETE /api/projects`);
      console.log(`   Messages: POST (public) · GET/PATCH/DELETE (admin)`);
      console.log(`   Reply:    POST /api/messages/:id/reply`);
      console.log(`   Team:     GET/POST/PUT/DELETE /api/team`);
      console.log(`   Blog:     GET/POST/PUT/DELETE /api/blog`);
      console.log(`   Pages:    GET/POST/PUT/DELETE /api/pages`);
      console.log(`   Stats:    GET /api/stats`);
    });
  })
  .catch((err) => {
    console.error("❌ Failed to connect to database:", err.message);
    process.exit(1);
  });