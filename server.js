const express = require("express");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const app = express();
app.use(cors({ origin: "*", credentials: true }));
app.use(express.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  port: parseInt(process.env.DB_PORT || "3306"),
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
});

const mailer = nodemailer.createTransport({
  service: "gmail",
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});

const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token provided" });
  try { req.user = jwt.verify(token, process.env.JWT_SECRET || "secret"); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
};

async function setupDatabase() {
  const conn = await db.getConnection();
  try {
    await conn.query(`CREATE TABLE IF NOT EXISTS admins (id INT AUTO_INCREMENT PRIMARY KEY, email VARCHAR(255) UNIQUE NOT NULL, password_hash VARCHAR(255) NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS projects (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(200) NOT NULL, type VARCHAR(50), country VARCHAR(100), status VARCHAR(50) DEFAULT 'In Progress', tech JSON, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS contact_submissions (id INT AUTO_INCREMENT PRIMARY KEY, full_name VARCHAR(120) NOT NULL, email VARCHAR(255) NOT NULL, company VARCHAR(120), phone VARCHAR(40), project_type VARCHAR(100), budget_range VARCHAR(50), message TEXT, status VARCHAR(20) DEFAULT 'unread', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS team_members (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(120) NOT NULL, role VARCHAR(100), email VARCHAR(255), status VARCHAR(20) DEFAULT 'Active', created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS blog_posts (id INT AUTO_INCREMENT PRIMARY KEY, title VARCHAR(255) NOT NULL, content TEXT, status VARCHAR(20) DEFAULT 'Draft', views INT DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`);
    await conn.query(`CREATE TABLE IF NOT EXISTS pages (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, slug VARCHAR(100) UNIQUE NOT NULL, content TEXT, status VARCHAR(20) DEFAULT 'Published', updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)`);
    const [rows] = await conn.query("SELECT id FROM admins WHERE email = ?", ["admin@codevalceno.com"]);
    if (rows.length === 0) {
      const hash = await bcrypt.hash("admin123", 10);
      await conn.query("INSERT INTO admins (email, password_hash) VALUES (?, ?)", ["admin@codevalceno.com", hash]);
    }
    console.log("✅ Database ready");
  } finally { conn.release(); }
}

// Run setup on first request
let dbReady = false;
app.use(async (req, res, next) => {
  if (!dbReady) {
    try { await setupDatabase(); dbReady = true; }
    catch (err) { console.error("DB setup error:", err.message); }
  }
  next();
});

// ─── HOME ROUTE (fixes 404 on /) ──────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({
    message: "CodeValceno API is running ✅",
    version: "1.0.0",
    status: "healthy",
    endpoints: [
      "POST /api/auth/login",
      "GET  /api/projects",
      "GET  /api/messages",
      "GET  /api/team",
      "GET  /api/blog",
      "GET  /api/stats",
      "GET  /api/pages",
    ],
  });
});

// ─── AUTH ──────────────────────────────────────────────────────────────────
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: "Email and password required" });
  try {
    const [rows] = await db.query("SELECT * FROM admins WHERE email = ?", [email]);
    if (rows.length === 0) return res.status(401).json({ error: "Invalid credentials" });
    const valid = await bcrypt.compare(password, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign(
      { id: rows[0].id, email: rows[0].email },
      process.env.JWT_SECRET || "secret",
      { expiresIn: "1h" } // ← changed from 7d to 1h to match frontend session
    );
    res.json({ token, email: rows[0].email });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── PROJECTS ──────────────────────────────────────────────────────────────
app.get("/api/projects", auth, async (req, res) => { try { const [rows] = await db.query("SELECT * FROM projects ORDER BY created_at DESC"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post("/api/projects", auth, async (req, res) => { const { title, type, country, status, tech } = req.body; try { const [r] = await db.query("INSERT INTO projects (title, type, country, status, tech) VALUES (?, ?, ?, ?, ?)", [title, type, country, status || "In Progress", JSON.stringify(tech || [])]); res.status(201).json({ id: r.insertId }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put("/api/projects/:id", auth, async (req, res) => { const { title, type, country, status, tech } = req.body; try { await db.query("UPDATE projects SET title=?, type=?, country=?, status=?, tech=? WHERE id=?", [title, type, country, status, JSON.stringify(tech || []), req.params.id]); res.json({ message: "Updated" }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete("/api/projects/:id", auth, async (req, res) => { try { await db.query("DELETE FROM projects WHERE id=?", [req.params.id]); res.json({ message: "Deleted" }); } catch (err) { res.status(500).json({ error: err.message }); } });

// ─── MESSAGES ──────────────────────────────────────────────────────────────
// ─── MESSAGES ──────────────────────────────────────────────────────────────
app.post("/api/messages", async (req, res) => {
  const { full_name, email, company, phone, project_type, budget_range, message } = req.body;
  if (!full_name || !email) return res.status(400).json({ error: "Name and email required" });
  try {
    await db.query(
      "INSERT INTO contact_submissions (full_name, email, company, phone, project_type, budget_range, message) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [full_name, email, company || "", phone || "", project_type || "", budget_range || "", message || ""]
    );

    // Auto-reply email to user
    await mailer.sendMail({
      from: `"CodeValceno" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Thank you for contacting CodeValceno! 💛",
      html: `
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;">
          <h2 style="color:#0f172a;">Hi ${full_name}! 👋</h2>
          <p style="color:#475569;line-height:1.7;">
            Thank you for reaching out to us! 💛<br/>
            We'll review your message and get back to you shortly — stay tuned!
          </p>
          <p style="color:#94a3b8;font-size:13px;">— CodeValceno Team</p>
        </div>
      `
    });

    res.status(201).json({ message: "Message received!" });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.get("/api/messages", auth, async (req, res) => { try { const [rows] = await db.query("SELECT * FROM contact_submissions ORDER BY created_at DESC"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.patch("/api/messages/:id/status", auth, async (req, res) => { const { status } = req.body; try { await db.query("UPDATE contact_submissions SET status=? WHERE id=?", [status, req.params.id]); res.json({ message: "Updated" }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post("/api/messages/:id/reply", auth, async (req, res) => {
  const { replyText, toEmail, toName } = req.body;
  if (!replyText || !toEmail) return res.status(400).json({ error: "replyText and toEmail required" });
  try {
    await mailer.sendMail({
      from: `"CodeValceno" <${process.env.EMAIL_USER}>`,
      to: toEmail,
      subject: "Re: Your inquiry — CodeValceno",
      text: replyText,
      html: `<p>Hi ${toName || "there"},</p><p>${replyText.replace(/\n/g, "<br/>")}</p><p>— CodeValceno Team</p>`
    });
    await db.query("UPDATE contact_submissions SET status=? WHERE id=?", ["replied", req.params.id]);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});
app.delete("/api/messages/:id", auth, async (req, res) => { try { await db.query("DELETE FROM contact_submissions WHERE id=?", [req.params.id]); res.json({ message: "Deleted" }); } catch (err) { res.status(500).json({ error: err.message }); } });

// ─── TEAM ──────────────────────────────────────────────────────────────────
app.get("/api/team", auth, async (req, res) => { try { const [rows] = await db.query("SELECT * FROM team_members ORDER BY created_at DESC"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post("/api/team", auth, async (req, res) => { const { name, role, email, status } = req.body; try { const [r] = await db.query("INSERT INTO team_members (name, role, email, status) VALUES (?, ?, ?, ?)", [name, role, email, status || "Active"]); res.status(201).json({ id: r.insertId }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put("/api/team/:id", auth, async (req, res) => { const { name, role, email, status } = req.body; try { await db.query("UPDATE team_members SET name=?, role=?, email=?, status=? WHERE id=?", [name, role, email, status, req.params.id]); res.json({ message: "Updated" }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete("/api/team/:id", auth, async (req, res) => { try { await db.query("DELETE FROM team_members WHERE id=?", [req.params.id]); res.json({ message: "Deleted" }); } catch (err) { res.status(500).json({ error: err.message }); } });

// ─── BLOG ──────────────────────────────────────────────────────────────────
app.get("/api/blog", auth, async (req, res) => { try { const [rows] = await db.query("SELECT * FROM blog_posts ORDER BY created_at DESC"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post("/api/blog", auth, async (req, res) => { const { title, content, status } = req.body; try { const [r] = await db.query("INSERT INTO blog_posts (title, content, status) VALUES (?, ?, ?)", [title, content || "", status || "Draft"]); res.status(201).json({ id: r.insertId }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put("/api/blog/:id", auth, async (req, res) => { const { title, content, status } = req.body; try { await db.query("UPDATE blog_posts SET title=?, content=?, status=? WHERE id=?", [title, content, status, req.params.id]); res.json({ message: "Updated" }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete("/api/blog/:id", auth, async (req, res) => { try { await db.query("DELETE FROM blog_posts WHERE id=?", [req.params.id]); res.json({ message: "Deleted" }); } catch (err) { res.status(500).json({ error: err.message }); } });

// ─── PAGES ──────────────────────────────────────────────────────────────────
app.get("/api/pages", auth, async (req, res) => { try { const [rows] = await db.query("SELECT * FROM pages ORDER BY id ASC"); res.json(rows); } catch (err) { res.status(500).json({ error: err.message }); } });
app.post("/api/pages", auth, async (req, res) => { const { name, slug, content, status } = req.body; try { const [r] = await db.query("INSERT INTO pages (name, slug, content, status) VALUES (?, ?, ?, ?)", [name, slug, content || "", status || "Published"]); res.status(201).json({ id: r.insertId }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.put("/api/pages/:id", auth, async (req, res) => { const { name, slug, content, status } = req.body; try { await db.query("UPDATE pages SET name=?, slug=?, content=?, status=? WHERE id=?", [name, slug, content, status, req.params.id]); res.json({ message: "Updated" }); } catch (err) { res.status(500).json({ error: err.message }); } });
app.delete("/api/pages/:id", auth, async (req, res) => { try { await db.query("DELETE FROM pages WHERE id=?", [req.params.id]); res.json({ message: "Deleted" }); } catch (err) { res.status(500).json({ error: err.message }); } });

// ─── STATS ──────────────────────────────────────────────────────────────────
app.get("/api/stats", auth, async (req, res) => {
  try {
    const [[{ projects }]] = await db.query("SELECT COUNT(*) as projects FROM projects");
    const [[{ messages }]] = await db.query("SELECT COUNT(*) as messages FROM contact_submissions");
    const [[{ unread }]] = await db.query("SELECT COUNT(*) as unread FROM contact_submissions WHERE status='unread'");
    const [[{ team }]] = await db.query("SELECT COUNT(*) as team FROM team_members");
    const [[{ posts }]] = await db.query("SELECT COUNT(*) as posts FROM blog_posts");
    res.json({ projects, messages, unread, team, posts });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ─── LOCAL DEV ──────────────────────────────────────────────────────────────
if (process.env.NODE_ENV !== "production") {
  const PORT = process.env.PORT || 4000;
  setupDatabase()
    .then(() => app.listen(PORT, () => console.log(`🚀 API running on port ${PORT}`)))
    .catch((err) => console.error("❌ DB error:", err.message));
}

module.exports = app;