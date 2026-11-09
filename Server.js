
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL || !process.env.JWT_SECRET) {
  throw new Error("DATABASE_URL and JWT_SECRET must be configured.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet());
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      roll_no TEXT UNIQUE,
      department TEXT,
      year TEXT,
      password TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'student'
        CHECK (role IN ('student','teacher','admin')),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS exams (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      duration INTEGER NOT NULL,
      total_marks INTEGER NOT NULL,
      questions JSONB NOT NULL,
      published BOOLEAN DEFAULT FALSE,
      results_published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS submissions (
      id SERIAL PRIMARY KEY,
      exam_id INTEGER REFERENCES exams(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      answers JSONB NOT NULL,
      score INTEGER NOT NULL,
      submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(exam_id, user_id)
    );

    CREATE TABLE IF NOT EXISTS attendance (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      attendance_date DATE DEFAULT CURRENT_DATE,
      status TEXT NOT NULL CHECK (status IN ('present','absent')),
      UNIQUE(user_id, attendance_date)
    );

    CREATE TABLE IF NOT EXISTS fees (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      description TEXT NOT NULL,
      amount NUMERIC(10,2) NOT NULL,
      status TEXT DEFAULT 'pending'
        CHECK (status IN ('pending','paid'))
    );

    CREATE TABLE IF NOT EXISTS notices (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      message TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  if (process.env.ADMIN_EMAIL && process.env.ADMIN_PASSWORD) {
    const email = process.env.ADMIN_EMAIL.toLowerCase();
    const existing = await pool.query(
      "SELECT id FROM users WHERE email=$1", [email]
    );

    if (!existing.rowCount) {
      const hash = await bcrypt.hash(process.env.ADMIN_PASSWORD, 12);
      await pool.query(
        `INSERT INTO users(name,email,password,role)
         VALUES($1,$2,$3,'admin')`,
        ["JD University Administrator", email, hash]
      );
    }
  }
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Login required" });

  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired login" });
  }
}

function allow(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ error: "Access denied" });
    }
    next();
  };
}

function issueToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );
}

// Student registration
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, roll_no, department, year, password } = req.body;

    if (!name || !email || !roll_no || !password || password.length < 8) {
      return res.status(400).json({
        error: "Enter all required details. Password must be at least 8 characters."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users(name,email,roll_no,department,year,password)
       VALUES($1,$2,$3,$4,$5,$6)
       RETURNING id,name,email,roll_no,department,year,role`,
      [name, email.toLowerCase(), roll_no, department, year, hash]
    );

    res.status(201).json({
      user: result.rows[0],
      token: issueToken(result.rows[0])
    });
  } catch {
    res.status(400).json({ error: "Registration failed. Check duplicate email or roll number." });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [String(email || "").toLowerCase()]
  );

  const user = result.rows[0];
  if (!user || !(await bcrypt.compare(password || "", user.password))) {
    return res.status(401).json({ error: "Incorrect email or password" });
  }

  const { password: hidden, ...safeUser } = user;
  res.json({ user: safeUser, token: issueToken(user) });
});

// Current user profile
app.get("/api/me", authenticate, async (req, res) => {
  const result = await pool.query(
    `SELECT id,name,email,roll_no,department,year,role
     FROM users WHERE id=$1`,
    [req.user.id]
  );
  res.json(result.rows[0] || null);
});

// Admin creates teacher or other admin accounts
app.post("/api/staff", authenticate, allow("admin"), async (req, res) => {
  try {
    const { name, email, password, role } = req.body;
    if (!name || !email || !password || password.length < 8 ||
        !["teacher", "admin"].includes(role)) {
      return res.status(400).json({ error: "Invalid staff details" });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      `INSERT INTO users(name,email,password,role)
       VALUES($1,$2,$3,$4)
       RETURNING id,name,email,role`,
      [name, email.toLowerCase(), hash, role]
    );
    res.status(201).json(result.rows[0]);
  } catch {
    res.status(400).json({ error: "Could not create staff account" });
  }
});

// Create examination
app.post("/api/exams", authenticate, allow("admin", "teacher"), async (req, res) => {
  const { title, duration, total_marks, questions } = req.body;

  if (!title || !Number.isInteger(duration) || duration < 1 ||
      !Number.isInteger(total_marks) || total_marks < 1 ||
      !Array.isArray(questions) || !questions.length) {
    return res.status(400).json({ error: "Invalid exam details" });
  }

  const result = await pool.query(
    `INSERT INTO exams(title,duration,total_marks,questions)
     VALUES($1,$2,$3,$4) RETURNING id,title,duration,total_marks,published`,
    [title, duration, total_marks, JSON.stringify(questions)]
  );
  res.status(201).json(result.rows[0]);
});

// List published exams for students; all exams for staff
app.get("/api/exams", authenticate, async (req, res) => {
  const staff = ["admin", "teacher"].includes(req.user.role);
  const result = await pool.query(
    staff
      ? "SELECT id,title,duration,total_marks,published FROM exams ORDER BY id DESC"
      : "SELECT id,title,duration,total_marks FROM exams WHERE published=true ORDER BY id DESC"
  );
  res.json(result.rows);
});

// Get exam questions
app.get("/api/exams/:id", authenticate, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM exams WHERE id=$1", [req.params.id]
  );
  const exam = result.rows[0];

  if (!exam || (!exam.published &&
      !["admin", "teacher"].includes(req.user.role))) {
    return res.status(404).json({ error: "Exam not found" });
  }

  const questions = exam.questions.map(q => {
    const { answer, ...safeQuestion } = q;
    return safeQuestion;
  });

  res.json({
    id: exam.id,
    title: exam.title,
    duration: exam.duration,
    total_marks: exam.total_marks,
    questions
  });
});

// Submit examination and calculate MCQ score on server
app.post("/api/exams/:id/submit", authenticate, allow("student"), async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const examResult = await client.query(
      "SELECT * FROM exams WHERE id=$1 AND published=true",
      [req.params.id]
    );
    const exam = examResult.rows[0];

    if (!exam) throw new Error("Exam unavailable");

    const questions = exam.questions;
    const answers = req.body.answers || {};
    let score = 0;

    for (const q of questions) {
      if (String(answers[q.id]) === String(q.answer)) {
        score += Number(q.marks || 1);
      }
    }

    const existing = await client.query(
      "SELECT id FROM submissions WHERE exam_id=$1 AND user_id=$2",
      [exam.id, req.user.id]
    );
    if (existing.rowCount) throw new Error("Exam already submitted");

    await client.query(
      `INSERT INTO submissions(exam_id,user_id,answers,score)
       VALUES($1,$2,$3,$4)`,
      [exam.id, req.user.id, JSON.stringify(answers), score]
    );

    await client.query("COMMIT");
    res.status(201).json({
      message: "Exam submitted. Results are waiting for approval."
    });
  } catch (error) {
    await client.query("ROLLBACK");
    res.status(400).json({ error: error.message });
  } finally {
    client.release();
  }
});

// Admin publishes results separately from exam availability
app.patch("/api/exams/:id/results", authenticate, allow("admin"), async (req, res) => {
  await pool.query(
    "UPDATE exams SET results_published=$1 WHERE id=$2",
    [Boolean(req.body.published), req.params.id]
  );
  res.json({ message: "Result publication setting updated" });
});

// Student sees only their own published results
app.get("/api/results", authenticate, async (req, res) => {
  const result = await pool.query(
    `SELECT e.title,s.score,e.total_marks,s.submitted_at
     FROM submissions s
     JOIN exams e ON e.id=s.exam_id
     WHERE s.user_id=$1 AND e.results_published=true
     ORDER BY s.submitted_at DESC`,
    [req.user.id]
  );
  res.json(result.rows);
});

// Admin and teachers view all submissions
app.get("/api/admin/results", authenticate, allow("admin", "teacher"), async (req, res) => {
  const result = await pool.query(
    `SELECT u.name,u.roll_no,u.department,e.title,
            s.score,e.total_marks,s.submitted_at
     FROM submissions s
     JOIN users u ON u.id=s.user_id
     JOIN exams e ON e.id=s.exam_id
     ORDER BY s.submitted_at DESC`
  );
  res.json(result.rows);
});

// Attendance
app.post("/api/attendance", authenticate, allow("admin", "teacher"), async (req, res) => {
  const { user_id, status, date } = req.body;
  if (!user_id || !["present", "absent"].includes(status)) {
    return res.status(400).json({ error: "Invalid attendance details" });
  }

  await pool.query(
    `INSERT INTO attendance(user_id,status,attendance_date)
     VALUES($1,$2,COALESCE($3::date,CURRENT_DATE))
     ON CONFLICT(user_id,attendance_date)
     DO UPDATE SET status=EXCLUDED.status`,
    [user_id, status, date || null]
  );
  res.json({ message: "Attendance saved" });
});

app.get("/api/attendance", authenticate, async (req, res) => {
  const isStaff = ["admin", "teacher"].includes(req.user.role);
  const result = await pool.query(
    isStaff
      ? `SELECT u.name,u.roll_no,a.attendance_date,a.status
         FROM attendance a JOIN users u ON u.id=a.user_id
         ORDER BY a.attendance_date DESC`
      : `SELECT attendance_date,status FROM attendance
         WHERE user_id=$1 ORDER BY attendance_date DESC`,
    isStaff ? [] : [req.user.id]
  );
  res.json(result.rows);
});

// Fees
app.post("/api/fees", authenticate, allow("admin"), async (req, res) => {
  const { user_id, description, amount } = req.body;
  if (!user_id || !description || !Number.isFinite(Number(amount)) ||
      Number(amount) < 0) {
    return res.status(400).json({ error: "Invalid fee details" });
  }

  const result = await pool.query(
    `INSERT INTO fees(user_id,description,amount)
     VALUES($1,$2,$3) RETURNING *`,
    [user_id, description, amount]
  );
  res.status(201).json(result.rows[0]);
});

app.get("/api/fees", authenticate, async (req, res) => {
  const staff = ["admin", "teacher"].includes(req.user.role);
  const result = await pool.query(
    staff
      ? `SELECT f.*,u.name,u.roll_no FROM fees f
         JOIN users u ON u.id=f.user_id ORDER BY f.id DESC`
      : "SELECT * FROM fees WHERE user_id=$1 ORDER BY id DESC",
    staff ? [] : [req.user.id]
  );
  res.json(result.rows);
});

// Notices
app.post("/api/notices", authenticate, allow("admin", "teacher"), async (req, res) => {
  const { title, message } = req.body;
  if (!title || !message) {
    return res.status(400).json({ error: "Title and message required" });
  }

  const result = await pool.query(
    "INSERT INTO notices(title,message) VALUES($1,$2) RETURNING *",
    [title, message]
  );
  res.status(201).json(result.rows[0]);
});

app.get("/api/notices", authenticate, async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM notices ORDER BY created_at DESC"
  );
  res.json(result.rows);
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", service: "JD University Portal API" });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initializeDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`JD University Portal running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Startup failed:", error);
    process.exit(1);
  });
  
