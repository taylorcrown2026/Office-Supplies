const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const path = require("path");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// In production, set secure cookies and use a session store (e.g., Redis)
app.use(session({
  secret: "CHANGE_ME_TO_ENV_SECRET",
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false, // set to true behind HTTPS
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 // 1 hour
  }
}));

// Static files (serve current directory)
app.use(express.static(__dirname));

function requireAuth(req, res, next){
  if(!req.session.user) return res.redirect('/login.html');
  next();
}
function requireAdmin(req, res, next){
  if(!req.session.user || req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  next();
}

let requests = [];

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  if(username === 'admin' && password === 'admin123'){
    req.session.user = { username, role: 'admin' };
    return res.redirect('/admin.html');
  }
  if(username && password){
    req.session.user = { username, role: 'user' };
    return res.redirect('/user.html');
  }
  return res.redirect('/login.html');
});

app.post('/request', requireAuth, (req, res) => {
  const { department, item, date } = req.body;
  if(!department || !item || !date) return res.status(400).send('Missing fields');

  const min = new Date();
  min.setHours(0,0,0,0);
  min.setDate(min.getDate()+10);
  const requested = new Date(date + 'T00:00:00');
  if(requested < min) return res.status(400).send('Date must be at least 10 days out');

  requests.push({ id: Date.now().toString(), user: req.session.user.username, department, item, date });
  res.sendStatus(200);
});

app.get('/requests', requireAdmin, (req, res) => {
  res.json(requests);
});

app.put('/requests/:id', requireAdmin, (req, res) => {
  requests = requests.filter(r => r.id !== req.params.id);
  res.sendStatus(200);
});

app.post('/createUser', requireAdmin, (req, res) => {
  console.log('New user (demo):', req.body); // Replace with real provisioning
  res.sendStatus(200);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));