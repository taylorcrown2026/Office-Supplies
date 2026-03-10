// server.js — secure server with bcrypt sessions and uploads
'use strict';
require('dotenv').config();
const fs = require('fs');
const http = require('http');
const https = require('https');
const path = require('path');
const express = require('express');
const helmet = require('helmet');
const session = require('express-session');
const bcrypt = require('bcrypt');
const multer = require('multer');

const app = express();
const { NODE_ENV='development', PORT=3000, SESSION_SECRET='dev_only_change_me', SESSION_IDLE_MS=String(10*60*1000), SSL_KEY, SSL_CERT } = process.env;

app.use(helmet({ crossOriginEmbedderPolicy:false }));
app.use(express.json());
app.use(express.urlencoded({ extended:true }));

app.use(session({
  name:'sid',
  secret:SESSION_SECRET,
  resave:false,
  rolling:true,
  saveUninitialized:false,
  cookie:{ httpOnly:true, secure: NODE_ENV==='production', sameSite:'lax', maxAge:Number(SESSION_IDLE_MS) }
}));

app.use((req,res,next)=>{
  if(req.session?.user){
    const now=Date.now();
    const last=req.session.lastActivity||0;
    if(now-last>Number(SESSION_IDLE_MS)) return req.session.destroy(()=>next());
    req.session.lastActivity=now;
  }
  next();
});

const DEMO_USER = { id:'u1', username:'hradmin', role:'admin' };
const DEMO_PASSWORD = 'HR!2026-Secure';
const DEMO_HASH = bcrypt.hashSync(DEMO_PASSWORD, 12);

app.get('/session',(req,res)=>{ res.json({ authenticated: !!req.session.user, user:req.session.user||null }); });
app.post('/login', async (req,res)=>{
  const { username, password } = req.body||{};
  if(!username||!password) return res.status(400).json({ ok:false, error:'missing_credentials' });
  if(String(username).toLowerCase()!==DEMO_USER.username) return res.status(401).json({ ok:false, error:'invalid_credentials' });
  const valid = await bcrypt.compare(password, DEMO_HASH);
  if(!valid) return res.status(401).json({ ok:false, error:'invalid_credentials' });
  req.session.user = { id:DEMO_USER.id, username:DEMO_USER.username, role:DEMO_USER.role };
  req.session.lastActivity = Date.now();
  res.json({ ok:true, user:req.session.user });
});
app.post('/logout', (req,res)=> req.session.destroy(()=>res.json({ ok:true })) );

function requireAuth(req,res,next){ if(!req.session.user) return res.redirect('/login.html?returnTo='+encodeURIComponent(req.originalUrl)); next(); }

const uploadDir = path.join(__dirname,'uploads');
if(!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir,{recursive:true});
const storage = multer.diskStorage({ destination:(req,file,cb)=>cb(null,uploadDir), filename:(req,file,cb)=>{ const safe = path.basename(file.originalname).replace(/[^a-z0-9_.-]+/gi,'_'); const uniq = Date.now().toString(36)+'-'+Math.random().toString(36).slice(2,8); cb(null, uniq+'-'+safe); } });
const upload = multer({ storage, limits:{ fileSize:15*1024*1024 } });
app.post('/upload', requireAuth, upload.single('file'), (req,res)=>{ if(!req.file) return res.status(400).json({ ok:false, error:'no_file' }); res.json({ ok:true, file:{ name:req.file.originalname, size:req.file.size, url:'/uploads/'+req.file.filename } }); });

const publicDir = path.join(__dirname,'public');
app.use('/uploads', express.static(uploadDir, { dotfiles:'deny', maxAge:'7d' }));
app.use(express.static(publicDir));
app.get('/', (req,res)=> res.sendFile(path.join(publicDir,'index.html')) );

function start(){
  if(SSL_KEY && SSL_CERT && fs.existsSync(SSL_KEY) && fs.existsSync(SSL_CERT)){
    const key=fs.readFileSync(SSL_KEY); const cert=fs.readFileSync(SSL_CERT);
    https.createServer({key,cert}, app).listen(PORT, ()=>{
      console.log(`HTTPS on https://localhost:${PORT} (${NODE_ENV})`);
      console.log('Demo credentials: %s / %s', DEMO_USER.username, DEMO_PASSWORD);
    });
  }else{
    http.createServer(app).listen(PORT, ()=>{
      console.log(`HTTP on http://localhost:${PORT} (${NODE_ENV})`);
      console.log('Demo credentials: %s / %s', DEMO_USER.username, DEMO_PASSWORD);
    });
  }
}
start();
