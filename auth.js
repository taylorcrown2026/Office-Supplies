(function(){
  const IDLE_HINT_MS = 9 * 60 * 1000;
  const state = { authenticated:false, user:null };

  function base(){ return (window.__BASE_PATH__ || '').replace(/\/$/,''); }

  async function session(){
    try{
      const r = await fetch(base() + '/session', { credentials:'same-origin' });
      const raw = await r.text(); let j=null; try{ j = raw ? JSON.parse(raw) : null; }catch{}
      return j && typeof j==='object' ? (state.authenticated=!!j.authenticated, state.user=j.user||null, state) : { authenticated:false, user:null };
    }catch(e){ return { authenticated:false, user:null }; }
  }

  async function login(username,password){
    const r = await fetch(base() + '/login', {
      method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
      body: JSON.stringify({ username, password })
    });
    const raw = await r.text(); let data=null; try{ data = raw ? JSON.parse(raw) : null; }catch{}
    if(!r.ok){ const snippet = raw && raw.length < 300 ? ` - ${raw}` : ''; throw new Error(`Login failed (${r.status})${snippet}`); }
    if(!data || !data.user){ const ct = r.headers.get('content-type')||''; const msg = raw? `Unexpected response (content-type: ${ct}): ${raw.slice(0,200)}` : `Empty 200/204 response from ${base()}/login (content-type: ${ct})`; throw new Error(msg); }
    state.authenticated=true; state.user=data.user; refreshAuthUI(); return data.user;
  }

  async function logout(redirectToLogin=true){
    try{ await fetch(base() + '/logout', { method:'POST', credentials:'same-origin' }); }catch(e){}
    state.authenticated=false; state.user=null; refreshAuthUI();
    if(redirectToLogin){ const here = location.pathname + location.search + location.hash; location.href = (base()||'') + '/login.html?loggedOut=1&returnTo=' + encodeURIComponent(here); }
  }

  function guardLinks(root=document){
    const selector = 'a[href]:not([data-public])';
    root.addEventListener('click', async function(e){
      const a = e.target.closest('a'); if(!a || !a.matches(selector)) return;
      const href = a.getAttribute('href') || ''; const isLogout = a.matches('[data-logout]'); const isLogin = a.matches('[data-login]');
      if(isLogout){ e.preventDefault(); await logout(true); return; } if(isLogin){ return; }
      if(href.startsWith('mailto:') || href.startsWith('tel:')) return;
      const u = new URL(href, location.href); const s = await session();
      if(!s.authenticated){ e.preventDefault(); const dest = u.pathname + u.search + u.hash; location.href = (base()||'') + '/login.html?returnTo=' + encodeURIComponent(dest); }
    }, {passive:false});
  }

  function refreshAuthUI(){
    const cta = document.querySelector('#authCta');
    if(cta){ if(state.authenticated){ cta.textContent='Log out'; cta.setAttribute('data-logout',''); cta.removeAttribute('data-login'); cta.removeAttribute('href'); cta.setAttribute('role','button'); } else { cta.textContent='Sign in'; cta.setAttribute('data-login',''); cta.removeAttribute('data-logout'); cta.setAttribute('href', (base()||'') + '/login.html?returnTo=' + encodeURIComponent(location.pathname + location.search + location.hash)); cta.removeAttribute('role'); } }
    const who = document.querySelector('#whoami'); if(who){ who.textContent = (state.authenticated&&state.user)? state.user.username : ''; }
  }

  async function ensureAuthenticated(){ const s = await session(); if(!s.authenticated){ const here = location.pathname + location.search + location.hash; location.replace((base()||'') + '/login.html?returnTo=' + encodeURIComponent(here)); return false; } return true; }

  function startIdleHint(){ let t=null; const reset=()=>{ if(t) clearTimeout(t); t=setTimeout(()=>{}, IDLE_HINT_MS);}; ['click','keydown','mousemove','scroll','touchstart'].forEach(evt=> window.addEventListener(evt, reset, {passive:true})); reset(); }
  function startIdleTimer(){ startIdleHint(); }

  window.Auth = { session, login, logout, guardLinks, refreshAuthUI, ensureAuthenticated, state, startIdleHint, startIdleTimer };

  document.addEventListener('DOMContentLoaded', async ()=>{ try{ await session(); refreshAuthUI(); guardLinks(document); startIdleHint(); }catch(e){} });
})();
