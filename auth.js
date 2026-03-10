(function(){
  const IDLE_HINT_MS = 9 * 60 * 1000; // client-side hint (server enforces 10 min)

  const state = { authenticated: false, user: null };

  async function session(){
    try{
      const r = await fetch('/session', { credentials:'same-origin' });
      const j = await r.json();
      state.authenticated = !!j.authenticated;
      state.user = j.user || null;
      return state;
    }catch(e){ return { authenticated:false, user:null }; }
  }

  async function login(username, password){
    const r = await fetch('/login', {
      method:'POST', headers:{'Content-Type':'application/json'}, credentials:'same-origin',
      body: JSON.stringify({ username, password })
    });
    if(!r.ok) throw new Error('Invalid credentials');
    const j = await r.json();
    state.authenticated = true; state.user = j.user;
    refreshAuthUI();
    return j.user;
  }

  async function logout(redirectToLogin=true){
    try{ await fetch('/logout', { method:'POST', credentials:'same-origin' }); }catch(e){}
    state.authenticated = false; state.user = null;
    refreshAuthUI();
    if(redirectToLogin){
      const here = location.pathname + location.search + location.hash;
      location.href = 'login.html?loggedOut=1&returnTo=' + encodeURIComponent(here);
    }
  }

  function guardLinks(root=document){
    const selector = 'a[href]:not([data-public])';
    root.addEventListener('click', async function(e){
      const a = e.target.closest('a');
      if(!a || !a.matches(selector)) return;
      const href = a.getAttribute('href') || '';
      const isLogout = a.matches('[data-logout]');
      const isLogin = a.matches('[data-login]');
      if(isLogout){ e.preventDefault(); await logout(true); return; }
      if(isLogin){ return; }
      if(href.startsWith('mailto:') || href.startsWith('tel:')) return;

      const u = new URL(href, location.href);
      const s = await session();
      if(!s.authenticated){
        e.preventDefault();
        const dest = u.pathname + u.search + u.hash;
        location.href = 'login.html?returnTo=' + encodeURIComponent(dest);
      }
    }, {passive:false});
  }

  function refreshAuthUI(){
    const cta = document.querySelector('#authCta');
    if(cta){
      if(state.authenticated){
        cta.textContent = 'Log out';
        cta.setAttribute('data-logout','');
        cta.removeAttribute('data-login');
        cta.removeAttribute('href');
        cta.setAttribute('role','button');
      }else{
        cta.textContent = 'Sign in';
        cta.setAttribute('data-login','');
        cta.removeAttribute('data-logout');
        cta.setAttribute('href','login.html?returnTo=' + encodeURIComponent(location.pathname + location.search + location.hash));
        cta.removeAttribute('role');
      }
    }
    const who = document.querySelector('#whoami');
    if(who){
      who.textContent = state.authenticated && state.user ? state.user.username : '';
    }
  }

  async function ensureAuthenticated(){
    const s = await session();
    if(!s.authenticated){
      const here = location.pathname + location.search + location.hash;
      location.replace('login.html?returnTo=' + encodeURIComponent(here));
      return false;
    }
    return true;
  }

  // Idle hint (optional UX)
  function startIdleHint(){
    let t=null; const reset=()=>{ if(t) clearTimeout(t); t=setTimeout(()=>{ /* hint only */ }, IDLE_HINT_MS); };
    ['click','keydown','mousemove','scroll','touchstart'].forEach(evt=> window.addEventListener(evt, reset, {passive:true}));
    reset();
  }
  // Backwards-compat for pages that call Auth.startIdleTimer()
  function startIdleTimer(){ startIdleHint(); }

  // Expose
  window.Auth = { session, login, logout, guardLinks, refreshAuthUI, ensureAuthenticated, state, startIdleHint, startIdleTimer };

  document.addEventListener('DOMContentLoaded', async () => {
    try{ await session(); refreshAuthUI(); guardLinks(document); startIdleHint(); }catch(e){}
  });
})();
