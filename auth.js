
/*
  Minimal front-end auth helper (demo only)
  -----------------------------------------------------------------
  ⚠️ SECURITY NOTE (Read me):
  - Real authentication must happen on the server over HTTPS.
  - Passwords must be hashed server-side with a strong KDF (e.g., Argon2id/bcrypt/scrypt) with per-user salts.
  - This file only simulates a session for front-end demos and route guards.
*/
(function(){
  const IDLE_TIMEOUT_MS = 10 * 60 * 1000; // 10 minutes
  const STORAGE_KEYS = {
    token: 'session.token',
    created: 'session.created',
    last: 'session.lastActivity',
    user: 'session.user'
  };

  function now(){ return Date.now(); }

  function isAuthenticated(){
    try{
      const token = sessionStorage.getItem(STORAGE_KEYS.token);
      const last = parseInt(sessionStorage.getItem(STORAGE_KEYS.last) || '0', 10);
      if(!token) return false;
      if(!last) return false;
      if(now() - last > IDLE_TIMEOUT_MS) {
        // idle timeout exceeded
        logout(false);
        return false;
      }
      return true;
    }catch(e){ return false; }
  }

  function updateActivity(){
    sessionStorage.setItem(STORAGE_KEYS.last, String(now()));
  }

  function randomToken(){
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  function login(user){
    // In a real app the server would set an HttpOnly, Secure cookie for the session.
    sessionStorage.setItem(STORAGE_KEYS.token, randomToken());
    sessionStorage.setItem(STORAGE_KEYS.created, String(now()));
    sessionStorage.setItem(STORAGE_KEYS.user, user || 'user');
    updateActivity();
    refreshAuthUI();
  }

  function logout(redirectToLogin=true){
    try{
      sessionStorage.removeItem(STORAGE_KEYS.token);
      sessionStorage.removeItem(STORAGE_KEYS.created);
      sessionStorage.removeItem(STORAGE_KEYS.last);
      sessionStorage.removeItem(STORAGE_KEYS.user);
    }catch(e){}
    refreshAuthUI();
    if(redirectToLogin){
      const here = encodeURIComponent(location.pathname + location.search + location.hash);
      location.href = 'login.html?returnTo=' + here;
    }
  }

  // Guard all in-page links (anchors) unless they are explicitly marked data-public
  function guardLinks(root=document){
    const selector = 'a[href]:not([data-public])';
    root.addEventListener('click', function(e){
      const a = e.target.closest('a');
      if(!a) return;
      if(!a.matches(selector)) return;
      const href = a.getAttribute('href');
      // allow same-page anchors (#) and logout/login links to pass custom handling
      const isLogout = a.matches('[data-logout]');
      const isLogin = a.matches('[data-login]');
      if(isLogout){ e.preventDefault(); logout(true); return; }
      if(isLogin){ return; }
      if(!href || href.startsWith('mailto:') || href.startsWith('tel:')) return;
      if(!isAuthenticated()){
        e.preventDefault();
        const here = encodeURIComponent(location.pathname + location.search + location.hash);
        
        // Preserve anchor links so users land on the intended section after login
        let dest = here;
        if(href.startsWith('#')){
          dest = location.pathname + location.search + href;
        }else if(href.startsWith('http')){
          dest = href;
        }
        location.href = 'login.html?returnTo=' + encodeURIComponent(dest);

      }else{
        updateActivity();
      }
    }, {passive:false});
  }

  function startIdleTimer(){
    let idleTimer = null;
    const reset = () => {
      if(!isAuthenticated()) return; // nothing to do
      updateActivity();
      if(idleTimer) clearTimeout(idleTimer);
      idleTimer = setTimeout(()=>{
        // Auto-logout
        logout(true);
      }, IDLE_TIMEOUT_MS);
    };
    // User activity events
    ['click','keydown','mousemove','scroll','touchstart'].forEach(evt=>{
      window.addEventListener(evt, reset, {passive:true});
    });
    // Start now
    reset();
  }

  function refreshAuthUI(){
    // Toggle Sign in / Log out in header if present
    const cta = document.querySelector('#authCta');
    if(cta){
      if(isAuthenticated()){
        cta.textContent = 'Log out';
        cta.setAttribute('data-logout','');
        cta.removeAttribute('data-login');
      }else{
        cta.textContent = 'Sign in';
        cta.setAttribute('data-login','');
        cta.removeAttribute('data-logout');
        cta.setAttribute('href','login.html?returnTo=' + encodeURIComponent(location.pathname + location.search + location.hash));
      }
    }
  }

  // Expose a tiny API on window for the login page to call
  window.Auth = {
    isAuthenticated,
    login,
    logout,
    guardLinks,
    startIdleTimer,
    refreshAuthUI,
    updateActivity
  };

  // Initialize guards automatically on normal pages
  document.addEventListener('DOMContentLoaded', function(){
    try{
      guardLinks(document);
      startIdleTimer();
      refreshAuthUI();
    }catch(e){ /* no-op */ }
  });
})();
