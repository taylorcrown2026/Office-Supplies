(function(){
  const state = { authenticated: false, user: null };

  function base(){ return (window.__BASE_PATH__ || ""); }

  async function session(){
    const r = await fetch(base() + "/session", { credentials: "include" });
    const raw = await r.text();
    try {
      const json = JSON.parse(raw);
      state.authenticated = json.authenticated;
      state.user = json.user;
    } catch {}
    return state;
  }

  async function login(username, password){
    const r = await fetch(base() + "/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await r.json().catch(()=>({}));
    if(!r.ok || !data.user) throw new Error("Login failed");
    state.authenticated = true; state.user = data.user; return data.user;
  }

  async function ensureAuthenticated(){
    await session();
    if(!state.authenticated){
      alert("Please sign in to continue.");
      location.href = "login.html";
      return false;
    }
    return true;
  }

  function refreshAuthUI(){
    const ctas = document.querySelectorAll('#authCta');
    ctas.forEach(el => {
      if(state.authenticated){ el.textContent = state.user?.username || 'Account'; el.removeAttribute('data-public'); el.href = '#'; }
      else { el.textContent = 'Sign in'; el.href = 'login.html'; }
    });
  }

  function guardLinks(root){
    if(!root) root = document;
    // Any link without data-public requires auth
    root.querySelectorAll('a:not([data-public])').forEach(a => {
      a.addEventListener('click', async (e) => {
        if(!state.authenticated){
          e.preventDefault();
          await ensureAuthenticated();
        }
      });
    });
  }

  function startIdleTimer(){ /* server handles idle via rolling cookie; no-op */ }

  window.Auth = { state, session, login, ensureAuthenticated, refreshAuthUI, guardLinks, startIdleTimer };
})();