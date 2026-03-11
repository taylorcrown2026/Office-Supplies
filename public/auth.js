(function () {
  const state = { authenticated: false, user: null };

  function base() { return (window.__BASE_PATH__ || ""); }

  async function session() {
    try {
      const r = await fetch(base() + "/session", { credentials: "include" });
      const raw = await r.text();
      try {
        const json = JSON.parse(raw);
        state.authenticated = !!json.authenticated;
        state.user = json.user || null;
      } catch (e) { state.authenticated = false; state.user = null; }
    } catch (e) { state.authenticated = false; state.user = null; }
    return state;
  }

  async function login(username, password) {
    const r = await fetch(base() + "/login", {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.user) throw new Error("Login failed");
    state.authenticated = true; state.user = data.user; return data.user;
  }

  async function logout() {
    try { await fetch(base() + "/logout", { method: "POST", credentials: "include" }); } catch {}
    state.authenticated = false; state.user = null;
  }

  async function ensureAuthenticated() {
    await session();
    if (!state.authenticated) {
      const here = location.pathname + location.search + location.hash;
      const ret = encodeURIComponent(here);
      location.href = base() + "/login.html?return=" + ret;
      return false;
    }
    return true;
  }

  function redirectAfterLogin(user) {
    if (!user) user = state.user; if (!user) return;
    if (user.role === "admin") location.href = "admin.html"; else location.href = "index.html";
  }

  function refreshAuthUI(root) {
    root = root || document;
    const ctas = root.querySelectorAll('#authCta, [data-auth-cta]');
    ctas.forEach(el => {
      // Reset existing listeners by cloning
      const clone = el.cloneNode(true); el.parentNode.replaceChild(clone, el);
      if (state.authenticated) {
        clone.textContent = 'Log out';
        clone.href = '#';
        clone.addEventListener('click', async (e) => { e.preventDefault(); await logout(); location.href = 'index.html'; });
      } else {
        clone.textContent = 'Sign in';
        clone.href = 'login.html';
      }
    });

    // Show/hide admin links
    root.querySelectorAll('[data-admin-link]').forEach(a => {
      a.style.display = (state.user?.role === "admin" ? "" : "none");
    });
  }

  function bindLogoutButtons(root){
    root = root || document;
    root.querySelectorAll('[data-logout]').forEach(btn => {
      btn.addEventListener('click', async () => { await logout(); location.href = 'index.html'; });
    });
  }

  // Optional UX: guard protected links client-side for nicer flow
  async function guardLinks(root){
    root = root || document;
    await session();
    const protectedHrefs = new Set(['invoice.html','supply.html','admin.html']);
    root.addEventListener('click', (e) => {
      const a = e.target.closest('a');
      if (!a) return;
      const href = (a.getAttribute('href')||'').replace(/^\\?/, '');
      if (protectedHrefs.has(href) && !state.authenticated) {
        e.preventDefault();
        const ret = encodeURIComponent('/' + href);
        location.href = base() + '/login.html?return=' + ret;
      }
    }, true);
  }

  // Optional: simple idle timer to auto-refresh session state every 60s
  function startIdleTimer(){
    setInterval(session, 60000);
  }

  window.Auth = { state, base, session, login, logout, ensureAuthenticated,
    redirectAfterLogin, refreshAuthUI, bindLogoutButtons, guardLinks, startIdleTimer };
})();