(function () {
  const state = { authenticated: false, user: null };

  function base() { return (window.__BASE_PATH__ || ""); }

  async function session() {
    const r = await fetch(base() + "/session", { credentials: "include" });
    const raw = await r.text();
    try {
      const json = JSON.parse(raw);
      state.authenticated = json.authenticated;
      state.user = json.user;
    } catch {}
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
    state.authenticated = true; state.user = data.user;
    return data.user;
  }

  async function logout() {
    await fetch(base() + "/logout", { method: "POST", credentials: "include" });
    state.authenticated = false; state.user = null;
  }

  async function ensureAuthenticated() {
    await session();
    if (!state.authenticated) {
      location.href = "login.html";
      return false;
    }
    return true;
  }

  function redirectAfterLogin(user) {
    if (!user) user = state.user;
    if (!user) return;
    if (user.role === "admin") location.href = "admin.html";
    else location.href = "index.html";
  }

  function refreshAuthUI() {
    const ctas = document.querySelectorAll('#authCta');
    ctas.forEach(el => {
      if (state.authenticated) { el.textContent = state.user?.username || 'Account'; el.href = '#'; }
      else { el.textContent = 'Sign in'; el.href = 'login.html'; }
    });
    // Show/hide admin link
    document.querySelectorAll('[data-admin-link]').forEach(a => {
      a.style.display = (state.user?.role === "admin" ? "" : "none");
    });
  }

  function bindLogoutButtons() {
    document.querySelectorAll('[data-logout]').forEach(btn => {
      btn.addEventListener("click", async () => {
        await logout();
        location.href = "login.html";
      });
    });
  }

  window.Auth = {
    state, base, session, login, logout,
    ensureAuthenticated, refreshAuthUI, bindLogoutButtons, redirectAfterLogin
  };
})();