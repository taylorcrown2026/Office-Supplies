(async function () {
  const state = { authenticated: false, user: null };

  function base() {
    return window.__BASE_PATH__ || "";
  }

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

    const raw = await r.text();
    let data;
    try {
      data = JSON.parse(raw);
    } catch {
      throw new Error("Empty or invalid response from /login");
    }

    if (!r.ok || !data || !data.user) {
      throw new Error("Login failed: " + raw);
    }

    state.authenticated = true;
    state.user = data.user;
    return data.user;
  }

  window.Auth = { login, session, state };
})();