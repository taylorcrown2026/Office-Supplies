(function () {
  const state = { authenticated: false, user: null };

  function base() {
    return window.__BASE_PATH__ || "";
  }

  async function session() {
    const r = await fetch(base() + "/session", {
      credentials: "include"
    });

    const raw = await r.text();
    let j = null;
    try {
      j = raw ? JSON.parse(raw) : null;
    } catch {}

    return j && typeof j === "object"
      ? ((state.authenticated = !!j.authenticated),
        (state.user = j.user || null),
        state)
      : { authenticated: false, user: null };
  }

  async function login(username, password) {
    const r = await fetch(base() + "/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ username, password })
    });

    const raw = await r.text();
    let data = null;

    try {
      data = raw ? JSON.parse(raw) : null;
    } catch {}

    if (!r.ok) {
      throw new Error(
        `Login failed (${r.status}) - ${raw ? raw.slice(0, 200) : ""}`
      );
    }

    if (!data || !data.user) {
      throw new Error(
        `Unexpected empty response from ${base()}/login`
      );
    }

    state.authenticated = true;
    state.user = data.user;

    return data.user;
  }

  window.Auth = { login, session, state };
})();