/* PlexyTrack — Sidebar & Theme Controller */
(function () {
  'use strict';

  /* ---- CSRF protection ---------------------------------------------------
   * The server publishes a per-session CSRF token in a readable cookie. We
   * attach it as a header on same-origin mutating fetches and as a hidden
   * field on classic form submissions, so existing calls keep working without
   * per-call changes. */
  const CSRF_COOKIE = 'plexytrack_csrf';
  const CSRF_HEADER = 'X-CSRFToken';
  const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS', 'TRACE'];

  function getCookie(name) {
    const match = document.cookie.match('(^|;)\\s*' + name + '\\s*=\\s*([^;]+)');
    return match ? decodeURIComponent(match.pop()) : '';
  }

  function csrfToken() {
    return getCookie(CSRF_COOKIE);
  }

  function isSameOrigin(url) {
    if (!url) return true;
    if (url.startsWith('/') && !url.startsWith('//')) return true;
    try {
      return new URL(url, window.location.href).origin === window.location.origin;
    } catch (e) {
      return false;
    }
  }

  const _origFetch = window.fetch ? window.fetch.bind(window) : null;
  if (_origFetch) {
    window.fetch = function (input, init) {
      init = init || {};
      const method = (
        init.method ||
        (input && typeof input !== 'string' && input.method) ||
        'GET'
      ).toUpperCase();
      const url = typeof input === 'string' ? input : (input && input.url) || '';
      if (!SAFE_METHODS.includes(method) && isSameOrigin(url)) {
        const token = csrfToken();
        if (token) {
          const headers = new Headers(
            init.headers || (input && typeof input !== 'string' && input.headers) || {}
          );
          if (!headers.has(CSRF_HEADER)) headers.set(CSRF_HEADER, token);
          init.headers = headers;
        }
      }
      return _origFetch(input, init);
    };
  }

  // Inject the token into any non-GET form right before it submits. A capturing
  // listener covers forms added dynamically after page load too.
  document.addEventListener('submit', function (e) {
    const form = e.target;
    if (!(form instanceof HTMLFormElement)) return;
    const method = (form.getAttribute('method') || 'get').toUpperCase();
    if (method === 'GET') return;
    if (form.querySelector('input[name="_csrf_token"]')) return;
    const token = csrfToken();
    if (!token) return;
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = '_csrf_token';
    input.value = token;
    form.appendChild(input);
  }, true);

  /* ---- Theme ---- */
  const THEME_KEY = 'plexytrack-theme';

  function getPreferredTheme() {
    const stored = localStorage.getItem(THEME_KEY);
    if (stored) return stored;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    localStorage.setItem(THEME_KEY, theme);
  }

  // Apply immediately (before DOMContentLoaded to avoid flash)
  applyTheme(getPreferredTheme());

  document.addEventListener('DOMContentLoaded', function () {
    /* ---- Theme toggle ---- */
    const themeBtn = document.getElementById('themeToggle');
    if (themeBtn) {
      themeBtn.addEventListener('click', function () {
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        applyTheme(current === 'dark' ? 'light' : 'dark');
      });
    }

    /* ---- Sidebar toggle ---- */
    const hamburger = document.getElementById('hamburgerBtn');
    const sidebar = document.querySelector('.sidebar');
    const overlay = document.getElementById('sidebarOverlay');

    function openSidebar() {
      if (sidebar) sidebar.classList.add('open');
      if (overlay) overlay.classList.add('active');
    }

    function closeSidebar() {
      if (sidebar) sidebar.classList.remove('open');
      if (overlay) overlay.classList.remove('active');
    }

    if (hamburger) {
      hamburger.addEventListener('click', function () {
        if (sidebar && sidebar.classList.contains('open')) {
          closeSidebar();
        } else {
          openSidebar();
        }
      });
    }

    if (overlay) {
      overlay.addEventListener('click', closeSidebar);
    }

    /* ---- Logout ---- */
    const logoutBtn = document.getElementById('logoutBtn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', async function () {
        try {
          const response = await fetch('/logout', { method: 'POST' });
          if (response.ok) {
            const data = await response.json();
            window.location.href = data.redirect || '/login';
          } else {
            alert('Error logging out');
          }
        } catch (err) {
          alert('Error logging out');
        }
      });
    }

    /* ---- Reinforced-password notice ---- */
    checkSecurityStatus();
  });

  function showPasswordBanner(minLength) {
    if (document.getElementById('pt-security-banner')) return;
    const banner = document.createElement('div');
    banner.id = 'pt-security-banner';
    banner.setAttribute('role', 'alert');
    banner.style.cssText =
      'position:fixed;top:0;left:0;right:0;z-index:9999;padding:12px 16px;' +
      'display:flex;flex-wrap:wrap;gap:12px;align-items:center;justify-content:center;' +
      'background:#b45309;color:#fff;font-size:14px;box-shadow:0 2px 8px rgba(0,0,0,.2);';

    const msg = document.createElement('span');
    msg.textContent =
      'Security requirements were reinforced. Your password should be at least ' +
      (minLength || 8) + ' characters.';
    banner.appendChild(msg);

    const changeBtn = document.createElement('button');
    changeBtn.textContent = 'Change password';
    changeBtn.style.cssText =
      'background:#fff;color:#b45309;border:none;border-radius:6px;padding:6px 12px;' +
      'font-weight:600;cursor:pointer;';
    changeBtn.addEventListener('click', function () {
      window.location.href = '/account/password';
    });
    banner.appendChild(changeBtn);

    const ignoreBtn = document.createElement('button');
    ignoreBtn.textContent = 'Ignore';
    ignoreBtn.style.cssText =
      'background:transparent;color:#fff;border:1px solid rgba(255,255,255,.6);' +
      'border-radius:6px;padding:6px 12px;cursor:pointer;';
    ignoreBtn.addEventListener('click', async function () {
      ignoreBtn.disabled = true;
      try {
        await fetch('/api/security/ack_password', { method: 'POST' });
      } catch (e) { /* best effort */ }
      banner.remove();
    });
    banner.appendChild(ignoreBtn);

    document.body.appendChild(banner);
  }

  async function checkSecurityStatus() {
    try {
      const res = await fetch('/api/security/status');
      if (!res.ok) return;
      const data = await res.json();
      if (data.password_upgrade_notice) {
        showPasswordBanner(data.min_password_length);
      }
    } catch (e) { /* ignore */ }
  }
})();
