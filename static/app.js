/* PlexyTrack — Sidebar & Theme Controller */
(function () {
  'use strict';

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
  });
})();
