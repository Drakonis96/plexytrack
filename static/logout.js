document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('logoutBtn');
    if (btn) {
        btn.addEventListener('click', async function() {
            try {
                const response = await fetch('/logout', { method: 'POST' });
                if (response.ok) {
                    localStorage.removeItem('plexytrackUsersState');
                    window.location.reload();
                } else {
                    alert('Error logging out');
                }
            } catch (err) {
                alert('Error logging out');
            }
        });
    }

    const navToggle = document.getElementById('navToggle');
    const appNav = document.querySelector('.app-nav');
    if (navToggle && appNav) {
        navToggle.addEventListener('click', function() {
            appNav.classList.toggle('open');
        });
    }
});
