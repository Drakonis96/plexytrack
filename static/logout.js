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
    const sidebar = document.querySelector('.sidebar');
    if (navToggle && sidebar) {
        navToggle.addEventListener('click', function() {
            sidebar.classList.toggle('open');
        });
    }
});
