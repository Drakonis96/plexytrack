document.addEventListener('DOMContentLoaded', function() {
    const btn = document.getElementById('logoutBtn');
    if (!btn) return;
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
});
