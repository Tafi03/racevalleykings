const toggleBtn = document.getElementById('theme-toggle');
const body = document.body;

const pref = localStorage.getItem('darkMode');
if (pref === null || pref === 'true') {
    body.classList.add('dark');
    toggleBtn.textContent = '☀️';
} else {
    toggleBtn.textContent = '🌙';
}

toggleBtn.addEventListener('click', () => {
    body.classList.toggle('dark');
    const dark = body.classList.contains('dark');
    toggleBtn.textContent = dark ? '☀️' : '🌙';
    localStorage.setItem('darkMode', dark);
});
