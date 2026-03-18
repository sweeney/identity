(function() {
    var pw = document.getElementById('password');
    var confirm = document.getElementById('password_confirm');
    var msg = document.getElementById('pw-mismatch');
    var form = document.getElementById('user-form');

    function validate() {
        if (confirm.value && pw.value !== confirm.value) {
            msg.style.display = 'block';
            confirm.setAttribute('aria-invalid', 'true');
            return false;
        }
        msg.style.display = 'none';
        confirm.removeAttribute('aria-invalid');
        return true;
    }

    confirm.addEventListener('input', validate);
    pw.addEventListener('input', function() { if (confirm.value) validate(); });

    form.addEventListener('submit', function(e) {
        if (!validate()) { e.preventDefault(); return; }
        if (pw.value === '' && confirm.value === '') return;
        if (pw.value !== confirm.value) { e.preventDefault(); }
    });
})();
