// Passkey login button logic for admin and OAuth login pages.
// Requires webauthn.js to be loaded first.

(function () {
  var btn = document.getElementById('passkey-btn');
  if (!btn || !window.PublicKeyCredential) return;

  // Show the passkey UI
  document.getElementById('passkey-divider').classList.remove('passkey-hidden');
  btn.classList.remove('passkey-hidden');

  // Tell the server the browser supports WebAuthn (for passkey registration prompt)
  var form = document.getElementById('login-form');
  if (form) {
    var flag = document.createElement('input');
    flag.type = 'hidden';
    flag.name = 'webauthn_supported';
    flag.value = '1';
    form.appendChild(flag);
  }

  btn.addEventListener('click', function () {
    btn.disabled = true;
    btn.textContent = 'Waiting for passkey...';

    var username = document.getElementById('login-username').value || '';

    passkeyLogin(location.origin, username)
      .then(function (tokens) {
        var clientId = btn.getAttribute('data-client-id');

        if (clientId) {
          // OAuth flow — post to passkey authorize endpoint, get redirect URL as JSON
          var body = new URLSearchParams({
            access_token: tokens.access_token,
            client_id: clientId,
            redirect_uri: btn.getAttribute('data-redirect-uri') || '',
            state: btn.getAttribute('data-state') || '',
            code_challenge: btn.getAttribute('data-code-challenge') || '',
          });

          return fetch('/oauth/authorize/passkey', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/x-www-form-urlencoded',
              'Accept': 'application/json',
            },
            body: body,
          }).then(function (resp) {
            if (!resp.ok) {
              return resp.json().catch(function () { return {}; }).then(function (err) {
                throw new Error(err.message || 'Authorization failed');
              });
            }
            return resp.json();
          }).then(function (data) {
            if (!/^https?:\/\//i.test(data.redirect_uri)) {
              throw new Error('Invalid redirect URI scheme');
            }
            window.location.href = data.redirect_uri;
          });
        } else {
          // Admin flow — post access_token, follow redirect
          var body = new URLSearchParams({ access_token: tokens.access_token });

          fetch('/admin/login/passkey', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: body,
            redirect: 'follow',
            credentials: 'same-origin',
          }).then(function (resp) {
            // The server sets the session cookie and redirects to /admin/
            window.location.href = '/admin/';
          });
        }
      })
      .catch(function (err) {
        btn.disabled = false;
        btn.textContent = 'Sign in with passkey';

        var flash = document.querySelector('.flash-error');
        if (!flash) {
          flash = document.createElement('p');
          flash.className = 'flash-error';
          var loginForm = document.getElementById('login-form');
          loginForm.parentNode.insertBefore(flash, loginForm);
        }
        flash.textContent = err.message;
      });
  });
})();
