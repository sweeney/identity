// Passkey approval logic for the device authorization page (/oauth/device).
// Completes a WebAuthn login ceremony, then approves the device for that user.
// Requires webauthn.js to be loaded first.

(function () {
  var btn = document.getElementById('passkey-btn');
  if (!btn || !window.PublicKeyCredential) return;

  // Tell the server the browser supports WebAuthn so it can offer to register a
  // passkey after a password approval (mirrors passkey-login.js on the login
  // pages). The flag rides on the username/password approve form.
  var approveForm = document.getElementById('device-approve-form');
  if (approveForm && !approveForm.querySelector('input[name="webauthn_supported"]')) {
    var flag = document.createElement('input');
    flag.type = 'hidden';
    flag.name = 'webauthn_supported';
    flag.value = '1';
    approveForm.appendChild(flag);
  }

  // Reveal the passkey UI now that we know the browser supports it.
  var divider = document.getElementById('passkey-divider');
  if (divider) divider.classList.remove('passkey-hidden');
  btn.classList.remove('passkey-hidden');

  var userCode = btn.getAttribute('data-user-code') || '';

  function showError(message) {
    btn.disabled = false;
    btn.textContent = 'Sign in with passkey';
    var flash = document.querySelector('.flash-error');
    if (!flash) {
      flash = document.createElement('p');
      flash.className = 'flash-error';
      var box = document.querySelector('.login-box');
      box.insertBefore(flash, box.firstChild.nextSibling);
    }
    flash.textContent = message;
  }

  btn.addEventListener('click', function () {
    btn.disabled = true;
    btn.textContent = 'Waiting for passkey...';

    // Usernameless (discoverable credential) login — the user is identified by
    // the passkey itself, so no username field is needed on the device page.
    passkeyLogin(location.origin, '')
      .then(function (tokens) {
        var body = new URLSearchParams({
          access_token: tokens.access_token,
          user_code: userCode,
        });

        return fetch('/oauth/device/passkey', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json',
          },
          body: body,
        }).then(function (resp) {
          if (!resp.ok) {
            return resp.json().catch(function () { return {}; }).then(function (err) {
              throw new Error(err.message || 'Could not approve the device.');
            });
          }
          return resp.json();
        }).then(function () {
          var box = document.querySelector('.login-box');
          box.innerHTML =
            '<h1>Device approved</h1>' +
            '<p>Your device is now signed in. You can close this page — it will connect automatically.</p>';
        });
      })
      .catch(function (err) {
        showError(err.message);
      });
  });
})();
