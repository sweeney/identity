// Passkey registration logic for the admin passkeys page.
// Requires webauthn.js to be loaded first.

(function () {
  var btn = document.getElementById('register-btn');
  if (!btn) return;

  if (!window.PublicKeyCredential) {
    document.getElementById('no-webauthn').style.display = '';
    return;
  }

  btn.style.display = '';

  btn.addEventListener('click', function () {
    btn.disabled = true;
    btn.textContent = 'Waiting for passkey...';

    var name = document.getElementById('passkey-name').value.trim();
    var nameParam = name ? '&name=' + encodeURIComponent(name) : '';

    // 1. Begin registration
    fetch('/admin/passkeys/register/begin', {
      method: 'POST',
      credentials: 'same-origin',
    })
      .then(function (resp) {
        if (!resp.ok) throw new Error('Failed to begin registration');
        return resp.json();
      })
      .then(function (data) {
        var challengeId = data.challenge_id;
        var options = data.publicKey;

        // Decode base64url fields
        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map(function (c) {
            return Object.assign({}, c, { id: base64urlToBuffer(c.id) });
          });
        }

        // 2. Browser ceremony
        return navigator.credentials
          .create({ publicKey: options })
          .then(function (credential) {
            // 3. Send attestation to server
            var body = {
              id: credential.id,
              rawId: bufferToBase64url(credential.rawId),
              type: credential.type,
              response: {
                attestationObject: bufferToBase64url(credential.response.attestationObject),
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
              },
            };
            if (credential.response.getTransports) {
              body.transports = credential.response.getTransports();
            }

            return fetch(
              '/admin/passkeys/register/finish?challenge_id=' + challengeId + nameParam,
              {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'same-origin',
              body: JSON.stringify(body),
              }
            );
          });
      })
      .then(function (resp) {
        if (!resp.ok) throw new Error('Registration failed');
        // Reload the page to show the new passkey
        location.reload();
      })
      .catch(function (err) {
        btn.disabled = false;
        btn.textContent = 'Register Passkey';
        alert(err.message || 'Passkey registration failed');
      });
  });
})();
