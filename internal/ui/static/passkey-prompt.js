// Passkey registration prompt shown after password login.
// Requires webauthn.js to be loaded first.

(function () {
  var btn = document.getElementById('register-btn');
  var status = document.getElementById('register-status');
  if (!btn) return;

  if (!window.PublicKeyCredential) {
    // Browser doesn't support passkeys — just show the skip link
    document.getElementById('register-section').style.display = 'none';
    return;
  }

  btn.addEventListener('click', function () {
    btn.disabled = true;
    btn.textContent = 'Waiting for passkey...';
    status.textContent = '';

    var section = document.getElementById('register-section');
    var beginUrl = section.getAttribute('data-begin-url');
    var finishUrl = section.getAttribute('data-finish-url');

    var name = document.getElementById('passkey-name').value.trim();

    fetch(beginUrl, {
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

        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        if (options.excludeCredentials) {
          options.excludeCredentials = options.excludeCredentials.map(function (c) {
            return Object.assign({}, c, { id: base64urlToBuffer(c.id) });
          });
        }

        return navigator.credentials
          .create({ publicKey: options })
          .then(function (credential) {
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

            var finishHeaders = {
              'Content-Type': 'application/json',
              'X-Challenge-ID': challengeId,
            };
            if (name) {
              finishHeaders['X-Passkey-Name'] = name;
            }

            return fetch(
              finishUrl,
              {
                method: 'POST',
                headers: finishHeaders,
                credentials: 'same-origin',
                body: JSON.stringify(body),
              }
            );
          });
      })
      .then(function (resp) {
        if (!resp.ok) throw new Error('Registration failed');

        // Success — follow the skip link to continue to the original destination
        status.textContent = 'Passkey registered!';
        btn.textContent = 'Done';

        var skip = document.getElementById('skip-link');
        if (skip) {
          setTimeout(function () {
            window.location.href = skip.href;
          }, 800);
        }
      })
      .catch(function (err) {
        btn.disabled = false;
        btn.textContent = 'Set up passkey';
        status.textContent = err.message || 'Passkey registration failed';
        status.className = 'flash-error';
      });
  });
})();
