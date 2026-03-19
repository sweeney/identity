// WebAuthn / Passkey ceremony helpers for identity server login pages.
// Used by both admin login and OAuth login templates.

function bufferToBase64url(buf) {
  const bytes = new Uint8Array(buf);
  let str = '';
  for (const b of bytes) str += String.fromCharCode(b);
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlToBuffer(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

// passkeyLogin performs the WebAuthn login ceremony and returns the
// challenge_id needed for server-side verification, or null on failure.
// The caller (admin or OAuth page) decides what to do with the result.
async function passkeyLogin(apiBase, username) {
  // 1. Begin — get challenge from server
  const beginResp = await fetch(apiBase + '/api/v1/webauthn/login/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username: username || undefined }),
  });

  if (!beginResp.ok) {
    const err = await beginResp.json().catch(() => ({}));
    throw new Error(err.message || 'Failed to begin passkey login');
  }

  const beginData = await beginResp.json();
  const challengeId = beginData.challenge_id;
  const options = beginData.publicKey;

  // Decode challenge
  options.challenge = base64urlToBuffer(options.challenge);

  // Decode allowCredentials if present
  if (options.allowCredentials) {
    options.allowCredentials = options.allowCredentials.map(function(c) {
      return Object.assign({}, c, { id: base64urlToBuffer(c.id) });
    });
  }

  // 2. Browser ceremony — user touches biometric
  var assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey: options });
  } catch (err) {
    throw new Error('Passkey authentication was cancelled');
  }

  // 3. Finish — send assertion to server
  const body = {
    id: assertion.id,
    rawId: bufferToBase64url(assertion.rawId),
    type: assertion.type,
    response: {
      authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
      signature: bufferToBase64url(assertion.response.signature),
    },
  };
  if (assertion.response.userHandle) {
    body.response.userHandle = bufferToBase64url(assertion.response.userHandle);
  }

  const finishResp = await fetch(apiBase + '/api/v1/webauthn/login/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Challenge-ID': challengeId,
    },
    body: JSON.stringify(body),
  });

  if (!finishResp.ok) {
    const err = await finishResp.json().catch(() => ({}));
    throw new Error(err.message || 'Passkey authentication failed');
  }

  return finishResp.json();
}
