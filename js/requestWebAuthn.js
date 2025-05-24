//Required urls: requestWebAuthnUrl, verifyWebAuthnRegistrationUrl 

function requestWebAuthn(event) {
  event.preventDefault();
  const form = event.target;
  const formData = new FormData(form);
  const data = Object.fromEntries(formData.entries());

  $.post(requestWebAuthnUrl,
    JSON.stringify(data),
    getWebAuthnCredential,
    'json'
  );
}

async function getWebAuthnCredential(publicKeyOptions) {
  publicKeyOptions.challenge = base64toArrayBuffer(publicKeyOptions.challenge);
  if (publicKeyOptions.allowCredentials) {
    for (let i = 0; i < publicKeyOptions.allowCredentials.length; i++) {
      idArrayBuffer = base64toArrayBuffer(publicKeyOptions.allowCredentials[i].id);
      publicKeyOptions.allowCredentials[i].id = idArrayBuffer;
    }
  }

  const credential = await navigator.credentials.get({
    publicKey: publicKeyOptions
  });

  const credentialData = {
    id: credential.id,
    rawId: arrayBufferToBase64(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: arrayBufferToBase64(credential.response.authenticatorData),
      clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON),
      signature: arrayBufferToBase64(credential.response.signature)
    },
    csrf_token: $('input[name="csrf_token"]').val(),
  };

  sendCredentialToServer(verifyWebAuthnRequestUrl, credentialData);
}
