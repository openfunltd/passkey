//Required urls: registerWebAuthnUrl, verifyWebAuthnRegistrationUrl

function registerWebAuthn(event) {
    event.preventDefault();
    const form = event.target;
    const formData = new FormData(form);
    const data = Object.fromEntries(formData.entries());

    $.post(registerWebAuthnUrl,
      JSON.stringify(data),  
      function(publicKeyOptions) {
        createWebAuthnCredential(publicKeyOptions);
      },
      'json'
    )
}

async function createWebAuthnCredential(publicKeyOptions) {
  publicKeyOptions.challenge = base64toArrayBuffer(publicKeyOptions.challenge);
  publicKeyOptions.user.id = base64toArrayBuffer(publicKeyOptions.user.id);

  //create credentials using WebAuthn API
  const credential = await navigator.credentials.create({
    publicKey: publicKeyOptions
  });

  //prepare credentialData for sending to the server
  const credentialData = {
    id: credential.id,
    rawId: arrayBufferToBase64(credential.rawId),
    type: credential.type,
    response: {
      attestationObject: arrayBufferToBase64(credential.response.attestationObject),
      clientDataJSON: arrayBufferToBase64(credential.response.clientDataJSON)
    },
    csrf_token: $('input[name="csrf_token"]').val(),
  };

  //send credentail to the server
  sendCredentialToServer(verifyWebAuthnRegistrationUrl, credentialData);
}
