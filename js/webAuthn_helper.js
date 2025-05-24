function base64toArrayBuffer(base64Url) {
  //base64Url to base64
  let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  const padding = '='.repeat((4 - base64.length % 4) % 4);
  base64 = base64 + padding;

  //convert to ArrayBuffter
  const binaryString = window.atob(base64);
  const arr = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    arr[i] = binaryString.charCodeAt(i);
  }

  return arr;
}

function arrayBufferToBase64(arrayBuffer) {
  //convert ArrayBuffer to binary string
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }

  //convert binary string to base64
  let base64 = window.btoa(binary);

  //base64 to base64Url
  base64 = base64.replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');

  return base64;
}

function sendCredentialToServer(url, credentialData) {
  $.post({
    url: url,
    data: JSON.stringify(credentialData),
    contentType: 'application/json',
    dataType: 'json'
  })
  .done(function (res) {
    if (res.success) {
      alert(res.message);
      window.location.href = "/";
    } else {
      alert('error: ' + (res.error || 'unknown error'));
      //TODO Add redirect to res.next
    }
  })
}
