# passkey

<img src="https://github.com/user-attachments/assets/41a9d902-89e4-4fb3-ba55-845ff79ba144" height="150">

A simplified application-level interface for handling complex WebAuthn functionality, built on top of the webauthn_framework library.

Ready for being used in mini-engine

## Install

1. Install `web-auth/webauthn-lib: 5.1` via
```
composer install
```
2. Move `Passkey.php` into your libraries
```
mv Passkey.php /path/to/your-project/libraries/
```

3. Move js files into your js diectory
```
mv js/* /path/to/your-project/static/js/
```

4. Provide 4 endpoints to send POST request to server via javascript
```
requestWebAuthnUrl; //example: /auth/requestWebAuthn
verifyWebAuthnRegistrationUrl;
registerWebAuthnUrl;
verifyWebAuthnRegistrationUrl;
```

## TODO
Documentation to explain function input/output in `Passkey.php`
