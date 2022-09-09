# XChaCha20-JS

XChaCha20-Poly1305 implementation in a plain JavaScript.

This library will auto generate random nonce and append it to the encrypted message.

## Usage

### 1. Import library
We can import XChaCha20.js library or XChaCha20.min.js for minified version.
```html
<!DOCTYPE html>
<html>
  <head>
    <title>XChaCha20-JS</title>
    <!-- First we import XChaCha20 library -->
    <script src="XChaCha20.min.js"></script>
  </head>
  <body>
  ...
  </body>
</html>
```

## 2. Encryption
```js
XChaCha20.encrypt(message, secretKey);
```

## 3. Decryption
```js
XChaCha20.decrypt(message, secretKey)
```
