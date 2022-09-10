# XChaCha20-JS

XChaCha20-Poly1305 implementation in a plain JavaScript.

This library will auto generate random nonce and append it to the encrypted message.

## Usage

### 1. Import library
```html
<script src="XChaCha20.min.js"></script>
```

### 2. Encryption
```js
XChaCha20.encrypt(message, secretKey);
```

### 3. Decryption
```js
XChaCha20.decrypt(message, secretKey)
```
