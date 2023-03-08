# XChaCha20-JS

XChaCha20 implementation in JavaScript (ES6).

This library will auto generate random nonce and append it to the encrypted message.

## Usage

### 1. Download library
```bash
npm i --save @rabbit-company/xchacha20
```

### 2. Import library
```js
import XChaCha20 from "@rabbit-company/xchacha20";
```

### 3. Encryption
```js
XChaCha20.encrypt(message, secretKey);
```

### 4. Decryption
```js
XChaCha20.decrypt(message, secretKey);
```
