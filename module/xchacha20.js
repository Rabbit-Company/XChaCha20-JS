// src/xchacha20.ts
class XChaCha20 {
  keystream;
  encryptedText;
  plaintext;
  nonce;
  constructor() {
    this.keystream = [];
    this.encryptedText = [];
    this.plaintext = [];
    this.nonce = [];
  }
  rotateleft = (a, b) => {
    return a << b | a >>> 32 - b;
  };
  le32 = (a, b, c, d) => {
    return (a ^ b << 8 ^ c << 16 ^ d << 24) >>> 0;
  };
  int2(data) {
    let result = [];
    for (let i = 0;i < data.length; i++) {
      const hex = data.charCodeAt(i).toString(16);
      result.push(parseInt(hex, 16));
    }
    return result;
  }
  Qround(state, a, b, c, d) {
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = this.rotateleft(state[d], 16);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = this.rotateleft(state[b], 12);
    state[a] += state[b];
    state[d] ^= state[a];
    state[d] = this.rotateleft(state[d], 8);
    state[c] += state[d];
    state[b] ^= state[c];
    state[b] = this.rotateleft(state[b], 7);
    state[a] >>>= 0;
    state[b] >>>= 0;
    state[c] >>>= 0;
    state[d] >>>= 0;
  }
  Inner_Block(state) {
    this.Qround(state, 0, 4, 8, 12);
    this.Qround(state, 1, 5, 9, 13);
    this.Qround(state, 2, 6, 10, 14);
    this.Qround(state, 3, 7, 11, 15);
    this.Qround(state, 0, 5, 10, 15);
    this.Qround(state, 1, 6, 11, 12);
    this.Qround(state, 2, 7, 8, 13);
    this.Qround(state, 3, 4, 9, 14);
  }
  Chacha20_BlockFunction(key, nonce, block_counter) {
    let state = [];
    state[0] = 1634760805;
    state[1] = 857760878;
    state[2] = 2036477234;
    state[3] = 1797285236;
    state[4] = this.le32(key[0], key[1], key[2], key[3]);
    state[5] = this.le32(key[4], key[5], key[6], key[7]);
    state[6] = this.le32(key[8], 9, key[10], key[11]);
    state[7] = this.le32(key[12], key[13], key[14], key[15]);
    state[8] = this.le32(key[16], key[17], 18, key[19]);
    state[9] = this.le32(key[20], key[21], 22, key[23]);
    state[10] = this.le32(key[24], key[25], key[26], key[27]);
    state[11] = this.le32(key[28], key[29], key[30], key[31]);
    state[12] = block_counter;
    state[13] = this.le32(nonce[0], nonce[1], nonce[2], nonce[3]);
    state[14] = this.le32(nonce[4], nonce[5], nonce[6], nonce[7]);
    state[15] = this.le32(nonce[8], nonce[9], nonce[10], nonce[11]);
    let temp = new Uint32Array(state.slice());
    for (let i = 1;i <= 10; i++) {
      this.Inner_Block(temp);
    }
    let Serialized_Block = [];
    for (let i = 0, i2 = 0;i < 16; i++) {
      state[i] += temp[i];
      Serialized_Block[i2++] = state[i] & 255;
      Serialized_Block[i2++] = state[i] >>> 8 & 255;
      Serialized_Block[i2++] = state[i] >>> 16 & 255;
      Serialized_Block[i2++] = state[i] >>> 24 & 255;
    }
    return Serialized_Block;
  }
  HChacha20_BlockFunction(key, nonce) {
    let state = [];
    state[0] = 1634760805;
    state[1] = 857760878;
    state[2] = 2036477234;
    state[3] = 1797285236;
    state[4] = this.le32(key[0], key[1], key[2], key[3]);
    state[5] = this.le32(key[4], key[5], key[6], key[7]);
    state[6] = this.le32(key[8], 9, key[10], key[11]);
    state[7] = this.le32(key[12], key[13], key[14], key[15]);
    state[8] = this.le32(key[16], key[17], 18, key[19]);
    state[9] = this.le32(key[20], key[21], 22, key[23]);
    state[10] = this.le32(key[24], key[25], key[26], key[27]);
    state[11] = this.le32(key[28], key[29], key[30], key[31]);
    state[12] = this.le32(nonce[0], nonce[1], nonce[2], nonce[3]);
    state[13] = this.le32(nonce[4], nonce[5], nonce[6], nonce[7]);
    state[14] = this.le32(nonce[8], nonce[9], nonce[10], nonce[11]);
    state[15] = this.le32(nonce[12], nonce[13], nonce[14], nonce[15]);
    let temp = new Uint32Array(state.slice());
    for (let i = 1;i <= 10; i++) {
      this.Inner_Block(temp);
    }
    let B1 = temp.slice(0, 4);
    let B2 = temp.slice(12, 16);
    let B = new Uint32Array(B1.length + B2.length);
    B.set(B1);
    B.set(B2, B1.length);
    let Serialized_Block = [];
    for (let i = 0, i2 = 0;i < 8; i++) {
      Serialized_Block[i2++] = B[i] & 255;
      Serialized_Block[i2++] = B[i] >>> 8 & 255;
      Serialized_Block[i2++] = B[i] >>> 16 & 255;
      Serialized_Block[i2++] = B[i] >>> 24 & 255;
    }
    return Serialized_Block;
  }
  chacha20_encrypt(key, counter, nonce, plaintext) {
    let keystream = [];
    keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
    let pos = 0;
    for (let i = 0;i < plaintext.length; i++) {
      if (pos === 64) {
        counter++;
        keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
        pos = 0;
      }
      plaintext[i] = parseInt(plaintext[i].toString(), 16);
      pos++;
    }
    let cipherText = [];
    for (let i = 0;i < plaintext.length; i++) {
      cipherText[i] = plaintext[i] ^ keystream[i];
    }
    this.keystream = keystream;
    this.encryptedText = cipherText;
  }
  chacha20_decrypt(key, counter, nonce, eT) {
    let keystream = [];
    keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
    let pos = 0;
    for (let i = 0;i < eT.length; i++) {
      if (pos === 64) {
        counter++;
        keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
        pos = 0;
      }
      pos++;
    }
    let pT = [];
    for (let i = 0;i < this.encryptedText.length; i++) {
      pT[i] = this.encryptedText[i] ^ keystream[i];
    }
    this.plaintext = pT;
  }
  xchacha20_decrypt(key, encryptedText) {
    this.encryptedText = this.int2(XChaCha20.b64DecodeUnicode(encryptedText));
    let nonce = this.encryptedText.slice(-24);
    this.encryptedText = this.encryptedText.slice(0, -24);
    let subkey = this.HChacha20_BlockFunction(key, nonce.slice(0, 16));
    let chacha20_nonce = [0, 0, 0, 0];
    chacha20_nonce.push(...nonce.slice(16, 24));
    this.chacha20_decrypt(subkey, 0, chacha20_nonce, this.encryptedText);
  }
  xchacha20_encrypt(key, nonce, plaintext) {
    let subkey = this.HChacha20_BlockFunction(key, nonce.slice(0, 16));
    let chacha20_nonce = [0, 0, 0, 0];
    chacha20_nonce.push(...nonce.slice(16, 24));
    this.chacha20_encrypt(subkey, 0, chacha20_nonce, plaintext);
  }
  static convertToText(data) {
    let text = "";
    for (let i = 0;i < data.length; i++) {
      text += String.fromCharCode(data[i]);
    }
    return text;
  }
  static hexEncode(data) {
    let result = [];
    for (let i = 0;i < data.length; i++) {
      result.push(data.charCodeAt(i).toString(16));
    }
    return result;
  }
  static b64EncodeUnicode(str) {
    return btoa(encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function toSolidBytes(match, p1) {
      return String.fromCharCode(Number("0x" + p1));
    }));
  }
  static b64DecodeUnicode(str) {
    return decodeURIComponent(atob(str).split("").map(function(c) {
      return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
    }).join(""));
  }
  static randomNonce() {
    let rand_n = new Uint8Array(24);
    crypto.getRandomValues(rand_n);
    return rand_n;
  }
  static encrypt(message, secretKey) {
    const hexMessage = XChaCha20.hexEncode(message);
    const hexSecretKey = XChaCha20.hexEncode(secretKey);
    const nonce = XChaCha20.randomNonce();
    const xchacha = new XChaCha20;
    xchacha.xchacha20_encrypt(hexSecretKey, Array.from(nonce), hexMessage);
    xchacha.encryptedText.push(...Array.from(nonce));
    return XChaCha20.b64EncodeUnicode(XChaCha20.convertToText(xchacha.encryptedText));
  }
  static decrypt(message, secretKey) {
    const hexSecretKey = XChaCha20.hexEncode(secretKey);
    let d1 = new XChaCha20;
    d1.xchacha20_decrypt(hexSecretKey, message);
    return XChaCha20.convertToText(d1.plaintext);
  }
}
export {
  XChaCha20 as default
};
