/**
 * Class representing the XChaCha20 encryption and decryption algorithm.
 * This class provides methods for encoding, encrypting, decrypting, and handling text and keys.
 */
export default class XChaCha20 {
	/**
	 * The keystream generated during encryption/decryption.
	 * @type {number[]}
	 */
	keystream: number[];
	/**
	 * The encrypted text as an array of character codes.
	 * @type {number[]}
	 */
	encryptedText: number[];
	/**
	 * The decrypted plain text as an array of character codes.
	 * @type {number[]}
	 */
	plaintext: number[];
	/**
	 * The nonce used in the encryption process.
	 * @type {number[]}
	 */
	nonce: number[];

	/**
	 * Constructs a new XChaCha20 instance.
	 */
	constructor() {
		this.keystream = [];
		this.encryptedText = [];
		this.plaintext = [];
		this.nonce = [];
	}

	/**
	 * Rotates bits to the left by a given number of positions.
	 *
	 * @param {number} a - The number to rotate.
	 * @param {number} b - The number of positions to rotate.
	 * @returns {number} The result after rotating left.
	 */
	rotateleft = (a: number, b: number): number => {
		return (a << b) | (a >>> (32 - b));
	};

	/**
	 * Combines four bytes into a 32-bit little-endian integer.
	 *
	 * @param {number} a - The first byte.
	 * @param {number} b - The second byte.
	 * @param {number} c - The third byte.
	 * @param {number} d - The fourth byte.
	 * @returns {number} The resulting 32-bit integer.
	 */
	le32 = (a: number, b: number, c: number, d: number): number => {
		return (a ^ (b << 8) ^ (c << 16) ^ (d << 24)) >>> 0;
	};

	/**
	 * Converts a string to an array of numbers based on character codes.
	 *
	 * @param {string} data - The string to convert.
	 * @returns {number[]} The resulting array of numbers.
	 */
	int2(data: string): number[] {
		let result: number[] = [];
		for (let i = 0; i < data.length; i++) {
			const hex = data.charCodeAt(i).toString(16);
			result.push(parseInt(hex, 16));
		}
		return result;
	}

	/**
	 * Performs the quarter round operation in the ChaCha20 algorithm.
	 *
	 * @param {Uint32Array} state - The state to modify.
	 * @param {number} a - Index of the first element in the quarter round.
	 * @param {number} b - Index of the second element in the quarter round.
	 * @param {number} c - Index of the third element in the quarter round.
	 * @param {number} d - Index of the fourth element in the quarter round.
	 * @returns {void}
	 */
	Qround(state: Uint32Array, a: number, b: number, c: number, d: number): void {
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

	/**
	 * Applies the ChaCha20 inner block operation.
	 *
	 * @param {Uint32Array} state - The state to modify.
	 * @returns {void}
	 */
	Inner_Block(state: Uint32Array): void {
		// column_QuarterRounds
		this.Qround(state, 0, 4, 8, 12);
		this.Qround(state, 1, 5, 9, 13);
		this.Qround(state, 2, 6, 10, 14);
		this.Qround(state, 3, 7, 11, 15);
		// diagonal_QuarterRounds
		this.Qround(state, 0, 5, 10, 15);
		this.Qround(state, 1, 6, 11, 12);
		this.Qround(state, 2, 7, 8, 13);
		this.Qround(state, 3, 4, 9, 14);
	}

	/**
	 * Generates a block for the ChaCha20 encryption function.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number} block_counter - The block counter.
	 * @returns {number[]} The generated block.
	 */
	Chacha20_BlockFunction(key: number[], nonce: number[], block_counter: number): number[] {
		let state: number[] = [];
		// Constant
		state[0] = 0x61707865;
		state[1] = 0x3320646e;
		state[2] = 0x79622d32;
		state[3] = 0x6b206574;
		// Key
		state[4] = this.le32(key[0], key[1], key[2], key[3]);
		state[5] = this.le32(key[4], key[5], key[6], key[7]);
		state[6] = this.le32(key[8], 9, key[10], key[11]);
		state[7] = this.le32(key[12], key[13], key[14], key[15]);
		state[8] = this.le32(key[16], key[17], 18, key[19]);
		state[9] = this.le32(key[20], key[21], 22, key[23]);
		state[10] = this.le32(key[24], key[25], key[26], key[27]);
		state[11] = this.le32(key[28], key[29], key[30], key[31]);
		// Counter
		state[12] = block_counter;
		// Nonce
		state[13] = this.le32(nonce[0], nonce[1], nonce[2], nonce[3]);
		state[14] = this.le32(nonce[4], nonce[5], nonce[6], nonce[7]);
		state[15] = this.le32(nonce[8], nonce[9], nonce[10], nonce[11]);

		let temp = new Uint32Array(state.slice());
		for (let i = 1; i <= 10; i++) {
			this.Inner_Block(temp);
		}

		let Serialized_Block: number[] = [];
		for (let i = 0, i2 = 0; i < 16; i++) {
			state[i] += temp[i];

			Serialized_Block[i2++] = state[i] & 0xff;
			Serialized_Block[i2++] = (state[i] >>> 8) & 0xff;
			Serialized_Block[i2++] = (state[i] >>> 16) & 0xff;
			Serialized_Block[i2++] = (state[i] >>> 24) & 0xff;
		}
		return Serialized_Block;
	}

	/**
	 * Generates a block for the HChaCha20 encryption function.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number[]} nonce - The nonce value.
	 * @returns {number[]} The generated block.
	 */
	HChacha20_BlockFunction(key: number[], nonce: number[]): number[] {
		let state: number[] = [];
		// Constant
		state[0] = 0x61707865;
		state[1] = 0x3320646e;
		state[2] = 0x79622d32;
		state[3] = 0x6b206574;
		// Key
		state[4] = this.le32(key[0], key[1], key[2], key[3]);
		state[5] = this.le32(key[4], key[5], key[6], key[7]);
		state[6] = this.le32(key[8], 9, key[10], key[11]);
		state[7] = this.le32(key[12], key[13], key[14], key[15]);
		state[8] = this.le32(key[16], key[17], 18, key[19]);
		state[9] = this.le32(key[20], key[21], 22, key[23]);
		state[10] = this.le32(key[24], key[25], key[26], key[27]);
		state[11] = this.le32(key[28], key[29], key[30], key[31]);

		// Nonce
		state[12] = this.le32(nonce[0], nonce[1], nonce[2], nonce[3]);
		state[13] = this.le32(nonce[4], nonce[5], nonce[6], nonce[7]);
		state[14] = this.le32(nonce[8], nonce[9], nonce[10], nonce[11]);
		state[15] = this.le32(nonce[12], nonce[13], nonce[14], nonce[15]);

		let temp = new Uint32Array(state.slice());
		for (let i = 1; i <= 10; i++) {
			this.Inner_Block(temp);
		}
		let B1 = temp.slice(0, 4);
		let B2 = temp.slice(12, 16);

		let B = new Uint32Array(B1.length + B2.length);
		B.set(B1);
		B.set(B2, B1.length);

		let Serialized_Block: number[] = [];
		for (let i = 0, i2 = 0; i < 8; i++) {
			Serialized_Block[i2++] = B[i] & 0xff;
			Serialized_Block[i2++] = (B[i] >>> 8) & 0xff;
			Serialized_Block[i2++] = (B[i] >>> 16) & 0xff;
			Serialized_Block[i2++] = (B[i] >>> 24) & 0xff;
		}
		return Serialized_Block;
	}

	/**
	 * Encrypts plaintext using the ChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number} counter - The block counter.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number[]} plaintext - The plaintext to encrypt.
	 * @returns {void}
	 */
	chacha20_encrypt(key: number[], counter: number, nonce: number[], plaintext: number[]): void {
		let keystream: number[] = [];
		keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
		let pos = 0;
		for (let i = 0; i < plaintext.length; i++) {
			if (pos === 64) {
				counter++;
				keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
				pos = 0;
			}
			plaintext[i] = parseInt(plaintext[i].toString(), 16);
			pos++;
		}

		let cipherText: number[] = [];
		for (let i = 0; i < plaintext.length; i++) {
			cipherText[i] = plaintext[i] ^ keystream[i];
		}
		this.keystream = keystream;
		this.encryptedText = cipherText;
	}

	/**
	 * Decrypts encrypted text using the ChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number} counter - The block counter.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number[]} eT - The encrypted text.
	 * @returns {void}
	 */
	chacha20_decrypt(key: number[], counter: number, nonce: number[], eT: number[]): void {
		let keystream: number[] = [];
		keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
		let pos = 0;
		for (let i = 0; i < eT.length; i++) {
			if (pos === 64) {
				counter++;
				keystream.push(...this.Chacha20_BlockFunction(key, nonce, counter));
				pos = 0;
			}
			pos++;
		}

		let pT: number[] = [];
		for (let i = 0; i < this.encryptedText.length; i++) {
			pT[i] = this.encryptedText[i] ^ keystream[i];
		}
		this.plaintext = pT;
	}

	/**
	 * Decrypts a message using the XChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {string} encryptedText - The encrypted text in base64 format.
	 * @returns {void}
	 */
	xchacha20_decrypt(key: number[], encryptedText: string): void {
		this.encryptedText = this.int2(XChaCha20.b64DecodeUnicode(encryptedText));
		let nonce = this.encryptedText.slice(-24);
		this.encryptedText = this.encryptedText.slice(0, -24);

		let subkey = this.HChacha20_BlockFunction(key, nonce.slice(0, 16));
		let chacha20_nonce = [0x00, 0x00, 0x00, 0x00];
		chacha20_nonce.push(...nonce.slice(16, 24));
		this.chacha20_decrypt(subkey, 0, chacha20_nonce, this.encryptedText);
	}

	/**
	 * Encrypts a message using the XChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number[]} plaintext - The plaintext to encrypt.
	 * @returns {void}
	 */
	xchacha20_encrypt(key: number[], nonce: number[], plaintext: number[]): void {
		let subkey = this.HChacha20_BlockFunction(key, nonce.slice(0, 16));
		let chacha20_nonce = [0x00, 0x00, 0x00, 0x00];
		chacha20_nonce.push(...nonce.slice(16, 24));
		this.chacha20_encrypt(subkey, 0, chacha20_nonce, plaintext);
	}

	/**
	 * Converts an array of numbers representing character codes into a string.
	 *
	 * @param {number[]} data - The array of numbers to convert.
	 * @returns {string} The resulting string.
	 */
	private static convertToText(data: number[]): string {
		let text = "";
		for (let i = 0; i < data.length; i++) {
			text += String.fromCharCode(data[i]);
		}
		return text;
	}

	/**
	 * Encodes a given string into its hexadecimal representation.
	 *
	 * @param {string} data - The string to encode.
	 * @returns {any[]} The hexadecimal encoded string as an array of strings.
	 */
	private static hexEncode(data: string): any[] {
		let result: string[] = [];
		for (let i = 0; i < data.length; i++) {
			result.push(data.charCodeAt(i).toString(16));
		}
		return result;
	}

	/**
	 * Encodes a given string into base64 format, supporting Unicode characters.
	 *
	 * @param {string} str - The string to encode.
	 * @returns {string} The base64 encoded string.
	 */
	private static b64EncodeUnicode(str: string): string {
		return btoa(
			encodeURIComponent(str).replace(/%([0-9A-F]{2})/g, function toSolidBytes(match, p1) {
				return String.fromCharCode(Number("0x" + p1));
			})
		);
	}

	/**
	 * Decodes a base64 string, supporting Unicode characters.
	 *
	 * @param {string} str - The base64 encoded string.
	 * @returns {string} The decoded string.
	 */
	private static b64DecodeUnicode(str: string): string {
		return decodeURIComponent(
			atob(str)
				.split("")
				.map(function (c) {
					return "%" + ("00" + c.charCodeAt(0).toString(16)).slice(-2);
				})
				.join("")
		);
	}

	/**
	 * Generates a random nonce for use with the XChaCha20 algorithm.
	 *
	 * @returns {Uint8Array} A randomly generated nonce.
	 */
	private static randomNonce(): Uint8Array {
		let rand_n = new Uint8Array(24);
		globalThis.crypto.getRandomValues(rand_n);
		return rand_n;
	}

	/**
	 * Encrypts a given message using the XChaCha20 encryption algorithm.
	 *
	 * @param {string} message - The plain text message that needs to be encrypted.
	 * @param {string} secretKey - The secret key used for encryption. This should be a secure key.
	 * @returns {string} The encrypted message, encoded in base64 format.
	 *
	 * @example
	 * const message = "Hello World!";
	 * const secretKey = "shXiepgJCYF1lTvGzdpRxgrNcvd@6y";
	 *
	 * XChaCha20.encrypt(message, secretKey);
	 */
	static encrypt(message: string, secretKey: string): string {
		const hexMessage = XChaCha20.hexEncode(message);
		const hexSecretKey = XChaCha20.hexEncode(secretKey);
		const nonce = XChaCha20.randomNonce();

		const xchacha = new XChaCha20();
		xchacha.xchacha20_encrypt(hexSecretKey, Array.from(nonce), hexMessage);
		xchacha.encryptedText.push(...Array.from(nonce));

		return XChaCha20.b64EncodeUnicode(XChaCha20.convertToText(xchacha.encryptedText));
	}

	/**
	 * Decrypts a given encrypted message using the XChaCha20 decryption algorithm.
	 *
	 * @param {string} message - The encrypted message in base64 format that needs to be decrypted.
	 * @param {string} secretKey - The secret key used for decryption. It should match the key used for encryption.
	 * @returns {string} The decrypted plain text message.
	 *
	 * @example
	 * const encryptedMessage = "JWTChRvDsMOnTcK4KCU+wpzCkF85wpgGeMKnDio8woHDlsOdJ8OKZSzDiinCv8O4aiDCrFN7K8KQQ8OkwowS";
	 * const secretKey = "shXiepgJCYF1lTvGzdpRxgrNcvd@6y";
	 *
	 * XChaCha20.decrypt(encryptedMessage, secretKey);
	 */
	static decrypt(message: string, secretKey: string): string {
		const hexSecretKey = XChaCha20.hexEncode(secretKey);

		let d1 = new XChaCha20();
		d1.xchacha20_decrypt(hexSecretKey, message);

		return XChaCha20.convertToText(d1.plaintext);
	}
}
