/**
 * Class representing the XChaCha20 encryption and decryption algorithm.
 * This class provides methods for encoding, encrypting, decrypting, and handling text and keys.
 */
declare class XChaCha20 {
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
	constructor();
	/**
	 * Rotates bits to the left by a given number of positions.
	 *
	 * @param {number} a - The number to rotate.
	 * @param {number} b - The number of positions to rotate.
	 * @returns {number} The result after rotating left.
	 */
	rotateleft: (a: number, b: number) => number;
	/**
	 * Combines four bytes into a 32-bit little-endian integer.
	 *
	 * @param {number} a - The first byte.
	 * @param {number} b - The second byte.
	 * @param {number} c - The third byte.
	 * @param {number} d - The fourth byte.
	 * @returns {number} The resulting 32-bit integer.
	 */
	le32: (a: number, b: number, c: number, d: number) => number;
	/**
	 * Converts a string to an array of numbers based on character codes.
	 *
	 * @param {string} data - The string to convert.
	 * @returns {number[]} The resulting array of numbers.
	 */
	int2(data: string): number[];
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
	Qround(state: Uint32Array, a: number, b: number, c: number, d: number): void;
	/**
	 * Applies the ChaCha20 inner block operation.
	 *
	 * @param {Uint32Array} state - The state to modify.
	 * @returns {void}
	 */
	Inner_Block(state: Uint32Array): void;
	/**
	 * Generates a block for the ChaCha20 encryption function.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number} block_counter - The block counter.
	 * @returns {number[]} The generated block.
	 */
	Chacha20_BlockFunction(key: number[], nonce: number[], block_counter: number): number[];
	/**
	 * Generates a block for the HChaCha20 encryption function.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number[]} nonce - The nonce value.
	 * @returns {number[]} The generated block.
	 */
	HChacha20_BlockFunction(key: number[], nonce: number[]): number[];
	/**
	 * Encrypts plaintext using the ChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number} counter - The block counter.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number[]} plaintext - The plaintext to encrypt.
	 * @returns {void}
	 */
	chacha20_encrypt(key: number[], counter: number, nonce: number[], plaintext: number[]): void;
	/**
	 * Decrypts encrypted text using the ChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number} counter - The block counter.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number[]} eT - The encrypted text.
	 * @returns {void}
	 */
	chacha20_decrypt(key: number[], counter: number, nonce: number[], eT: number[]): void;
	/**
	 * Decrypts a message using the XChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {string} encryptedText - The encrypted text in base64 format.
	 * @returns {void}
	 */
	xchacha20_decrypt(key: number[], encryptedText: string): void;
	/**
	 * Encrypts a message using the XChaCha20 algorithm.
	 *
	 * @param {number[]} key - The encryption key.
	 * @param {number[]} nonce - The nonce value.
	 * @param {number[]} plaintext - The plaintext to encrypt.
	 * @returns {void}
	 */
	xchacha20_encrypt(key: number[], nonce: number[], plaintext: number[]): void;
	/**
	 * Converts an array of numbers representing character codes into a string.
	 *
	 * @param {number[]} data - The array of numbers to convert.
	 * @returns {string} The resulting string.
	 */
	private static convertToText;
	/**
	 * Encodes a given string into its hexadecimal representation.
	 *
	 * @param {string} data - The string to encode.
	 * @returns {any[]} The hexadecimal encoded string as an array of strings.
	 */
	private static hexEncode;
	/**
	 * Encodes a given string into base64 format, supporting Unicode characters.
	 *
	 * @param {string} str - The string to encode.
	 * @returns {string} The base64 encoded string.
	 */
	private static b64EncodeUnicode;
	/**
	 * Decodes a base64 string, supporting Unicode characters.
	 *
	 * @param {string} str - The base64 encoded string.
	 * @returns {string} The decoded string.
	 */
	private static b64DecodeUnicode;
	/**
	 * Generates a random nonce for use with the XChaCha20 algorithm.
	 *
	 * @returns {Uint8Array} A randomly generated nonce.
	 */
	private static randomNonce;
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
	static encrypt(message: string, secretKey: string): string;
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
	static decrypt(message: string, secretKey: string): string;
}

export {
	XChaCha20 as default,
};

export {};
