declare class XChaCha20 {
	keystream: number[];
	encryptedText: number[];
	plaintext: number[];
	nonce: number[];
	constructor();
	rotateleft: (a: number, b: number) => number;
	le32: (a: number, b: number, c: number, d: number) => number;
	int2(data: string): number[];
	Qround(state: Uint32Array, a: number, b: number, c: number, d: number): void;
	Inner_Block(state: Uint32Array): void;
	Chacha20_BlockFunction(key: number[], nonce: number[], block_counter: number): number[];
	HChacha20_BlockFunction(key: number[], nonce: number[]): number[];
	chacha20_encrypt(key: number[], counter: number, nonce: number[], plaintext: number[]): void;
	chacha20_decrypt(key: number[], counter: number, nonce: number[], eT: number[]): void;
	xchacha20_decrypt(key: number[], encryptedText: string): void;
	xchacha20_encrypt(key: number[], nonce: number[], plaintext: number[]): void;
	private static convertToText;
	private static hexEncode;
	private static b64EncodeUnicode;
	private static b64DecodeUnicode;
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
