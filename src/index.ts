import XChaCha20 from "./xchacha20";

const text1Input = document.getElementById("text-1") as HTMLInputElement;
const text2Input = document.getElementById("text-2") as HTMLInputElement;
const secretKeyInput = document.getElementById("secretKey") as HTMLInputElement;
const amountInput = document.getElementById("amount") as HTMLInputElement;

// Encrypt text
document.getElementById("btn-encrypt")?.addEventListener("click", () => {
	let textPlan = text1Input.value;
	let secretKey = secretKeyInput.value;

	text2Input.value = XChaCha20.encrypt(textPlan, secretKey);
});

// Decrypt text
document.getElementById("btn-decrypt")?.addEventListener("click", () => {
	let textEncrypted = text1Input.value;
	let secretKey = secretKeyInput.value;

	text2Input.value = XChaCha20.decrypt(textEncrypted, secretKey);
});

function generateRandomText(length: number) {
	let result = "";
	let charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

	for (let i = 0; i < length; i++) {
		const randomIndex = Math.floor(Math.random() * charset.length);
		result += charset.charAt(randomIndex);
	}

	return result;
}

function calcT(timer: number) {
	return Date.now() - timer;
}

// Performance test
document.getElementById("btn-start")?.addEventListener("click", () => {
	let amount = parseInt(amountInput.value, 10);
	if (amount < 1) amount = 1;
	if (amount > 100000) amount = 100000;
	const perf = document.getElementById("perf");
	if (!perf) return;
	let messages = [];
	let encryptedMessages = [];
	let decryptedMessages = [];
	let secretKey = "lTmnm8G6X1ESDuVf1xnf2t1F4XpUZzZYfodPQQbprsx40k3n9d";
	let timerStart = Date.now();

	perf.innerText = "1. Performance test has started.\n";

	let timer = Date.now();
	for (let i = 0; i < amount; i++) {
		messages[i] = generateRandomText(30);
	}
	perf.innerText += "2. " + amount + " random messages generated in " + calcT(timer) + " milliseconds.\n";

	timer = Date.now();
	for (let i = 0; i < amount; i++) {
		encryptedMessages[i] = XChaCha20.encrypt(messages[i], secretKey);
	}
	perf.innerText += "3. " + amount + " random messages encrypted in " + calcT(timer) + " milliseconds.\n";

	timer = Date.now();
	for (let i = 0; i < amount; i++) {
		decryptedMessages[i] = XChaCha20.decrypt(encryptedMessages[i], secretKey);
	}
	perf.innerText += "4. " + amount + " random messages decrypted in " + calcT(timer) + " milliseconds.\n";

	perf.innerText += "5. Performance test has completed in " + calcT(timerStart) + " milliseconds.\n";
});
