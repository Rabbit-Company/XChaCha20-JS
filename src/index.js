import XChaCha20 from "./xchacha20.js";

// Encrypt text
document.getElementById("btn-encrypt").addEventListener('click', () => {
	let textPlan = document.getElementById("text-1").value;
	let secretKey = document.getElementById("secretKey").value;

	document.getElementById("text-2").value = XChaCha20.encrypt(textPlan, secretKey);
});

// Decrypt text
document.getElementById("btn-decrypt").addEventListener('click', () => {
	let textEncrypted = document.getElementById("text-1").value;
	let secretKey = document.getElementById("secretKey").value;

	document.getElementById("text-2").value = XChaCha20.decrypt(textEncrypted, secretKey);
});

function calcT(timer){
	return Date.now() - timer;
}

// Performance test
document.getElementById("btn-start").addEventListener("click", () => {
	let amount = document.getElementById("amount").value;
	if(amount < 1) amount = 1;
	if(amount > 100000) amount = 100000;
	let perf = document.getElementById("perf");
	let messages = [];
	let encryptedMessages = [];
	let secretKey = btoa(XChaCha20.convertToText(XChaCha20.randomNonce())) + btoa(XChaCha20.convertToText(XChaCha20.randomNonce()));
	let timerStart = Date.now();

	perf.innerText = "1. Performance test has started.\n";

	let timer = Date.now();
	for(let i = 0; i < amount; i++){
		messages[i] = btoa(XChaCha20.convertToText(XChaCha20.randomNonce()));
	}
	perf.innerText += "2. " + amount + " random messages generated in " + calcT(timer) + " milliseconds.\n";

	timer = Date.now();
	for(let i = 0; i < amount; i++){
		encryptedMessages[i] = XChaCha20.encrypt(messages[i], secretKey);
	}
	perf.innerText += "3. " + amount + " random messages encrypted in " + calcT(timer) + " milliseconds.\n";

	timer = Date.now();
	for(let i = 0; i < amount; i++){
		XChaCha20.decrypt(encryptedMessages[i], secretKey);
	}
	perf.innerText += "4. " + amount + " random messages decrypted in " + calcT(timer) + " milliseconds.\n";

	perf.innerText += "5. Performance test has completed in " + calcT(timerStart) + " milliseconds.\n";
});