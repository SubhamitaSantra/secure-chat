let rsaKeyPair;
let exportedPublicKey;
const userPublicKeys = {};
let aesKey;
const socket = io();

document.addEventListener('DOMContentLoaded', async () => {
    const usernameInput = document.getElementById('username');
    const messageInput = document.getElementById('message');
    const sendButton = document.getElementById('send');
    const messagesList = document.getElementById('messages');

    // Ask for username
    let enteredName = prompt("Enter your name:");
    if (!enteredName) {
        alert("You must enter a name to join the chat.");
        location.reload();
        return;
    }
    usernameInput.value = enteredName.trim();

    // Generate a random AES key
    aesKey = window.crypto.getRandomValues(new Uint8Array(32));

    // ✅ Call RSA generation AFTER usernameInput is defined
    await generateRSAKeys(usernameInput.value.trim());

    // Send button functionality
    sendButton.addEventListener('click', async () => {
    const username = usernameInput.value.trim();
    const message = messageInput.value.trim();
    const recipient = document.getElementById('recipient').value;

    if (username && message && recipient) {
        const encrypted = await encryptMessage(message, aesKey);

        const recipientPublicKey = userPublicKeys[recipient];
        const encryptedAESKey = await encryptAESKeyWithPublicKey(aesKey, recipientPublicKey);

        socket.emit('chat_message', {
            from: username,
            to: recipient,
            ciphertext: encrypted.ciphertext,
            iv: encrypted.iv,
            encryptedAESKey: Array.from(new Uint8Array(encryptedAESKey))
        });

        messageInput.value = '';
    } else {
        alert("Please enter a message and select a recipient.");
    }
});

    socket.on('chat_message', async (data) => {
    const { from, to, ciphertext, iv, encryptedAESKey } = data;
    const currentUsername = usernameInput.value.trim();
    const now = new Date();
    const time = now.toLocaleTimeString();

    if (to === currentUsername) {
        // I'm the recipient
        try {
            const aesKeyBuffer = await decryptAESKeyWithPrivateKey(
                new Uint8Array(encryptedAESKey),
                rsaKeyPair.privateKey
            );

            const decryptedMessage = await decryptMessage(ciphertext, iv, new Uint8Array(aesKeyBuffer));

            const messageElement = document.createElement('li');
            messageElement.classList.add('message-received');
            messageElement.textContent = `[${time}] ${from} → You: ${decryptedMessage}`;
            messagesList.appendChild(messageElement);
        } catch (error) {
            console.error('Message decryption failed:', error);
        }
    } else if (from === currentUsername) {
    // I'm the sender — decrypt and display the message I sent
    try {
        const decryptedMessage = await decryptMessage(ciphertext, iv, aesKey);

        const messageElement = document.createElement('li');
        messageElement.classList.add('message-sent');
        messageElement.textContent = `[${time}] You → ${to}: ${messageInput.value.trim()}`;
        messagesList.appendChild(messageElement);
    } catch (error) {
        console.error('Sender decryption failed:', error);
    }
}
});


    // When server broadcasts a new user and their public key
socket.on('new_user', (data) => {
    const { username, public_key } = data;

    if (!(username in userPublicKeys)) {
        const keyBytes = new Uint8Array(public_key);
        window.crypto.subtle.importKey(
            "spki",
            keyBytes.buffer,
            {
                name: "RSA-OAEP",
                hash: "SHA-256",
            },
            true,
            ["encrypt"]
        ).then((importedKey) => {
            userPublicKeys[username] = importedKey;
            console.log(`Received and stored public key for ${username}`);

            // Update recipient dropdown
            const option = document.createElement('option');
            option.value = username;
            option.textContent = username;
            document.getElementById('recipient').appendChild(option);
        });
        }
    });
});
socket.on('existing_users', (users) => {
    users.forEach(({ username, public_key }) => {
        if (!(username in userPublicKeys)) {
            const keyBytes = new Uint8Array(public_key);
            window.crypto.subtle.importKey(
                "spki",
                keyBytes.buffer,
                {
                    name: "RSA-OAEP",
                    hash: "SHA-256",
                },
                true,
                ["encrypt"]
            ).then((importedKey) => {
                userPublicKeys[username] = importedKey;
                console.log(`Existing user loaded: ${username}`);

                const option = document.createElement('option');
                option.value = username;
                option.textContent = username;
                document.getElementById('recipient').appendChild(option);
            });
        }
    });
});



// ============ 🔐 ENCRYPTION / DECRYPTION =============

async function generateRSAKeys(username) {
    rsaKeyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048,
            publicExponent: new Uint8Array([1, 0, 1]),
            hash: "SHA-256",
        },
        true,
        ["encrypt", "decrypt"]
    );

    exportedPublicKey = await window.crypto.subtle.exportKey("spki", rsaKeyPair.publicKey);
    console.log("RSA key pair generated.");

    socket.emit('public_key', {
        username: username,
        public_key: exportedPublicKey
    });

    // Simulate sharing and receiving your own key
    const encryptedAESKey = await encryptAESKeyWithPublicKey(aesKey, rsaKeyPair.publicKey);
    const decryptedAESKey = await decryptAESKeyWithPrivateKey(encryptedAESKey, rsaKeyPair.privateKey);
    const match = aesKey.every((val, i) => val === new Uint8Array(decryptedAESKey)[i]);
    console.log("AES key encryption/decryption successful?", match);
}

async function encryptAESKeyWithPublicKey(key, publicKey) {
    return await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP" },
        publicKey,
        key
    );
}

async function decryptAESKeyWithPrivateKey(encryptedKey, privateKey) {
    return await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP" },
        privateKey,
        encryptedKey
    );
}

async function encryptMessage(message, key) {
    const encoder = new TextEncoder();
    const data = encoder.encode(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));

    const cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        key,
        "AES-GCM",
        false,
        ["encrypt"]
    );

    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        cryptoKey,
        data
    );

    return {
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(encrypted))),
        iv: btoa(String.fromCharCode(...iv))
    };
}

async function decryptMessage(ciphertext, iv, key) {
    const encryptedData = Uint8Array.from(atob(ciphertext), c => c.charCodeAt(0));
    const ivBytes = Uint8Array.from(atob(iv), c => c.charCodeAt(0));

    const cryptoKey = await window.crypto.subtle.importKey(
        "raw",
        key,
        "AES-GCM",
        false,
        ["decrypt"]
    );

    const decrypted = await window.crypto.subtle.decrypt(
        { name: "AES-GCM", iv: ivBytes },
        cryptoKey,
        encryptedData
    );

    return new TextDecoder().decode(decrypted);
}