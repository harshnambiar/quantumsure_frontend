import { MlKem1024 } from 'crystals-kyber-js';
import { encode, decode } from 'base64-arraybuffer';
import ChaCha20 from 'js-chacha20';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { Buffer } from 'buffer';
import detectEthereumProvider from "@metamask/detect-provider";
import { wrapEthereumProvider } from "@oasisprotocol/sapphire-paratime";
import { wrapEthersSigner, wrapEthersProvider } from '@oasisprotocol/sapphire-ethers-v6';
import { BrowserProvider, Contract, ethers } from "ethers";
import { AEAD, NonceSize } from '@oasisprotocol/deoxysii';
import Web3 from "web3";

// === CONFIG ===
const API_BASE_URL = 'https://quantumsure.onrender.com/api'; // Update if needed
//const API_BASE_URL = 'https://quantumsure.onrender.com/api';

// === CRYPTO HELPERS ===
function randomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Buffer.from(array);
}

async function computeMac(data, key) {
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const combined = Buffer.concat([Buffer.from(dataBytes), Buffer.from(keyBytes)]);
  const hash = await crypto.subtle.digest('SHA-256', combined);
  return Buffer.from(hash);
}

function postQuantumEncrypt(data, key) {
  const nonce = randomBytes(12);
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(dataBytes);
  return {
    encrypted: encode(encrypted),
    nonce: encode(nonce),
  };
}

async function postQuantumDecrypt(encryptedB64, nonceB64, key, authTagB64) {
  const encrypted = Buffer.from(decode(encryptedB64));
  const nonce = Buffer.from(decode(nonceB64));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

async function quantumResistantEncrypt(inputData, pubKeyB64) {
  const publicKey = Buffer.from(decode(pubKeyB64));
  const sender = new MlKem1024();
  const [ciphertext, sharedSecret] = await sender.encap(publicKey);
  const { encrypted, nonce } = postQuantumEncrypt(inputData, sharedSecret);
  const combinedData = new TextEncoder().encode(`${nonce}${encrypted}`);
  const authTag = await computeMac(combinedData, sharedSecret);
  return {
    encrypted_data: `${encode(ciphertext)}:${nonce}:${encrypted}:${encode(authTag)}`,
  };
}

async function quantumResistantDecrypt(encryptedData, privateKeyB64) {
  const [ciphertextB64, nonceB64, encryptedB64, authTagB64] = encryptedData.split(':');
  if (!ciphertextB64 || !nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted data format');
  }
  const privateKey = Buffer.from(decode(privateKeyB64));
  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(Buffer.from(decode(ciphertextB64)), privateKey);
  return await postQuantumDecrypt(encryptedB64, nonceB64, sharedSecret, authTagB64);
}

async function encryptPrivateKey(privateKey, masterPassword) {
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const nonce = randomBytes(12);
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(Buffer.from(privateKey));
  const combinedData = new TextEncoder().encode(`${encode(nonce)}${encode(encrypted)}`);
  const authTag = await computeMac(combinedData, key);
  return `${encode(nonce)}.${encode(encrypted)}.${encode(authTag)}`;
}

async function decryptPrivateKey(encryptedPrivateKey, masterPassword) {
  const [nonceB64, encryptedB64, authTagB64] = encryptedPrivateKey.split('.');
  if (!nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted private key format');
  }
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const nonce = Buffer.from(decode(nonceB64));
  const encrypted = Buffer.from(decode(encryptedB64));
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

// === USER SESSION MANAGER ===
const USER_SESSIONS = 'qs_user_sessions';
let currentSession = null;

function saveSession(apiKey, encryptedPrivateKey, alias = 'User') {
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  const existing = sessions.find(s => s.apiKey === apiKey);
  if (existing) {
    existing.encryptedPrivateKey = encryptedPrivateKey;
    existing.alias = alias;
  } else {
    sessions.push({ apiKey, encryptedPrivateKey, alias });
  }
  localStorage.setItem(USER_SESSIONS, JSON.stringify(sessions));
  switchToSession(apiKey);
}

function switchToSession(apiKey) {
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  const session = sessions.find(s => s.apiKey === apiKey);
  if (!session) return;

  currentSession = session;
  localStorage.setItem('apiKey', session.apiKey);
  localStorage.setItem('encryptedPrivateKey', session.encryptedPrivateKey);

  document.getElementById('current-user').innerText = `${session.alias} (${session.apiKey.slice(0, 8)}...)`;
  //document.getElementById('user-switcher').style.display = 'block';
}

async function logoutUser() {
  localStorage.removeItem('apiKey');
  localStorage.removeItem('encryptedPrivateKey');
  currentSession = null;
  document.getElementById('current-user').innerText = 'None';
  document.getElementById('output').innerText = 'Logged out. Create or switch user.';
}
window.logoutUser = logoutUser;

function switchUser() {
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  if (sessions.length === 0) {
    alert('No users to switch.');
    return;
  }

  const options = sessions.map((s, i) => `${i + 1}. ${s.alias} (${s.apiKey.slice(0, 8)}...)`).join('\n');
  const choice = prompt(`Switch to:\n${options}\n\nEnter number:`, '1');
  const index = parseInt(choice) - 1;
  if (index >= 0 && index < sessions.length) {
    switchToSession(sessions[index].apiKey);
    document.getElementById('output').innerText = `Switched to ${sessions[index].alias}`;
  }
}
window.switchUser = switchUser;

// === API CALLS ===
async function createAccount(secretPhrase, masterPassword, alias) {
  const recipient = new MlKem1024();
  const [publicKey, privateKey] = await recipient.generateKeyPair();
  const publicKeyB64 = encode(publicKey);
  const privateKeyB64 = encode(privateKey);
  const encryptedPrivateKey = await encryptPrivateKey(privateKeyB64, masterPassword);

  const response = await fetch(`${API_BASE_URL}/user/create`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { public_key: publicKeyB64, secret_phrase: secretPhrase }
    }),
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const result = await response.json();
  saveSession(result.api_key, encryptedPrivateKey, alias);
  return result;
}


async function getPublicKey(targetApiKey) {
  const myApiKey = localStorage.getItem('apiKey');
  const response = await fetch(`${API_BASE_URL}/user/public-key/${targetApiKey}`, {
    method: 'GET',
    headers: {
      'api_key': myApiKey,  // ← Auth as ME
      'Content-Type': 'application/json'
    },
  });
  if (!response.ok) throw new Error(`Failed to get public key: ${await response.text()}`);
  const { public_key } = await response.json();
  return public_key;
}

// storePassword() — get MY public key
async function getMyPublicKey() {
  const apiKey = localStorage.getItem('apiKey');
  const res = await fetch(`${API_BASE_URL}/user/public-key`, {
    method: 'GET',
    headers: { 'api_key': apiKey }
  });
  const { public_key } = await res.json();
  return public_key;
}

async function storePassword(apiKey, site, username, password, secretPhrase) {
  const publicKey = await getMyPublicKey();
  const { encrypted_data } = await quantumResistantEncrypt(password, publicKey);
  const response = await fetch(`${API_BASE_URL}/password/store`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { site, username, encrypted_text: encrypted_data }
    }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function listPasswords(apiKey) {
  const response = await fetch(`${API_BASE_URL}/password/list`, {
    method: 'GET',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function getPassword(apiKey, passwordId, masterPassword, encryptedPrivateKey) {
  const response = await fetch(`${API_BASE_URL}/password/get`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: { password_id: passwordId } }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const { encrypted_text, site, username } = await response.json();
  const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
  const password = await quantumResistantDecrypt(encrypted_text, privateKeyB64);
  return { site, username, password };
}

async function shareWithUsers(apiKey, passwordId, masterPassword, encryptedPrivateKey, recipientApiKeys) {
  const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
  const getRes = await fetch(`${API_BASE_URL}/password/get`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({ data: { password_id: passwordId } }),
  });
  const { encrypted_text } = await getRes.json();
  const plaintext = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

  const encryptedTokens = [];
  for (const recApiKey of recipientApiKeys) {
    const pubKey = await getPublicKey(recApiKey);
    const { encrypted_data } = await quantumResistantEncrypt(plaintext, pubKey);
    encryptedTokens.push(encrypted_data);
  }

  const shareRes = await fetch(`${API_BASE_URL}/share`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: {
        qpassword_id: passwordId,
        user_api_keys: recipientApiKeys,
        encrypted_access_tokens: encryptedTokens,
        expires_in_hours: 24
      }
    }),
  });
  if (!shareRes.ok) throw new Error(`HTTP ${shareRes.status}`);
  return await shareRes.json();
}

async function revokeSharedPassword(apiKey, shareId, secretPhrase) {
  const response = await fetch(`${API_BASE_URL}/share/revoke`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { share_id: shareId }
    }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}


async function deleteSharedPassword(apiKey, shareId, secretPhrase) {
  const response = await fetch(`${API_BASE_URL}/share/delete`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { share_id: shareId }
    }),
  });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  return await response.json();
}

async function useSharedPassword(apiKey, shareId, masterPassword, encryptedPrivateKey) {
  const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
  const res = await fetch(`${API_BASE_URL}/share/use`, {
    method: 'POST',
    headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { share_id: shareId, private_key_b64: privateKeyB64 }
    }),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const response = await res.json();
  const { encrypted_blob, share_type } = response;
  if (!encrypted_blob){
    throw new Error('No encrypted data found!');
  }
  const decrypted = await quantumResistantDecrypt(encrypted_blob, privateKeyB64);
  if (share_type.includes('password')){
    return {password: decrypted};
  }
  else if (share_type.includes('oauth')){
    return {access_token: decrypted};
  }
  else {
    throw new Error('Unknown share type: '.concat(share_type));
  }

}

async function createShareGroup1(apiKey, groupName, secretPhrase){
    const response = await fetch(`${API_BASE_URL}/sharegroup/create`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { name: groupName } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function addShareGroupMember(apiKey, groupId, memberApi, secretPhrase){
    const response = await fetch(`${API_BASE_URL}/sharegroup/add`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId, member_api_keys: [memberApi] } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function removeShareGroupMember(apiKey, groupId, memberApi, secretPhrase){
    const response = await fetch(`${API_BASE_URL}/sharegroup/remove`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId, member_api_keys: [memberApi] } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function revokeShareGroup1(apiKey, groupId, secretPhrase){
    const response = await fetch(`${API_BASE_URL}/sharegroup/revoke`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

async function deleteShareGroup1(apiKey, groupId, secretPhrase){
    const response = await fetch(`${API_BASE_URL}/sharegroup/delete`, {
        method: 'POST',
        headers: { 'api_key': apiKey, 'secret_phrase': secretPhrase, 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { group_id: groupId } }),
    });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
}

function generatePassword(length = 16) {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
  const bytes = randomBytes(length);
  return Array.from(bytes).map(b => chars[b % chars.length]).join('');
}

// === UI ===
window.createAccount = async () => {
  const mp = document.getElementById('create-master-password').value;
  const sp = document.getElementById('secret-phrase').value;
  const alias = prompt('Name this user (e.g., Alice, Bob):', 'User') || 'User';

  if (!mp || !sp) {
    alert('Master password and secret phrase required.');
    return;
  }

  try {
    const r = await createAccount(sp, mp, alias);
    document.getElementById('output').innerText =
      `Account created!\nName: ${alias}\nAPI Key: ${r.api_key}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.storePassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  if (!apiKey) return alert('No user logged in.');
  const site = document.getElementById('site').value;
  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;
  const secret = document.getElementById('secret-phrase0').value;
  if (!site || !username || !password) return alert('Fill all fields.');

  try {
    const r = await storePassword(apiKey, site, username, password, secret);
    document.getElementById('output').innerText = `Stored! ID: ${r.password_id}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.listPasswords = async () => {
  const apiKey = localStorage.getItem('apiKey');
  if (!apiKey) return alert('No user logged in.');
  try {
    const r = await listPasswords(apiKey);
    const ul = document.getElementById('password-list');
    ul.innerHTML = '';
    r.passwords.forEach(p => {
      const li = document.createElement('li');
      li.innerText = `${p.site} - ${p.username} (ID: ${p.id})`;
      ul.appendChild(li);
    });
    document.getElementById('output').innerText = `Loaded ${r.passwords.length} passwords.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.getPassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const id = document.getElementById('password-id').value;
  const mp = document.getElementById('retrieve-master-password').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  if (!apiKey || !id || !mp || !epk) return alert('Missing data.');

  try {
    const r = await getPassword(apiKey, id, mp, epk);
    document.getElementById('output').innerText = `Password: ${r.password}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.sharePassword = async () => {
  const apiKey = localStorage.getItem('apiKey');
  const id = document.getElementById('share-password-id').value;
  const mp = document.getElementById('share-master-password').value;
  const st = document.getElementById('share-type').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  const recipients = document.getElementById('recipient-api-keys').value.split(',').map(s => s.trim()).filter(Boolean);

  if (!apiKey || !id || !mp || !epk || !st || recipients.length === 0) {
    return alert('Fill all fields');
  }

  try {
    // 1. Get encrypted password
    const getRes = await fetch(`${API_BASE_URL}/password/get`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { password_id: id } })
    });
    const { encrypted_text } = await getRes.json();

    // 2. Decrypt locally
    const privateKeyB64 = await decryptPrivateKey(epk, mp);
    const plaintext = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    // 3. Re-encrypt for each recipient
    const encryptedTokens = [];
    for (const recKey of recipients) {
      const pubKey = await getPublicKey(recKey);
      const { encrypted_data } = await quantumResistantEncrypt(plaintext, pubKey);
      encryptedTokens.push(encrypted_data);
    }

    // 4. Send to server
    const shareRes = await fetch(`${API_BASE_URL}/share`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          qpassword_id: id,
          user_api_keys: recipients,
          encrypted_access_tokens: encryptedTokens,
          expires_in_hours: 24,
          share_type: st
        }
      })
    });

    const result = await shareRes.json();
    document.getElementById('output').innerText = `Shared! Check console.`;
    console.log('Shares:', result.shares);
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};


window.useShared = async () => {
  const shareId = document.getElementById('share-id').value;
  const mp = document.getElementById('access-master-password').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  const apiKey = localStorage.getItem("apiKey");
  if (!shareId || !mp || !epk) return alert('Fill all fields.');

  try {
    const r = await useSharedPassword(apiKey, shareId, mp, epk);
    document.getElementById('output').innerText = `Shared Password: ${r.password}`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};


window.revokeShared = async () => {
  const shareId = document.getElementById('share-id2').value;
  const secret = document.getElementById('secret-phrase2').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!shareId) return alert('Fill all fields.');

  try {
    const r = await revokeSharedPassword(apiKey, shareId, secret);
    document.getElementById('output').innerText = `Successfully Revoked Shared Token.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.deleteShared = async () => {
  const shareId = document.getElementById('share-id3').value;
  const secret = document.getElementById('secret-phrase3').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!shareId) return alert('Fill all fields.');

  try {
    const r = await deleteSharedPassword(apiKey, shareId, secret);
    document.getElementById('output').innerText = `Successfully Deleted Shared Token.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.createShareGroup = async () => {
  const groupName = document.getElementById('group-name').value;
  const secret = document.getElementById('secret-phrase4').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupName) return alert('Fill all fields.');

  try {
    const r = await createShareGroup1(apiKey, groupName, secret);
    console.log(r);
    document.getElementById('output').innerText = `Share Group Created. Group id: `.concat(r.group_id);
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.addGroupMember = async () => {
  const groupId = document.getElementById('add-group-id').value;
  const memberApi = document.getElementById('add-member-key').value;
  const secret = document.getElementById('secret-phrase5').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId || !memberApi) return alert('Fill all fields.');

  try {
    const r = await addShareGroupMember(apiKey, groupId, memberApi, secret);
    document.getElementById('output').innerText = `Added Member.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.removeGroupMember = async () => {
  const groupId = document.getElementById('remove-group-id').value;
  const memberApi = document.getElementById('remove-member-key').value;
  const secret = document.getElementById('secret-phrase6').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId || !memberApi) return alert('Fill all fields.');

  try {
    const r = await removeShareGroupMember(apiKey, groupId, memberApi, secret);
    document.getElementById('output').innerText = `Removed Member.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.revokeShareGroup = async () => {
  const groupId = document.getElementById('revoke-group-id').value;
  const secret = document.getElementById('secret-phrase7').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId) return alert('Fill all fields.');

  try {
    const r = await revokeShareGroup1(apiKey, groupId, secret);
    document.getElementById('output').innerText = `Share Group Revoked.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.deleteShareGroup = async () => {
  const groupId = document.getElementById('delete-group-id').value;
  const secret = document.getElementById('secret-phrase8').value;
  const apiKey = localStorage.getItem("apiKey");
  if (!groupId) return alert('Fill all fields.');

  try {
    const r = await deleteShareGroup1(apiKey, groupId, secret);
    document.getElementById('output').innerText = `Share Group Deleted.`;
  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.shareWithGroup = async () => {
  const groupId = document.getElementById('share-group-id').value.trim();
  const pwdId = document.getElementById('share-pwd-id').value.trim();
  const shareType = document.getElementById('share-pwd-type').value.trim();
  const mp = document.getElementById('share-mp').value;
  const epk = localStorage.getItem('encryptedPrivateKey');
  const apiKey = localStorage.getItem('apiKey');

  if (!groupId || !pwdId || !shareType || !mp){
    throw new Error('No field is optional!');
  }


  try {
    // Reuse logic from Step 3 above
    const privateKeyB64 = await decryptPrivateKey(epk, mp);
    const getRes = await fetch(`${API_BASE_URL}/password/get`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({ data: { password_id: pwdId } })
    });
    const { encrypted_text } = await getRes.json();
    const plaintext = await quantumResistantDecrypt(encrypted_text, privateKeyB64);

    const groupRes = await fetch(`${API_BASE_URL}/sharegroup/list`, { headers: { 'api_key': apiKey } });
    const groups = await groupRes.json();
    const group = groups.groups.find(g => g.group_id === groupId);

    const memberKeys = group.member_api_keys;

    const encryptedBlobs = [];
    for (const key of memberKeys) {
      const pub = await getPublicKey(key);
      const { encrypted_data } = await quantumResistantEncrypt(plaintext, pub);
      encryptedBlobs.push(encrypted_data);
    }

    const shareRes = await fetch(`${API_BASE_URL}/share`, {
      method: 'POST',
      headers: { 'api_key': apiKey, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        data: {
          qpassword_id: pwdId,
          group_id: groupId,
          user_api_keys: memberKeys,
          encrypted_access_tokens: encryptedBlobs,
          share_type: shareType,
          expires_in_hours: 24
        }
      })
    });
    const result = await shareRes.json();
    document.getElementById('output').innerText =
      `Shared!\nShares: ${result.shares.map(s => s.share_id).join(', ')}`;
     console.log('Shares:', result.shares);

  } catch (e) {
    document.getElementById('output').innerText = `Error: ${e.message}`;
  }
};

window.generatePassword = () => {
  document.getElementById('password').value = generatePassword();
};

// === ON LOAD ===
window.loadplan = async () => {
  const lastApiKey = localStorage.getItem('apiKey');
  const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  if (sessions.length !== 0) {
    const options = sessions.map((s, i) => `${i + 1}. ${s.alias} (${s.apiKey.slice(0, 8)}...)`).join('\n');
    //document.getElementById('user-switcher').style.display = 'block';

  }



  if (lastApiKey) {
    switchToSession(lastApiKey);
  }

  await showFlow(1);

};

async function loginUser(){
  let sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  console.log(sessions);
  const modal = document.getElementById('myModal');
  modal.style.display = 'flex';
}
window.loginUser = loginUser;

async function closeForm(){
  const modal = document.getElementById('myModal');
  modal.style.display = 'none';
}
window.closeForm = closeForm;

async function addAccount(){
    const form = document.getElementById('keyForm');
    const modal = document.getElementById('myModal');
    const apiKey = document.getElementById('apiKey').value.trim();
    const encryptedKey = document.getElementById('encryptedKey').value.trim();
    const alias = document.getElementById('alias').value.trim();
    const sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
    var i = 0;
    //console.log(sessions[0].apiKey);
    //console.log(sessions[0].encryptedPrivateKey);
    while (i < sessions.length){
      let key = sessions[i].apiKey;
      if (key == apiKey){
        modal.style.display = 'none';
        form.reset();
        alert('You are already logged in on this device this this account');
        return;
      }
      i++;
    }
    const response = await fetch(`${API_BASE_URL}/user/public-key/${apiKey}`, {
      method: 'GET',
      headers: {
        'api_key': apiKey,  // ← Auth as ME
        'Content-Type': 'application/json'
      },
    });
    if (!response.ok){
      modal.style.display = 'none';
      form.reset();
      alert('Invalid api key. Please choose one that actually exists.');
      return;
    };

    saveSession(apiKey, encryptedKey, alias);
    modal.style.display = 'none';
    form.reset();
}
window.addAccount = addAccount;

async function toggleFlowMenu() {
  const dropdown = document.getElementById('flow-dropdown');
  dropdown.style.display = dropdown.style.display === 'block' ? 'none' : 'block';
}
window.toggleFlowMenu = toggleFlowMenu;

async function showFlow(k){
  var i = 1;
  document.querySelectorAll('.content-wrapper').forEach(sec => {
    if (k != i){
      sec.style.display = 'none';
    }
    else {
      sec.style.display = 'block';
    }
    i++;
  });
  const dropdown = document.getElementById('flow-dropdown');
  dropdown.style.display = 'none';
}
window.showFlow = showFlow;


async function expandGuide(k){
  switch (k){
    case 1: {
      document.getElementById('dd1').style.display = document.getElementById('dd1').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 2: {
      document.getElementById('dd2').style.display = document.getElementById('dd2').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 3: {
      document.getElementById('dd3').style.display = document.getElementById('dd3').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 4: {
      document.getElementById('ee1').style.display = document.getElementById('ee1').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 5: {
      document.getElementById('ee2').style.display = document.getElementById('ee2').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 6: {
      document.getElementById('ee3').style.display = document.getElementById('ee3').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 7: {
      document.getElementById('ee4').style.display = document.getElementById('ee4').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 8: {
      document.getElementById('ee5').style.display = document.getElementById('ee5').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 9: {
      document.getElementById('ee6').style.display = document.getElementById('ee6').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 10: {
      document.getElementById('ff1').style.display = document.getElementById('ff1').style.display !== 'block' ? 'block': 'none';
      break;
    }
    case 11: {
      document.getElementById('ff2').style.display = document.getElementById('ff2').style.display !== 'block' ? 'block': 'none';
      break;
    }
    default: {}
  }
}
window.expandGuide = expandGuide;


// === Export Credentials ===


function downloadTxtFile(filename, text) {
  const a = document.createElement('a');
  a.href = 'data:text/plain;charset=utf-8,' + encodeURIComponent(text);
  a.download = filename;
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
}


function generateCredentials(ak, epk) {


  // Format the text content clearly
  const text = `Your Account Credentials
  ================================

  API Key: ${ak}

  Encrypted Private Key: ${epk}

  ================================
  IMPORTANT:
  - Save this file in a safe place.
  - Do not share these credentials with anyone.
  - This file was generated on your device and was never sent to any server.
  - You will not be able to view these credentials again after closing this page.

  Generated on: ${new Date().toLocaleString()}
  `;

  // Trigger download
  downloadTxtFile("quantumsure_".concat(ak).concat(".txt"), text);
}

async function exportAccount(){
  const apiKey = localStorage.getItem('apiKey');
  const epk = localStorage.getItem('encryptedPrivateKey');
  if (!apiKey || !epk){
    alert("You are not logged in to any account.");
    return;
  }
  else {
    generateCredentials(apiKey, epk);
  }
}
window.exportAccount = exportAccount;


// === Clear Account ===

async function clearAccount(){
  const apiKey = localStorage.getItem('apiKey');
  let sessions = JSON.parse(localStorage.getItem(USER_SESSIONS) || '[]');
  const ind = sessions.findIndex(s => s.apiKey === apiKey);
  if (ind != -1) {
    sessions.splice(ind, 1);
  } else {
    alert('Invalid Key');
    return;
  }
  localStorage.setItem(USER_SESSIONS, JSON.stringify(sessions));
  await logoutUser();
  alert('Account data cleared.');
}
window.clearAccount = clearAccount;


// === Files ===


// Concat helper
  function concatBytes(...arrays) {
    const total = arrays.reduce((acc, a) => acc + a.length, 0);
    const result = new Uint8Array(total);
    let offset = 0;
    for (const arr of arrays) result.set(arr, offset), offset += arr.length;
    return result;
  }


async function encryptFile() {
    const fileInput = document.getElementById('encrypt-file');
    const file = fileInput.files?.[0];
    if (!file) {
      alert('Please select a file first.');
      return;
    }

    let statusDiv = document.getElementById('encrypt-status');
    if (!statusDiv) {
      statusDiv = document.createElement('div');
      statusDiv.id = 'encrypt-status';
      fileInput.parentElement.appendChild(statusDiv);
    }
    statusDiv.textContent = 'Encrypting...';
    statusDiv.style.color = 'blue';

    try {
      const publicKeyEncoded = await getMyPublicKey();
      const publicKey = new Uint8Array(decode(publicKeyEncoded))// Uint8Array

      // Read file
      const fileBytes = new Uint8Array(await file.arrayBuffer());

      const kem = new MlKem1024();
      // ML-KEM-1024 encapsulate → get ciphertext + shared secret (our symmetric key)
      const ec =
        await kem.encap(publicKey);
      const kemCiphertext = ec[0];
      const fileKey = ec[1];
      // Encrypt file content with XChaCha20-Poly1305
      const nonce = randomBytes(24);

      const encryptedFile = xchacha20poly1305(fileKey, nonce).encrypt(fileBytes);

      // Bundle: version (2B) | kemLen (2B) | kemCiphertext | nonce (24B) | encryptedFile
      const version = new Uint8Array([1, 0]);
      const kemLenBytes = new Uint8Array([
        (kemCiphertext.length >> 8) & 0xff,
        kemCiphertext.length & 0xff
      ]);

      const bundle = concatBytes(
        version,
        kemLenBytes,
        kemCiphertext,
        nonce,
        encryptedFile
      );


      // Download
      const blob = new Blob([bundle], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name + '.qsecure';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      statusDiv.textContent = 'Encryption complete — file downloaded as .qsecure';
      statusDiv.style.color = 'green';
    } catch (err) {
      console.error(err);
      statusDiv.textContent = 'Encryption failed: ' + (err.message || 'Unknown error');
      statusDiv.style.color = 'red';
    }
}
window.encryptFile = encryptFile;


async function encryptFileForSomeone() {
    const fileInput = document.getElementById('encrypt-file-someone');
    const file = fileInput.files?.[0];
    if (!file) {
      alert('Please select a file first.');
      return;
    }

    const targetApiKey = document.getElementById('file-api').value;

    if (targetApiKey == "" || !targetApiKey || targetApiKey == null){
      alert('API Key cannot be blank');
      return;
    }

    let statusDiv = document.getElementById('encrypt-someone-status');
    if (!statusDiv) {
      statusDiv = document.createElement('div');
      statusDiv.id = 'encrypt-someone-status';
      fileInput.parentElement.appendChild(statusDiv);
    }
    statusDiv.textContent = 'Encrypting...';
    statusDiv.style.color = 'blue';

    try {
      const publicKeyEncoded = await getPublicKey(targetApiKey);
      const publicKey = new Uint8Array(decode(publicKeyEncoded))// Uint8Array

      // Read file
      const fileBytes = new Uint8Array(await file.arrayBuffer());

      const kem = new MlKem1024();
      // ML-KEM-1024 encapsulate → get ciphertext + shared secret (our symmetric key)
      const ec =
        await kem.encap(publicKey);
      const kemCiphertext = ec[0];
      const fileKey = ec[1];
      // Encrypt file content with XChaCha20-Poly1305
      const nonce = randomBytes(24);

      const encryptedFile = xchacha20poly1305(fileKey, nonce).encrypt(fileBytes);

      // Bundle: version (2B) | kemLen (2B) | kemCiphertext | nonce (24B) | encryptedFile
      const version = new Uint8Array([1, 0]);
      const kemLenBytes = new Uint8Array([
        (kemCiphertext.length >> 8) & 0xff,
        kemCiphertext.length & 0xff
      ]);

      const bundle = concatBytes(
        version,
        kemLenBytes,
        kemCiphertext,
        nonce,
        encryptedFile
      );


      // Download
      const blob = new Blob([bundle], { type: 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = file.name + '_'.concat(targetApiKey) + '.qsecure';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      statusDiv.textContent = 'Encryption complete — file downloaded as .qsecure';
      statusDiv.style.color = 'green';
    } catch (err) {
      console.error(err);
      statusDiv.textContent = 'Encryption failed: ' + (err.message || 'Unknown error');
      statusDiv.style.color = 'red';
    }
}
window.encryptFileForSomeone = encryptFileForSomeone;


async function decryptFile() {
    const fileInput = document.getElementById('decrypt-file');
    const mp = document.getElementById('file-mp').value;

    const file = fileInput.files?.[0];
    if (!file) {
        alert('Please select a .qsecure file first.');
        return;
    }

    let statusDiv = document.getElementById('decrypt-status');
    if (!statusDiv) {
        statusDiv = document.createElement('div');
        statusDiv.id = 'decrypt-status';
        fileInput.parentElement.appendChild(statusDiv);
    }
    statusDiv.textContent = 'Decrypting...';
    statusDiv.style.color = 'blue';

    try {
        // We need the private key to decapsulate
        const privateKeyEncoded = localStorage.getItem('encryptedPrivateKey');
        if (!privateKeyEncoded || privateKeyEncoded == "" || privateKeyEncoded == null){
          alert('You are not logged in!');
          return;
        }

        const privateKeyB64 = await decryptPrivateKey(privateKeyEncoded, mp);

        const privateKey = new Uint8Array(decode(privateKeyB64)); // Uint8Array

        // Read the encrypted file
        const bundle = new Uint8Array(await file.arrayBuffer());

        // Parse the structure:
        // version (2 bytes) | kemLen (2 bytes) | kemCiphertext | nonce (24 bytes) | encrypted data
        if (bundle.length < 2 + 2 + 24) {
            throw new Error("File is too short to be valid");
        }

        const version = bundle.slice(0, 2);
        if (version[0] !== 1 || version[1] !== 0) {
            throw new Error(`Unsupported file version: ${version[0]}.${version[1]}`);
        }

        const kemLen = (bundle[2] << 8) | bundle[3];
        if (kemLen < 1568 || kemLen > 2000) { // ML-KEM-1024 ciphertext ≈ 1568 bytes
            throw new Error("Invalid KEM ciphertext length");
        }

        const offset = 4;
        const kemCiphertext = bundle.slice(offset, offset + kemLen);
        const nonce = bundle.slice(offset + kemLen, offset + kemLen + 24);
        const encryptedFile = bundle.slice(offset + kemLen + 24);

        if (encryptedFile.length === 0) {
            throw new Error("No encrypted data found");
        }

        // Decapsulate → recover the file key (shared secret)
        const kem = new MlKem1024();
        const fileKey = await kem.decap(kemCiphertext, privateKey);

        // Decrypt the file content
        const decryptedBytes = xchacha20poly1305(fileKey, nonce).decrypt(encryptedFile);

        // Download decrypted file (original name = filename without .qsecure)
        let originalName = file.name;
        if (originalName.toLowerCase().endsWith('.qsecure')) {
            originalName = originalName.slice(0, -8);
        }

        const blob = new Blob([decryptedBytes], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = originalName || 'decrypted_file';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        statusDiv.textContent = 'Decryption complete — file downloaded';
        statusDiv.style.color = 'green';
    } catch (err) {
        console.error(err);
        statusDiv.textContent = 'Decryption failed: ' + (err.message || 'Unknown error');
        statusDiv.style.color = 'red';
    }
}

window.decryptFile = decryptFile;


// metamask

async function connectOrDisconnect() {
    const acc_cur = localStorage.getItem("accqs") || "";
    console.log(acc_cur == "");
    if (acc_cur != "" && acc_cur != null){
        localStorage.setItem("accqs","");
        document.getElementById("login-status").textContent = "Login";
        return;
    }

    var chainId = 23295;
    var cid = '0x5aff';
    var chain = 'Oasis Sapphire Testnet';
    var name = 'Oasis Sapphire Testnet';
    var symbol = 'TEST';
    var rpc = "https://testnet.sapphire.oasis.io";
    const provider1 = await detectEthereumProvider();
    const provider = wrapEthereumProvider(provider1);


    if (provider1 && provider1 === (window.ethereum)) {
        console.log("MetaMask is available!");

        console.log(window.ethereum.networkVersion);
        if (window.ethereum.networkVersion !== chainId) {
            try {
                await window.ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: cid }]
                });
                console.log("changed to ".concat(name).concat(" successfully"));

            } catch (err) {
                console.log(err);
                // This error code indicates that the chain has not been added to MetaMask
                if (err.code === 4902) {
                    console.log("please add ".concat(name).concat(" as a network"));
                        await window.ethereum.request({
                            method: 'wallet_addEthereumChain',
                            params: [
                                {
                                    chainName: chain,
                                    chainId: cid,
                                    nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                                    rpcUrls: [rpc]
                                }
                            ]
                        });
                }
                else {
                    console.log(err);
                }
            }
        }
        await startApp(provider1);
    } else {
      console.log(provider1);
        console.log("Please install MetaMask!")
    }



}
window.connectOrDisconnect = connectOrDisconnect;


async function startApp(provider1) {
  if (provider1 !== (window.ethereum)) {
    console.error("Do you have multiple wallets installed?")
  }
  else {
    const accounts = await window.ethereum
    .request({ method: "eth_requestAccounts" })
    .catch((err) => {
      if (err.code === 4001) {
        console.log("Please connect to MetaMask.")
      } else {
        console.error(err)
      }
    })
    console.log("hi");
  const account = accounts[0];
  var web3 = new Web3(provider1);
  const bal = await web3.eth.getBalance(account);

  console.log(bal);
  console.log(account);
  localStorage.setItem("accqs",account.toString());
  document.getElementById("login-status").textContent = (account.toString().slice(0,8)).concat('..(Logout)');

  }
}
