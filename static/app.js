// DOM Selectors
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const selectedDetails = document.getElementById('selected-file-details');
const encryptBtn = document.getElementById('encrypt-btn');
const resultBox = document.getElementById('result-box');
const shareUrlInput = document.getElementById('share-url-input');
const copyBtn = document.getElementById('copy-btn');

const sharePanel = document.getElementById('share-panel');
const downloadPanel = document.getElementById('download-panel');
const dlFilename = document.getElementById('dl-filename');
const dlMeta = document.getElementById('dl-meta');
const downloadBtn = document.getElementById('download-btn');

const loader = document.getElementById('loader');
const loaderText = document.getElementById('loader-text');

let selectedFile = null;
let downloadState = {
    fileId: null,
    keyHex: null,
    ivHex: null,
    encryptedFilename: null
};

// --- Initialization & Page Router ---
window.addEventListener('DOMContentLoaded', () => {
    const hash = window.location.hash;
    if (hash.startsWith('#download/')) {
        // Switch to download workspace
        sharePanel.classList.add('hidden');
        sharePanel.classList.remove('active');
        downloadPanel.classList.remove('hidden');
        downloadPanel.classList.add('active');
        
        parseDownloadHash(hash);
    }
});

// --- Upload Workspace Event Listeners ---
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
});

dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length > 0) {
        handleFileSelect(e.dataTransfer.files[0]);
    }
});

fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
        handleFileSelect(e.target.files[0]);
    }
});

function handleFileSelect(file) {
    selectedFile = file;
    selectedDetails.textContent = `Selected: ${file.name} (${formatBytes(file.size)})`;
    encryptBtn.disabled = false;
}

encryptBtn.addEventListener('click', async () => {
    if (!selectedFile) return;
    showLoader("Performing local AES-GCM-256 operations...");

    try {
        // 1. Generate key and IV
        const key = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true, // extractable
            ["encrypt", "decrypt"]
        );
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Export key to raw bytes to store in the hash fragment
        const exportedKey = await window.crypto.subtle.exportKey("raw", key);
        const keyHex = bufToHex(exportedKey);
        const ivHex = bufToHex(iv);

        // 2. Read and Encrypt file name (to preserve metadata securely)
        const enc = new TextEncoder();
        const filenameBytes = enc.encode(selectedFile.name);
        const encryptedFilenameBytes = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            filenameBytes
        );
        const encryptedFilenameHex = bufToHex(encryptedFilenameBytes);

        // 3. Read and Encrypt file contents
        const fileBytes = await readFileAsArrayBuffer(selectedFile);
        const encryptedFileBytes = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            fileBytes
        );

        // 4. Upload raw encrypted file payload to server
        showLoader("Uploading payload to node server...");
        const formData = new FormData();
        const encryptedBlob = new Blob([encryptedFileBytes], { type: 'application/octet-stream' });
        
        formData.append('file', encryptedBlob);
        formData.append('filename', encryptedFilenameHex);
        formData.append('iv', ivHex);

        const response = await fetch('/api/upload', {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Build absolute URL incorporating key parameter in hash routing
            const secureLink = `${window.location.origin}/#download/${data.id}/${keyHex}/${ivHex}`;
            shareUrlInput.value = secureLink;
            resultBox.classList.remove('hidden');
            encryptBtn.disabled = true;
        } else {
            alert("Upload failed: " + data.error);
        }
    } catch (err) {
        console.error(err);
        alert("Encryption/Upload failed: " + err.message);
    } finally {
        hideLoader();
    }
});

copyBtn.addEventListener('click', () => {
    shareUrlInput.select();
    document.execCommand('copy');
    copyBtn.textContent = "Copied!";
    setTimeout(() => copyBtn.textContent = "Copy Link", 2000);
});

// --- Download Workspace Logic ---
async function parseDownloadHash(hash) {
    // Hash layout: #download/{id}/{keyHex}/{ivHex}
    const parts = hash.split('/');
    if (parts.length < 4) {
        alert("Invalid sharing link configuration. Key data is missing.");
        return;
    }
    
    downloadState.fileId = parts[1];
    downloadState.keyHex = parts[2];
    downloadState.ivHex = parts[3];

    showLoader("Contacting server for metadata...");
    try {
        // Query server to get the encrypted filename & metadata headers
        const res = await fetch(`/api/download/${downloadState.fileId}`, { method: 'HEAD' });
        if (res.status === 404) {
            dlFilename.textContent = "Expired or Deleted Package";
            dlMeta.textContent = "The requested file has already been destroyed or does not exist.";
            downloadBtn.disabled = true;
            return;
        }

        const encryptedFilenameHex = res.headers.get('X-Encrypted-Filename');
        downloadState.encryptedFilename = encryptedFilenameHex;

        // Perform local client-side decryption of the filename to display it
        const key = await importHexKey(downloadState.keyHex);
        const iv = hexToBuf(downloadState.ivHex);
        const dec = new TextDecoder();
        
        const decFilenameBytes = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            hexToBuf(encryptedFilenameHex)
        );
        
        const decryptedName = dec.decode(decFilenameBytes);
        dlFilename.textContent = decryptedName;
        dlMeta.textContent = "Payload is locked and encrypted. Ready for client decryption.";
    } catch (err) {
        console.error(err);
        dlFilename.textContent = "Decryption Key Mismatch";
        dlMeta.textContent = "Unable to read metadata headers. The link may contain an invalid decryption key.";
        downloadBtn.disabled = true;
    } finally {
        hideLoader();
    }
}

downloadBtn.addEventListener('click', async () => {
    if (!downloadState.fileId || !downloadState.keyHex || !downloadState.ivHex) return;
    
    showLoader("Downloading payload...");
    try {
        const response = await fetch(`/api/download/${downloadState.fileId}`);
        if (!response.ok) throw new Error("Could not download file.");

        const encryptedData = await response.arrayBuffer();

        showLoader("Computing decryption keys...");
        const key = await importHexKey(downloadState.keyHex);
        const iv = hexToBuf(downloadState.ivHex);

        const decryptedData = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedData
        );

        // Download to browser filesystem
        const blob = new Blob([decryptedData], { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = dlFilename.textContent;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    } catch (err) {
        console.error(err);
        alert("Failed to download or decrypt file: " + err.message);
    } finally {
        hideLoader();
    }
});


// --- Cryptographic Helpers ---
function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result);
        reader.onerror = () => reject(reader.error);
        reader.readAsArrayBuffer(file);
    });
}

function importHexKey(hexStr) {
    const rawKey = hexToBuf(hexStr);
    return window.crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "AES-GCM" },
        false,
        ["encrypt", "decrypt"]
    );
}

// Convert buffer to hex string
function bufToHex(buffer) {
    return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join('');
}

// Convert hex string to buffer
function hexToBuf(hexStr) {
    return new Uint8Array(hexStr.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// Byte formatter
function formatBytes(bytes, decimals = 2) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Loader Utilities
function showLoader(text) {
    loaderText.textContent = text;
    loader.classList.remove('hidden');
}

function hideLoader() {
    loader.classList.add('hidden');
}
