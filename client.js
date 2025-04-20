/**
 * Secure File Transfer - Client Side JavaScript
 * Complete implementation with error handling and optimizations
 */

// Helper functions - defined first to avoid reference errors
function showStatus(elementId, message, type) {
    const statusElement = document.getElementById(elementId);
    statusElement.textContent = message;
    statusElement.className = 'status';
    statusElement.classList.add(type);
}

function showLoadingStatus(elementId, message) {
    const statusElement = document.getElementById(elementId);
    statusElement.innerHTML = `<i class="fas fa-spinner spinner"></i> ${message}`;
    statusElement.className = 'status loading';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function generateRandomId() {
    return Math.random().toString(36).substring(2, 10) + 
           Math.random().toString(36).substring(2, 10);
}

function sanitizeFilename(filename) {
    // Remove potentially problematic characters from filenames
    return filename.replace(/[^\w\-\.]/g, '_');
}

// Conversion utility functions
function convertUint8ArrayToWordArray(u8arr) {
    const len = u8arr.length;
    const words = [];
    
    for (let i = 0; i < len; i += 4) {
        words.push(
            (u8arr[i] << 24) |
            ((i + 1 < len ? u8arr[i + 1] : 0) << 16) |
            ((i + 2 < len ? u8arr[i + 2] : 0) << 8) |
            (i + 3 < len ? u8arr[i + 3] : 0)
        );
    }
    
    return CryptoJS.lib.WordArray.create(words, len);
}

function convertWordArrayToUint8Array(wordArray) {
    const len = wordArray.sigBytes;
    const words = wordArray.words;
    const result = new Uint8Array(len);
    let i = 0, j = 0;
    
    while(i < len) {
        const w = words[j++];
        result[i++] = (w >> 24) & 0xff;
        if (i < len) result[i++] = (w >> 16) & 0xff;
        if (i < len) result[i++] = (w >> 8) & 0xff;
        if (i < len) result[i++] = w & 0xff;
    }
    
    return result;
}

function base64ToUint8Array(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    
    for (let i = 0; i < len; i++) {
        bytes[i] = binary_string.charCodeAt(i);
    }
    
    return bytes;
}

// File processing functions
function compressFile(fileData) {
    try {
        // Use pako to compress the data
        const compressedData = pako.deflate(fileData);
        return compressedData;
    } catch (error) {
        console.error('Compression error:', error);
        throw new Error('Failed to compress the file');
    }
}

function encryptFile(data, password) {
    try {
        // Generate random salt and IV
        const salt = CryptoJS.lib.WordArray.random(16);
        const iv = CryptoJS.lib.WordArray.random(16);
        
        // Generate key from password and salt
        const key = CryptoJS.PBKDF2(password, salt, {
            keySize: 256 / 32,
            iterations: 1000
        });
        
        // Convert Uint8Array to WordArray for CryptoJS
        const dataWordArray = convertUint8ArrayToWordArray(data);
        
        // Encrypt the data
        const encrypted = CryptoJS.AES.encrypt(dataWordArray, key, {
            iv: iv,
            padding: CryptoJS.pad.Pkcs7,
            mode: CryptoJS.mode.CBC
        });
        
        // Concatenate salt + iv + encrypted data
        const saltWords = salt.words;
        const ivWords = iv.words;
        const encryptedWords = encrypted.ciphertext.words;
        const totalWords = saltWords.concat(ivWords).concat(encryptedWords);
        
        const result = CryptoJS.lib.WordArray.create(
            totalWords,
            16 + 16 + encrypted.ciphertext.sigBytes
        );
        
        // Convert the result to Base64 for easier handling
        return CryptoJS.enc.Base64.stringify(result);
    } catch (error) {
        console.error('Encryption error:', error);
        throw new Error('Failed to encrypt the file');
    }
}

function decryptFile(encryptedContent, password) {
    try {
        // If your encrypted content is base64 encoded, decode it first
        const encryptedBytes = CryptoJS.enc.Base64.parse(encryptedContent);
        
        // Extract the salt, IV, and actual encrypted data
        // Assuming the first 16 bytes are salt and next 16 bytes are IV
        const salt = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(0, 4), 16);
        const iv = CryptoJS.lib.WordArray.create(encryptedBytes.words.slice(4, 8), 16);
        const actualEncryptedData = CryptoJS.lib.WordArray.create(
            encryptedBytes.words.slice(8),
            encryptedBytes.sigBytes - 32
        );
        
        // Generate key from password and salt
        const key = CryptoJS.PBKDF2(password, salt, {
            keySize: 256 / 32,
            iterations: 1000
        });
        
        // Decrypt the data
        const decryptedData = CryptoJS.AES.decrypt(
            { ciphertext: actualEncryptedData },
            key,
            { iv: iv, padding: CryptoJS.pad.Pkcs7, mode: CryptoJS.mode.CBC }
        );
        
        // Convert to binary data (Uint8Array)
        const decryptedBinary = convertWordArrayToUint8Array(decryptedData);
        return decryptedBinary;
    } catch (error) {
        console.error('Decryption error:', error);
        throw new Error('Failed to decrypt the file');
    }
}

function decompressFile(compressedData) {
    try {
        // Decompress the data using pako
        const decompressedData = pako.inflate(compressedData);
        return decompressedData;
    } catch (error) {
        console.error('Decompression error:', error);
        // If decompression fails, it might not be compressed
        return compressedData;
    }
}

function createAndDownloadFile(data, fileName) {
    // Sanitize the filename
    const safeFileName = sanitizeFilename(fileName);
    
    // Create a blob from the data
    const blob = new Blob([data], { type: 'application/octet-stream' });
    
    // Create a URL for the blob
    const url = URL.createObjectURL(blob);
    
    // Create a download link
    const downloadLink = document.createElement('a');
    downloadLink.href = url;
    downloadLink.download = safeFileName;
    
    // Append the link to the body
    document.body.appendChild(downloadLink);
    
    // Trigger the download
    downloadLink.click();
    
    // Clean up
    document.body.removeChild(downloadLink);
    URL.revokeObjectURL(url);
}

// Main functions
function uploadFile() {
    const fileInput = document.getElementById('fileInput');
    const password = document.getElementById('uploadPassword').value;
    
    if (!fileInput.files.length) {
        showStatus('uploadStatus', 'Please select a file to upload', 'error');
        return;
    }
    
    if (!password) {
        showStatus('uploadStatus', 'Please enter an encryption password', 'error');
        return;
    }
    
    const file = fileInput.files[0];
    
    // File size check
    const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit
    if (file.size > MAX_FILE_SIZE) {
        showStatus('uploadStatus', 'File is too large (max 100MB)', 'error');
        return;
    }
    
    // Show loading state
    showLoadingStatus('uploadStatus', 'Reading file...');
    document.getElementById('uploadProgress').style.display = 'block';
    const progressBar = document.querySelector('#uploadProgress .progress-bar');
    progressBar.style.width = '10%'; // Initial progress
    
    // Step 1: Read the file as an ArrayBuffer
    const reader = new FileReader();
    
    reader.onload = function(event) {
        progressBar.style.width = '30%';
        showLoadingStatus('uploadStatus', 'Compressing file...');
        
        try {
            // Step 2: Compress the file data
            const fileData = new Uint8Array(event.target.result);
            const originalSize = fileData.byteLength;
            const compressedData = compressFile(fileData);
            const compressedSize = compressedData.byteLength;
            
            // Calculate compression ratio
            const compressionRatio = Math.round((1 - (compressedSize / originalSize)) * 100);
            
            progressBar.style.width = '50%';
            showLoadingStatus('uploadStatus', 'Encrypting file...');
            
            // Step 3: Encrypt the compressed data
            const encryptedData = encryptFile(compressedData, password);
            
            progressBar.style.width = '70%';
            showLoadingStatus('uploadStatus', 'Uploading file...');
            
            // For debugging - log the encrypted data size
            console.log('Encrypted data size:', encryptedData.length);
            
            // Step 4: Upload the encrypted data to the server
            // Store encrypted content directly - no conversion needed
            fetch('/api/upload', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    encryptedContent: encryptedData,
                    originalName: file.name
                })
            })
            .then(response => {
                if (!response.ok) {
                    if (response.status === 413) {
                        throw new Error('File too large for server');
                    } else {
                        throw new Error(`Server error (${response.status})`);
                    }
                }
                return response.json();
            })
            .then(data => {
                progressBar.style.width = '100%';
                
                setTimeout(() => {
                    document.getElementById('uploadProgress').style.display = 'none';
                    showStatus('uploadStatus', 'File uploaded successfully!', 'success');
                    
                    // Display file ID and compression info
                    document.getElementById('fileList').innerHTML = `
                        <div class="file-item">
                            <div class="file-info">
                                <span class="file-name">${file.name}</span>
                                <span class="file-size">${formatFileSize(file.size)}</span>
                            </div>
                        </div>
                    `;
                    
                    // Show upload info with file ID
                    const uploadInfo = document.getElementById('uploadInfo');
                    uploadInfo.innerHTML = `
                        <div class="info-item">
                            <span class="info-label">File ID:</span>
                            <span id="generatedFileId" class="info-value">${data.fileId}</span>
                            <button class="btn-copy" onclick="copyToClipboard('generatedFileId')">
                                <i class="fas fa-copy"></i>
                            </button>
                        </div>
                        <div class="info-item">
                            <span class="info-label">Compression:</span>
                            <span id="compressionRatio" class="info-value">${compressionRatio}%</span>
                        </div>
                    `;
                    uploadInfo.style.display = 'block';
                }, 500);
            })
            .catch(error => {
                document.getElementById('uploadProgress').style.display = 'none';
                showStatus('uploadStatus', `Upload failed: ${error.message}`, 'error');
                console.error('Upload error:', error);
            });
            
        } catch (error) {
            document.getElementById('uploadProgress').style.display = 'none';
            showStatus('uploadStatus', `Processing failed: ${error.message}`, 'error');
            console.error('Processing error:', error);
        }
    };
    
    reader.onerror = function() {
        document.getElementById('uploadProgress').style.display = 'none';
        showStatus('uploadStatus', 'Failed to read file', 'error');
    };
    
    // Start reading the file
    reader.readAsArrayBuffer(file);
}

function downloadFile() {
    const fileId = document.getElementById('fileId').value.trim();
    const password = document.getElementById('downloadPassword').value;
    
    if (!fileId) {
        showStatus('downloadStatus', 'Please enter a file ID', 'error');
        return;
    }
    
    if (!password) {
        showStatus('downloadStatus', 'Please enter the decryption password', 'error');
        return;
    }
    
    // Show loading state
    showLoadingStatus('downloadStatus', 'Fetching encrypted file...');
    document.getElementById('downloadProgress').style.display = 'block';
    const progressBar = document.querySelector('#downloadProgress .progress-bar');
    progressBar.style.width = '10%'; // Initial progress
    
    // Step 1: Fetch the encrypted file from your server
    fetch(`/api/files/${encodeURIComponent(fileId)}`)
        .then(response => {
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error('File not found');
                } else {
                    throw new Error(`Server error (${response.status})`);
                }
            }
            
            progressBar.style.width = '40%';
            return response.json();
        })
        .then(data => {
            if (!data.encryptedContent) {
                throw new Error('Invalid file data received');
            }
            
            progressBar.style.width = '60%';
            showLoadingStatus('downloadStatus', 'Decrypting file...');
            
            try {
                // Step 2: Decrypt the data using the provided password
                const decryptedData = decryptFile(data.encryptedContent, password);
                progressBar.style.width = '80%';
                
                // Step 3: Decompress the data if it was compressed
                const decompressedData = decompressFile(decryptedData);
                progressBar.style.width = '90%';
                
                // Step 4: Create a downloadable file from the decrypted/decompressed data
                createAndDownloadFile(decompressedData, data.fileName || 'downloaded-file');
                
                progressBar.style.width = '100%';
                setTimeout(() => {
                    document.getElementById('downloadProgress').style.display = 'none';
                    showStatus('downloadStatus', 'File downloaded successfully!', 'success');
                }, 500);
            } catch (error) {
                document.getElementById('downloadProgress').style.display = 'none';
                showStatus('downloadStatus', 'Failed to decrypt file. Check your password.', 'error');
                console.error('Decryption error:', error);
            }
        })
        .catch(error => {
            document.getElementById('downloadProgress').style.display = 'none';
            showStatus('downloadStatus', `Download failed: ${error.message}`, 'error');
            console.error('Download error:', error);
        });
}

// File input handling
function handleFileSelect() {
    const fileInput = document.getElementById('fileInput');
    const filePreview = document.getElementById('filePreview');
    
    if (fileInput.files.length) {
        const file = fileInput.files[0];
        
        // Create file list entry
        document.getElementById('fileList').innerHTML = `
            <div class="file-item">
                <div class="file-info">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${formatFileSize(file.size)}</span>
                </div>
            </div>
        `;
        
        filePreview.style.display = 'block';
    }
}

function copyToClipboard(elementId) {
    const element = document.getElementById(elementId);
    const textToCopy = element.textContent;
    
    navigator.clipboard.writeText(textToCopy).then(() => {
        element.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
        setTimeout(() => {
            element.style.backgroundColor = '';
        }, 500);
    }).catch(err => {
        console.error('Could not copy text: ', err);
        // Fallback for browsers that don't support clipboard API
        const tempInput = document.createElement('input');
        tempInput.value = textToCopy;
        document.body.appendChild(tempInput);
        tempInput.select();
        document.execCommand('copy');
        document.body.removeChild(tempInput);
        
        element.style.backgroundColor = 'rgba(16, 185, 129, 0.2)';
        setTimeout(() => {
            element.style.backgroundColor = '';
        }, 500);
    });
}

function togglePasswordVisibility(inputId, icon) {
    const input = document.getElementById(inputId);
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Set up event listeners once DOM is fully loaded
document.addEventListener('DOMContentLoaded', function() {
    const fileInput = document.getElementById('fileInput');
    const dropArea = document.getElementById('dropArea');
    
    // File input event listeners
    if (fileInput) {
        fileInput.addEventListener('change', handleFileSelect);
    }
    
    // Drag and drop functionality
    if (dropArea) {
        dropArea.addEventListener('dragover', function(e) {
            e.preventDefault();
            e.stopPropagation();
            this.classList.add('dragover');
        });
        
        dropArea.addEventListener('dragleave', function(e) {
            e.preventDefault();
            e.stopPropagation();
            this.classList.remove('dragover');
        });
        
        dropArea.addEventListener('drop', function(e) {
            e.preventDefault();
            e.stopPropagation();
            this.classList.remove('dragover');
            
            if (e.dataTransfer.files.length) {
                fileInput.files = e.dataTransfer.files;
                handleFileSelect();
            }
        });
    }
    
    // Toggle password visibility
    const toggleUploadPassword = document.getElementById('toggleUploadPassword');
    const toggleDownloadPassword = document.getElementById('toggleDownloadPassword');
    
    if (toggleUploadPassword) {
        toggleUploadPassword.addEventListener('click', function() {
            togglePasswordVisibility('uploadPassword', this);
        });
    }
    
    if (toggleDownloadPassword) {
        toggleDownloadPassword.addEventListener('click', function() {
            togglePasswordVisibility('downloadPassword', this);
        });
    }
    
    // Upload and download buttons
    const uploadBtn = document.getElementById('uploadBtn');
    const downloadBtn = document.getElementById('downloadBtn');
    
    if (uploadBtn) {
        uploadBtn.addEventListener('click', uploadFile);
    }
    
    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadFile);
    }
});