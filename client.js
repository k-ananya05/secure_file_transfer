/**
 * Secure File Transfer - Client Side JavaScript
 * Enhanced with multi-file upload/download support
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

// Main functions for multiple file handling
async function uploadFiles() {
    const fileInput = document.getElementById('fileInput');
    const password = document.getElementById('uploadPassword').value;
    
    if (!fileInput.files.length) {
        showStatus('uploadStatus', 'Please select files to upload', 'error');
        return;
    }
    
    if (!password) {
        showStatus('uploadStatus', 'Please enter an encryption password', 'error');
        return;
    }
    
    const files = Array.from(fileInput.files);
    const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100MB limit per file
    
    // Check if any file exceeds the size limit
    const oversizedFiles = files.filter(file => file.size > MAX_FILE_SIZE);
    if (oversizedFiles.length > 0) {
        const fileNames = oversizedFiles.map(f => f.name).join(', ');
        showStatus('uploadStatus', `These files are too large (max 100MB): ${fileNames}`, 'error');
        return;
    }
    
    // Show loading state
    showLoadingStatus('uploadStatus', `Processing ${files.length} files...`);
    document.getElementById('uploadProgress').style.display = 'block';
    const progressBar = document.querySelector('#uploadProgress .progress-bar');
    progressBar.style.width = '5%'; // Initial progress
    
    // Create array to store upload results
    const uploadResults = [];
    const fileListElement = document.getElementById('fileList');
    fileListElement.innerHTML = ''; // Clear previous list
    
    // Process each file sequentially
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const currentFileIndex = i + 1;
        
        showLoadingStatus(
            'uploadStatus', 
            `Processing file ${currentFileIndex}/${files.length}: ${file.name}`
        );
        
        try {
            // Update progress based on file index
            const baseProgress = (i / files.length) * 100;
            progressBar.style.width = `${baseProgress + 5}%`;
            
            // Read file as ArrayBuffer
            const fileData = await readFileAsArrayBuffer(file);
            progressBar.style.width = `${baseProgress + 10}%`;
            
            // Compress the file data
            const compressedData = compressFile(new Uint8Array(fileData));
            const compressionRatio = Math.round((1 - (compressedData.byteLength / fileData.byteLength)) * 100);
            progressBar.style.width = `${baseProgress + 30}%`;
            
            // Encrypt the compressed data
            const encryptedData = encryptFile(compressedData, password);
            progressBar.style.width = `${baseProgress + 50}%`;
            
            // Upload to server
            const response = await fetch('/api/upload', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    encryptedContent: encryptedData,
                    originalName: file.name
                })
            });
            
            if (!response.ok) {
                if (response.status === 413) {
                    throw new Error('File too large for server');
                } else {
                    throw new Error(`Server error (${response.status})`);
                }
            }
            
            const data = await response.json();
            
            // Store the result
            uploadResults.push({
                name: file.name,
                size: file.size,
                fileId: data.fileId,
                compressionRatio: compressionRatio
            });
            
            // Add to file list UI
            const fileItemDiv = document.createElement('div');
            fileItemDiv.className = 'file-item success';
            fileItemDiv.innerHTML = `
                <div class="file-info">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${formatFileSize(file.size)}</span>
                    <span class="file-badge">Uploaded</span>
                </div>
            `;
            fileListElement.appendChild(fileItemDiv);
            
            progressBar.style.width = `${baseProgress + 70}%`;
            
        } catch (error) {
            console.error(`Error processing ${file.name}:`, error);
            
            // Add to file list UI as failed
            const fileItemDiv = document.createElement('div');
            fileItemDiv.className = 'file-item error';
            fileItemDiv.innerHTML = `
                <div class="file-info">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${formatFileSize(file.size)}</span>
                    <span class="file-badge error">Failed</span>
                </div>
                <div class="file-error">${error.message}</div>
            `;
            fileListElement.appendChild(fileItemDiv);
        }
    }
    
    // All files processed - update UI
    document.getElementById('uploadProgress').style.display = 'none';
    
    if (uploadResults.length > 0) {
        showStatus('uploadStatus', `Successfully uploaded ${uploadResults.length} of ${files.length} files!`, 'success');
        
        // Show upload info with file IDs
        const uploadInfo = document.getElementById('uploadInfo');
        let infoHtml = '<h3>Upload Summary</h3>';
        
        uploadResults.forEach(result => {
            const itemId = `fileId-${result.fileId.substring(0, 5)}`;
            infoHtml += `
                <div class="info-item">
                    <span class="info-label">${result.name}:</span>
                    <span id="${itemId}" class="info-value">${result.fileId}</span>
                    <button class="btn-copy" onclick="copyToClipboard('${itemId}')">
                        <i class="fas fa-copy"></i>
                    </button>
                    <span class="compression-badge">Compressed: ${result.compressionRatio}%</span>
                </div>
            `;
        });
        
        // Add batch download option if there are multiple files
        if (uploadResults.length > 1) {
            const batchIds = uploadResults.map(r => r.fileId).join(',');
            const batchIdElement = 'batchFileIds';
            infoHtml += `
                <div class="info-item batch">
                    <span class="info-label">Batch ID (all files):</span>
                    <span id="${batchIdElement}" class="info-value">${batchIds}</span>
                    <button class="btn-copy" onclick="copyToClipboard('${batchIdElement}')">
                        <i class="fas fa-copy"></i>
                    </button>
                </div>
            `;
        }
        
        uploadInfo.innerHTML = infoHtml;
        uploadInfo.style.display = 'block';
    } else {
        showStatus('uploadStatus', 'All uploads failed. Please try again.', 'error');
    }
}

function readFileAsArrayBuffer(file) {
    return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = event => resolve(event.target.result);
        reader.onerror = error => reject(error);
        reader.readAsArrayBuffer(file);
    });
}

async function downloadFiles() {
    const fileIdInput = document.getElementById('fileId').value.trim();
    const password = document.getElementById('downloadPassword').value;
    
    if (!fileIdInput) {
        showStatus('downloadStatus', 'Please enter file ID(s)', 'error');
        return;
    }
    
    if (!password) {
        showStatus('downloadStatus', 'Please enter the decryption password', 'error');
        return;
    }
    
    // Check if it's a batch download (comma-separated IDs)
    const fileIds = fileIdInput.split(',').map(id => id.trim()).filter(id => id);
    
    if (fileIds.length === 0) {
        showStatus('downloadStatus', 'Please enter valid file ID(s)', 'error');
        return;
    }
    
    // Show loading state
    showLoadingStatus('downloadStatus', `Preparing to download ${fileIds.length} file(s)...`);
    document.getElementById('downloadProgress').style.display = 'block';
    const progressBar = document.querySelector('#downloadProgress .progress-bar');
    progressBar.style.width = '5%'; // Initial progress
    
    const downloadResults = {
        success: 0,
        failed: 0,
        total: fileIds.length
    };
    
    // Process each file ID sequentially
    for (let i = 0; i < fileIds.length; i++) {
        const fileId = fileIds[i];
        const currentFileIndex = i + 1;
        
        // Update progress and status
        const baseProgress = (i / fileIds.length) * 100;
        progressBar.style.width = `${baseProgress + 5}%`;
        showLoadingStatus(
            'downloadStatus', 
            `Downloading file ${currentFileIndex}/${fileIds.length}...`
        );
        
        try {
            // Fetch the encrypted file
            const response = await fetch(`/api/files/${encodeURIComponent(fileId)}`);
            
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error(`File ID "${fileId}" not found`);
                } else {
                    throw new Error(`Server error (${response.status})`);
                }
            }
            
            progressBar.style.width = `${baseProgress + 25}%`;
            const data = await response.json();
            
            if (!data.encryptedContent) {
                throw new Error('Invalid file data received');
            }
            
            // Decrypt the data
            progressBar.style.width = `${baseProgress + 50}%`;
            showLoadingStatus('downloadStatus', `Decrypting file ${currentFileIndex}/${fileIds.length}...`);
            const decryptedData = decryptFile(data.encryptedContent, password);
            
            // Decompress the data
            progressBar.style.width = `${baseProgress + 75}%`;
            showLoadingStatus('downloadStatus', `Processing file ${currentFileIndex}/${fileIds.length}...`);
            const decompressedData = decompressFile(decryptedData);
            
            // Create and trigger download
            createAndDownloadFile(decompressedData, data.fileName || `downloaded-file-${fileId}`);
            downloadResults.success++;
            
        } catch (error) {
            console.error(`Download error for ${fileId}:`, error);
            showStatus('downloadStatus', `Error with file ${currentFileIndex}: ${error.message}. Continuing with remaining files...`, 'error');
            // Pause briefly to show the error message
            await new Promise(resolve => setTimeout(resolve, 1500));
            downloadResults.failed++;
        }
    }
    
    // All files processed
    progressBar.style.width = '100%';
    setTimeout(() => {
        document.getElementById('downloadProgress').style.display = 'none';
        
        // Show final status
        if (downloadResults.failed === 0) {
            showStatus('downloadStatus', `All ${downloadResults.total} files downloaded successfully!`, 'success');
        } else if (downloadResults.success === 0) {
            showStatus('downloadStatus', 'Failed to download any files. Please check IDs and password.', 'error');
        } else {
            showStatus(
                'downloadStatus', 
                `Downloaded ${downloadResults.success} of ${downloadResults.total} files. ${downloadResults.failed} failed.`, 
                'warning'
            );
        }
    }, 500);
}

// File input handling for multiple files
function handleFileSelect() {
    const fileInput = document.getElementById('fileInput');
    const filePreview = document.getElementById('filePreview');
    const fileList = document.getElementById('fileList');
    
    if (fileInput.files.length) {
        // Clear previous list
        fileList.innerHTML = '';
        
        // Get all selected files
        const files = Array.from(fileInput.files);
        const totalSize = files.reduce((sum, file) => sum + file.size, 0);
        
        // Create a summary header if multiple files selected
        if (files.length > 1) {
            const summaryDiv = document.createElement('div');
            summaryDiv.className = 'file-summary';
            summaryDiv.innerHTML = `
                <div class="summary-text">
                    <strong>${files.length} files selected</strong>
                    <span class="total-size">Total: ${formatFileSize(totalSize)}</span>
                </div>
            `;
            fileList.appendChild(summaryDiv);
        }
        
        // Add each file to the list
        files.forEach(file => {
            const fileItemDiv = document.createElement('div');
            fileItemDiv.className = 'file-item';
            fileItemDiv.innerHTML = `
                <div class="file-info">
                    <span class="file-name">${file.name}</span>
                    <span class="file-size">${formatFileSize(file.size)}</span>
                </div>
            `;
            fileList.appendChild(fileItemDiv);
        });
        
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
    
    // Make the file input accept multiple files
    if (fileInput) {
        fileInput.setAttribute('multiple', 'true');
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
        uploadBtn.addEventListener('click', uploadFiles);
    }
    
    if (downloadBtn) {
        downloadBtn.addEventListener('click', downloadFiles);
    }
    
    // Update placeholder texts to reflect multiple file capability
    document.querySelectorAll('.input-prompt').forEach(prompt => {
        if (prompt.textContent.includes('file ID')) {
            prompt.textContent = 'Enter file ID(s) - separate multiple IDs with commas';
        }
    });
    
    document.querySelectorAll('.placeholder-text').forEach(text => {
        if (text.textContent.includes('Choose a file')) {
            text.textContent = 'Choose files or drag & drop';
        }
    });
});