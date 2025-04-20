const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

// Initialize Express
const app = express();
const PORT = process.env.PORT || 3000;

// Configure upload directory
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Multer configuration - only for non-encrypted files
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, `${uuidv4()}${path.extname(file.originalname)}`)
});

const upload = multer({
  storage,
  limits: { fileSize: 100 * 1024 * 1024 } // 100MB limit
});

// In-memory database (transition to DB in production)
const fileDatabase = {};

// Middleware
app.use(express.json({ limit: '100mb' })); // Increased JSON limit for large base64 strings
app.use(express.static(__dirname));
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  next();
});

// Debug middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.path}`);
  next();
});

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// New endpoint for direct JSON uploads (encrypted files)
app.post('/api/upload', (req, res) => {
  try {
    // Check if we have encrypted content directly in the JSON body
    if (req.body && req.body.encryptedContent) {
      const fileId = uuidv4();
      
      // Store the file details without writing to disk
      fileDatabase[fileId] = {
        originalName: req.body.originalName || 'encrypted-file',
        encryptedContent: req.body.encryptedContent,
        isEncrypted: true,
        uploadedAt: new Date()
      };

      console.log(`File uploaded with ID: ${fileId}`);
      
      return res.json({ 
        success: true, 
        fileId,
        downloadLink: `/api/files/${fileId}`
      });
    } 
    else {
      throw new Error('Invalid request: No file data provided');
    }
  } catch (error) {
    console.error(`Upload Error: ${error.message}`);
    res.status(500).json({ 
      error: error.message || 'Server error during upload' 
    });
  }
});

// Download endpoint - modified to handle encrypted content
app.get('/api/files/:fileId', (req, res) => {
  try {
    const fileId = req.params.fileId;
    const fileInfo = fileDatabase[fileId];
    
    if (!fileInfo) {
      console.log(`File not found: ${fileId}`);
      return res.status(404).json({ error: 'File not found' });
    }
    
    console.log(`File request for ID: ${fileId}, Name: ${fileInfo.originalName}`);
    
    // For encrypted files, return the content directly
    if (fileInfo.isEncrypted && fileInfo.encryptedContent) {
      return res.json({
        fileName: fileInfo.originalName,
        encryptedContent: fileInfo.encryptedContent
      });
    }
    
    // For regular files, send as download
    res.download(fileInfo.path, fileInfo.originalName, (err) => {
      if (err) {
        console.error(`Download Error: ${err.message}`);
        return res.status(500).json({ error: 'Download failed' });
      }
    });
  } catch (error) {
    console.error(`File retrieval error: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Server initialization
app.listen(PORT, () => {
  console.log(`Server operational on port ${PORT}`);
  console.log(`Access interface: http://localhost:${PORT}`);
});