// File: server.js (Updated Backend)
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const mongoose = require('mongoose');
const { ImageAnnotatorClient } = require('@google-cloud/vision');
const { OpenAI } = require('openai');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const PDFDocument = require('pdfkit');

// Initialize Express App
const app = express();
const PORT = process.env.PORT || 3000;

// Validate and format MongoDB URI
const getValidMongoDBURI = (uri) => {
  if (!uri) {
    console.error('MongoDB URI is not provided in environment variables');
    return null;
  }
  
  // Check if URI already has the correct format
  if (uri.startsWith('mongodb://') || uri.startsWith('mongodb+srv://')) {
    return uri;
  }
  
  // If it's not in the correct format but looks like a MongoDB URI, add the prefix
  if (uri.includes('@') && (uri.includes('.mongodb.net') || uri.includes('.mongo.cosmos'))) {
    return `mongodb+srv://${uri}`;
  }
  
  console.error('Invalid MongoDB URI format, unable to automatically correct');
  return null;
};

// Enhanced MongoDB Atlas Connection
const connectDB = async () => {
  try {
    // Validate and fix MongoDB URI format
    let uri = process.env.MONGODB_URI || '';
    
    // Make sure the URI has the proper protocol
    if (!uri.startsWith('mongodb://') && !uri.startsWith('mongodb+srv://')) {
      console.log('Adding MongoDB protocol prefix to URI');
      uri = 'mongodb+srv://' + uri;
    }
    
    // Check if we need to encode the password in the URI
    const uriRegex = /^mongodb(\+srv)?:\/\/([^:]+):([^@]+)@(.+)$/;
    const match = uri.match(uriRegex);
    
    if (match) {
      // Extract parts of the connection string
      const protocol = match[1] ? 'mongodb+srv://' : 'mongodb://';
      const username = match[2];
      let password = match[3];
      const hostAndRest = match[4];
      
      // Check if password contains special characters that need encoding
      if (password.includes('%') === false && 
          (password.includes('@') || password.includes('/') || 
           password.includes(':') || password.includes('#') || 
           password.includes(' ') || password.includes('+'))) {
        console.log('Password contains special characters, encoding it');
        password = encodeURIComponent(password);
      }
      
      // Rebuild the URI with encoded password
      uri = `${protocol}${username}:${password}@${hostAndRest}`;
      console.log('Using properly encoded MongoDB URI');
      
      // Append SSL parameters to the URI if not already present
      if (!uri.includes('ssl=')) {
        uri += (uri.includes('?') ? '&' : '?') + 'ssl=true';
      }
      
      // Add TLS version specification
      if (!uri.includes('tls=')) {
        uri += '&tls=true';
      }
      
      console.log('Added SSL/TLS parameters to URI');
    }
    
    // Use direct connection without Atlas proxy layer
    const useDirectConnection = true;
    console.log('Using direct connection:', useDirectConnection);
    
    // Configure Node.js TLS settings for MongoDB specifically
    try {
      // Set NODE_TLS_REJECT_UNAUTHORIZED temporarily to allow self-signed certificates
      // This is not ideal for production but helps diagnose the connection issue
      process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
      console.log('Temporarily disabled TLS certificate validation');
    } catch (tlsEnvError) {
      console.warn('Could not set TLS environment variable:', tlsEnvError.message);
    }
    
    // Try connecting with multiple TLS versions
    const connectWithTLSVersion = async (tlsVersion) => {
      try {
        console.log(`Attempting MongoDB connection with ${tlsVersion || 'default'} TLS settings...`);
        
        const options = {
          useNewUrlParser: true,
          useUnifiedTopology: true,
          ssl: true,
          sslValidate: false,
          tlsAllowInvalidCertificates: true,
          tlsAllowInvalidHostnames: true,
          directConnection: useDirectConnection,
          retryWrites: true,
          w: 'majority',
          serverSelectionTimeoutMS: 30000,
          connectTimeoutMS: 30000
        };
        
        // Add TLS version specific settings
        if (tlsVersion === 'TLSv1.2') {
          options.tls = true;
          options.tlsCAFile = undefined; // Don't use a CA file
          options.tlsCertificateKeyFile = undefined;
          options.tlsInsecure = true; // Bypass certificate validation
        } else if (tlsVersion === 'TLSv1.1') {
          options.tls = true;
          options.tlsInsecure = true;
        } else if (tlsVersion === 'TLSv1.0') {
          options.tls = true;
          options.tlsInsecure = true;
        }
        
        await mongoose.connect(uri, options);
        console.log(`MongoDB Connected successfully using ${tlsVersion || 'default'} TLS settings`);
        return true;
      } catch (error) {
        console.error(`Connection failed with ${tlsVersion || 'default'} TLS settings:`, error.message);
        return false;
      }
    };
    
    // Try different TLS versions in sequence
    const tlsVersions = [null, 'TLSv1.2', 'TLSv1.1', 'TLSv1.0'];
    let connected = false;
    
    for (const version of tlsVersions) {
      connected = await connectWithTLSVersion(version);
      if (connected) break;
    }
    
    if (!connected) {
      // Try one last approach: direct connection string modification
      console.log('All TLS version attempts failed. Trying with modified connection string...');
      
      // Remove any existing tls or ssl parameters
      let modifiedUri = uri.replace(/[?&]tls=(true|false)/gi, '')
                           .replace(/[?&]ssl=(true|false)/gi, '');
                           
      // Add our custom parameters
      modifiedUri += (modifiedUri.includes('?') ? '&' : '?') + 
                     'ssl=true&tls=true&tlsInsecure=true&readPreference=primary&retryWrites=true&maxIdleTimeMS=120000';
      
      try {
        await mongoose.connect(modifiedUri, {
          useNewUrlParser: true,
          useUnifiedTopology: true,
          ssl: true,
          tls: true,
          tlsInsecure: true,
          directConnection: useDirectConnection,
          serverSelectionTimeoutMS: 30000,
          connectTimeoutMS: 30000
        });
        console.log('MongoDB Connected successfully with modified connection string');
        connected = true;
      } catch (finalError) {
        console.error('Final connection attempt failed:', finalError.message);
        throw finalError; // Rethrow to be caught by the outer catch
      }
    }
    
    // Reset TLS environment variable to secure default
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';
    
  } catch (err) {
    console.error('Database Connection Error:', err);
    
    // Provide helpful diagnostics and guidance based on error type
    if (err.name === 'MongooseServerSelectionError' || 
        err.message?.includes('ENOTFOUND') ||
        err.message?.includes('SSL') ||
        err.message?.includes('TLS')) {
      
      console.error('\n===== MONGODB CONNECTION TROUBLESHOOTING =====');
      
      if (err.message?.includes('IP whitelist')) {
        console.error('\nIP WHITELIST ISSUE: Your Heroku app IP is not whitelisted in MongoDB Atlas.');
        console.error('To fix this:');
        console.error('1. Go to your MongoDB Atlas dashboard');
        console.error('2. Navigate to Network Access');
        console.error('3. Add 0.0.0.0/0 to whitelist all IPs temporarily (change after testing)');
        console.error('   OR add the specific Heroku IP ranges (see Heroku documentation)');
      }
      
      if (err.message?.includes('SSL') || err.message?.includes('TLS') || err.message?.includes('certificate') ||
          err.message?.includes('routines') || err.message?.includes('alert internal error')) {
          
        console.error('\nSSL/TLS ISSUE: There are problems with the secure connection to MongoDB.');
        console.error('This appears to be a TLS version compatibility issue with Heroku and MongoDB Atlas.');
        console.error('Try these fixes:');
        console.error('1. In MongoDB Atlas, go to "Advanced Connection Options" and check "Use TLS/SSL" option');
        console.error('2. Use a direct connection string from MongoDB Atlas under "Connect your application"');
        console.error('3. Make sure to select "Node.js" and version "4.0 or later" when getting the connection string');
        console.error('4. Try switching from mongodb+srv:// protocol to mongodb:// with full hostname list');
      }
      
      console.error('\nMONGODB URI FORMAT:');
      console.error('Your connection string should look like:');
      console.error('mongodb+srv://<username>:<password>@<cluster>.mongodb.net/<dbname>?retryWrites=true&w=majority');
      console.error('\nTry the helper tool: node heroku-env-helper.js to generate a properly formatted URI');
      console.error('================================================\n');
    }
    
    // Keep app running even if database connection fails in production
    if (process.env.NODE_ENV !== 'production') {
      console.error('Exiting due to database connection failure in development mode');
      process.exit(1);
    } else {
      console.warn('Continuing without database connection in production mode');
      console.warn('Your app will have limited functionality without database access');
      console.warn('Try setting MONGODB_URI manually from the MongoDB Atlas dashboard');
      console.warn('Run: heroku config:set MONGODB_URI="mongodb+srv://..."');
    }
  }
};

// Connect to MongoDB
connectDB();

// AI Clients Configuration
let visionClient;
try {
  // Check if running on Heroku (where we'd use the JSON string in env var)
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
    try {
      // Make sure we parse valid JSON - try different approaches to handle various formats
      let credentials;
      const credentialString = process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON;
      
      console.log('Attempting to process Google credentials from environment variable');
      
      // Heroku often formats environment variables in unexpected ways, try multiple methods
      const parseAttempts = [
        // Method 1: Direct parsing
        () => {
          try {
            return JSON.parse(credentialString);
          } catch (e) {
            return null;
          }
        },
        
        // Method 2: Handle quoted strings
        () => {
          try {
            if (credentialString.startsWith('"') && credentialString.endsWith('"')) {
              return JSON.parse(credentialString.substring(1, credentialString.length - 1));
            }
            return null;
          } catch (e) {
            return null;
          }
        },
        
        // Method 3: Double-parsing for doubly stringified JSON
        () => {
          try {
            return JSON.parse(JSON.parse(credentialString));
          } catch (e) {
            return null;
          }
        },
        
        // Method 4: Clean up common issues and try parsing
        () => {
          try {
            const cleaned = credentialString
              .replace(/\\n/g, '')
              .replace(/\\"/g, '"')
              .replace(/"{/g, '{')
              .replace(/}"/g, '}')
              .replace(/^['"]|['"]$/g, '');
            return JSON.parse(cleaned);
          } catch (e) {
            return null;
          }
        },
        
        // Method 5: For credentials that might be Base64 encoded
        () => {
          try {
            if (/^[A-Za-z0-9+/=]+$/.test(credentialString)) {
              const decoded = Buffer.from(credentialString, 'base64').toString('utf-8');
              return JSON.parse(decoded);
            }
            return null;
          } catch (e) {
            return null;
          }
        },
        
        // Method 6: Last resort - split by newlines and try to reconstruct a valid JSON
        () => {
          try {
            if (credentialString.includes('\n')) {
              const lines = credentialString.split('\n').map(line => line.trim());
              const jsonStr = lines.join('');
              return JSON.parse(jsonStr);
            }
            return null;
          } catch (e) {
            return null;
          }
        }
      ];
      
      // Try each parsing method until one works
      for (const attempt of parseAttempts) {
        credentials = attempt();
        if (credentials) {
          console.log('Successfully parsed Google credentials');
          break;
        }
      }
      
      // If all parsing attempts failed
      if (!credentials) {
        // Log the credential string format (safely) to help debugging
        console.log('All parsing methods failed. Credential string format:');
        console.log(`- Length: ${credentialString.length}`);
        console.log(`- First 20 chars: ${credentialString.substring(0, 20)}...`);
        console.log(`- Contains brackets: ${credentialString.includes('{') && credentialString.includes('}')}`);
        console.log(`- Contains quotes: ${credentialString.includes('"')}`);
        console.log(`- Contains escaped chars: ${credentialString.includes('\\')}`);
        
        throw new Error('Failed to parse credentials in any format');
      }
      
      // Validate that we have the minimum required fields for a service account
      if (!credentials.type || !credentials.project_id) {
        console.log('Invalid credentials structure. Available keys:', Object.keys(credentials).join(', '));
        throw new Error('Invalid Google credentials format - missing required fields');
      }
      
      visionClient = new ImageAnnotatorClient({ credentials });
      console.log('Vision API client initialized successfully with JSON credentials');
    } catch (jsonError) {
      console.error('Error processing Google credentials:', jsonError.message);
      // Create a fallback client
      visionClient = createMockVisionClient();
    }
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    // Local development (where we use the file path)
    try {
      visionClient = new ImageAnnotatorClient({
        keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
      });
      console.log('Vision API client initialized successfully with keyfile');
    } catch (fileError) {
      console.error('Error loading Google credentials file:', fileError.message);
      visionClient = createMockVisionClient();
    }
  } else {
    console.warn('No Google Cloud credentials provided, using mock client');
    visionClient = createMockVisionClient();
  }
} catch (error) {
  console.error('Error initializing Vision client:', error);
  visionClient = createMockVisionClient();
}

// Create a mock Vision client for fallback
function createMockVisionClient() {
  console.warn('Using mock Vision API client - OCR functionality will be limited');
  return {
    documentTextDetection: async () => {
      console.warn('Called mock documentTextDetection');
      return [{ fullTextAnnotation: { text: 'Mock OCR text for testing. Please check your Google Cloud Vision API configuration.' } }];
    }
  };
}

// Initialize OpenAI API client
const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 30000,
  maxRetries: 3
});

// Session Configuration with proper MongoDB URI handling
const sessionConfig = {
  secret: process.env.SESSION_SECRET || 'fallback_session_secret',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
};

// Use MongoStore for session storage if MongoDB URI is available
if (process.env.MONGODB_URI) {
  try {
    // Process the MongoDB URI for session store (similar to connectDB)
    let uri = process.env.MONGODB_URI;
    
    // Make sure the URI has the proper protocol
    if (!uri.startsWith('mongodb://') && !uri.startsWith('mongodb+srv://')) {
      uri = 'mongodb+srv://' + uri;
    }
    
    // Encode password if needed
    const uriRegex = /^mongodb(\+srv)?:\/\/([^:]+):([^@]+)@(.+)$/;
    const match = uri.match(uriRegex);
    
    if (match) {
      const protocol = match[1] ? 'mongodb+srv://' : 'mongodb://';
      const username = match[2];
      let password = match[3];
      const hostAndRest = match[4];
      
      if (password.includes('%') === false && 
          (password.includes('@') || password.includes('/') || 
           password.includes(':') || password.includes('#') || 
           password.includes(' ') || password.includes('+'))) {
        password = encodeURIComponent(password);
      }
      
      uri = `${protocol}${username}:${password}@${hostAndRest}`;
    }
    
    console.log('Initializing MongoStore for session storage');
    sessionConfig.store = MongoStore.create({
      mongoUrl: uri,
      ttl: 14 * 24 * 60 * 60, // 14 days
      autoRemove: 'native',
      touchAfter: 24 * 3600 // 24 hours
    });
  } catch (sessionErr) {
    console.error('Error initializing MongoStore:', sessionErr.message);
    console.log('Falling back to in-memory session store');
  }
}

// Express App Configuration
app.use(express.json()); // Support for JSON payloads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 } // Limit file size to 20MB
});

// Add basic health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Database Schemas
// User Schema
const UserSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 50
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: [/.+\@.+\..+/, 'Please fill a valid email address']
  },
  password: {
    type: String,
    required: true,
    minlength: 6,
    maxlength: 1024, // For hashed password
    select: false // Don't send password in normal queries
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date
  }
}, { timestamps: true });

// Content Schema with user reference
const ContentSchema = new mongoose.Schema({
  sessionId: { type: String, index: true },
  userId: { 
    type: mongoose.Schema.Types.ObjectId, 
    ref: 'User',
    index: true
  },
  title: {
    type: String,
    default: "Untitled Document"
  },
  content: {
    text: String,
    flashcards: [{
      question: String,
      answer: String,
      confidence: Number,
      tags: [String]
    }],
    quizzes: [{
      question: String,
      options: [String],
      answer: String,
      explanation: String
    }],
    summary: String,
    metadata: {
      pages: Number,
      languages: [String],
      processedAt: Date,
      contentType: String, // 'text', 'image', 'pdf'
      source: String // 'upload', 'direct-input'
    }
  }
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Content = mongoose.model('Content', ContentSchema);

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    // Check if user is authenticated via session
    if (req.session.userId) {
      const user = await User.findById(req.session.userId);
      if (!user) {
        return res.status(401).json({ error: 'Authentication required' });
      }
      req.user = user;
      return next();
    }
    
    // Check if user is authenticated via token
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'splanAI-jwt-secret');
    const user = await User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(401).json({ error: 'Authentication required' });
  }
};

// Process text regardless of source (OCR or direct input)
const processTextContent = async (text, sessionId, metadata = {}, userId = null) => {
  try {
    // Trim and validate input
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      throw new Error('Invalid or empty text content');
    }
    
    const fullText = text.trim();
    
    // AI Processing with OpenAI
    console.log('Processing with OpenAI, text length:', fullText.length);
    
    const [summaryResponse, flashcardsResponse, quizzesResponse] = await Promise.all([
      openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: `Summarize this in three paragraphs:\n${fullText}` }]
      }),
      openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ 
          role: 'user', 
          content: `Generate 5 flashcards from this text in the following JSON format:
          [
            {
              "question": "Question here?",
              "answer": "Answer here",
              "confidence": 0.9,
              "tags": ["tag1", "tag2"]
            }
          ]
          Text: ${fullText}` 
        }]
      }),
      openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ 
          role: 'user', 
          content: `Create 3 quiz questions based on this text in the following JSON format:
          [
            {
              "question": "Question here?",
              "options": ["Option A", "Option B", "Option C", "Option D"],
              "answer": "Option A",
              "explanation": "Explanation here"
            }
          ]
          Text: ${fullText}` 
        }]
      })
    ]);

    // Parse JSON responses with error handling
    let flashcards, quizzes;
    try {
      const flashcardsContent = flashcardsResponse.choices[0].message.content;
      flashcards = JSON.parse(flashcardsContent);
    } catch (e) {
      console.error('Failed to parse flashcards JSON:', e);
      flashcards = [{ 
        question: "What is this document about?", 
        answer: "See summary for details", 
        confidence: 0.5, 
        tags: ["auto-generated"] 
      }];
    }

    try {
      const quizzesContent = quizzesResponse.choices[0].message.content;
      quizzes = JSON.parse(quizzesContent);
    } catch (e) {
      console.error('Failed to parse quizzes JSON:', e);
      quizzes = [{ 
        question: "What is the main topic of this document?", 
        options: ["Option A", "Option B", "Option C", "Option D"], 
        answer: "See summary for details", 
        explanation: "Auto-generated fallback question" 
      }];
    }

    // Generate a title for the document
    let title = "Untitled Document";
    if (fullText.length > 10) {
      try {
        const titleResponse = await openai.chat.completions.create({
          model: 'gpt-4',
          messages: [{ 
            role: 'user', 
            content: `Generate a short, descriptive title (5-7 words) for this document:\n${fullText.substring(0, 500)}...` 
          }]
        });
        title = titleResponse.choices[0].message.content.trim().replace(/^["'](.*)["']$/, '$1');
      } catch (e) {
        console.error('Failed to generate title:', e);
      }
    }

    // Save to Database
    const contentDoc = new Content({
      sessionId,
      userId: userId, // Link to user if authenticated
      title: title,
      content: {
        text: fullText,
        flashcards: flashcards,
        quizzes: quizzes,
        summary: summaryResponse.choices[0].message.content,
        metadata: {
          pages: 1,
          languages: ['en'],
          processedAt: new Date(),
          ...metadata
        }
      }
    });

    await contentDoc.save();
    return contentDoc;
  } catch (error) {
    console.error('AI Processing Error:', error);
    throw new Error('Advanced content processing failed: ' + error.message);
  }
};

// Enhanced AI Processing Pipeline for file uploads
const processContent = async (buffer, sessionId, fileType, userId = null) => {
  try {
    // Detect content type and handle accordingly
    let fullText = '';
    let contentType = 'unknown';
    
    // Handle different file types
    if (fileType && fileType.includes('image')) {
      // Image files - use Vision API for OCR
      contentType = 'image';
      const [ocrResult] = await visionClient.documentTextDetection({
        image: { content: buffer.toString('base64') }
      });
      fullText = ocrResult.fullTextAnnotation?.text || '';
    } else if (fileType && fileType.includes('pdf')) {
      // PDF files - use Vision API for OCR
      contentType = 'pdf';
      const [ocrResult] = await visionClient.documentTextDetection({
        image: { content: buffer.toString('base64') }
      });
      fullText = ocrResult.fullTextAnnotation?.text || '';
    } else {
      // Try to extract as text
      contentType = 'text';
      try {
        fullText = buffer.toString('utf8');
      } catch (e) {
        throw new Error('Unsupported file type or corrupted file');
      }
    }

    if (!fullText || fullText.trim().length === 0) {
      throw new Error('Could not extract text from the uploaded file');
    }

    // Process the extracted text
    return processTextContent(fullText, sessionId, {
      contentType,
      source: 'upload'
    }, userId);
  } catch (error) {
    console.error('AI Processing Error:', error);
    throw new Error('Advanced content processing failed: ' + error.message);
  }
};

// =================== MIDDLEWARE ===================

// Security configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", 'https://*.openai.com'],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com', 'https://cdnjs.cloudflare.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com', 'https://cdnjs.cloudflare.com'],
      imgSrc: ["'self'", 'data:', 'https://cdn-icons-png.flaticon.com'],
    },
  },
}));
app.use(cors({
  origin: process.env.CLIENT_URL || '*',
  credentials: true
}));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // Limit each IP to 100 requests per windowMs
  max: 100
}));

// Session configuration
app.use(session(sessionConfig));

// =================== API Endpoints ===================

// User Authentication Routes
// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }
    
    // Check if user already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ error: 'User with this email or username already exists' });
    }
    
    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    
    // Create new user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });
    
    await user.save();
    
    // Create session
    req.session.userId = user._id;
    
    // Create JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'splanAI-jwt-secret',
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: error.message || 'Error registering user' });
  }
});

// Login User
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    // Validate input
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    
    // Find user
    const user = await User.findOne({ email }).select('+password');
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    
    // Update last login
    user.lastLogin = new Date();
    await user.save();
    
    // Create session
    req.session.userId = user._id;
    
    // Create JWT
    const token = jwt.sign(
      { userId: user._id }, 
      process.env.JWT_SECRET || 'splanAI-jwt-secret',
      { expiresIn: '7d' }
    );
    
    res.status(200).json({
      message: 'Login successful',
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      },
      token
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: error.message || 'Error logging in' });
  }
});

// Logout User
app.post('/api/auth/logout', (req, res) => {
  try {
    req.session.destroy(err => {
      if (err) {
        return res.status(500).json({ error: 'Could not log out, please try again' });
      }
      res.clearCookie('connect.sid');
      res.status(200).json({ message: 'Logged out successfully' });
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: error.message || 'Error logging out' });
  }
});

// Get Current User
app.get('/api/auth/me', auth, (req, res) => {
  try {
    res.status(200).json({
      user: {
        id: req.user._id,
        username: req.user.username,
        email: req.user.email,
        role: req.user.role,
        createdAt: req.user.createdAt,
        lastLogin: req.user.lastLogin
      }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: error.message || 'Error getting user data' });
  }
});

// Content Routes
// Process file upload
app.post('/api/process', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Get user ID if authenticated
    const userId = req.session.userId || null;
    
    const sessionId = uuidv4();
    const fileType = req.file.mimetype;
    
    console.log(`Processing uploaded file: ${fileType}`);
    const result = await processContent(req.file.buffer, sessionId, fileType, userId);
    
    res.json({ 
      sessionId, 
      content: result.content,
      title: result.title,
      message: 'File processed successfully' 
    });
  } catch (error) {
    console.error('Error processing file:', error);
    res.status(500).json({ error: error.message || 'Unknown error occurred' });
  }
});

// Process direct text input
app.post('/api/process-text', express.json(), async (req, res) => {
  try {
    const { text, title } = req.body;
    
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      return res.status(400).json({ error: 'Text input is required' });
    }
    
    // Get user ID if authenticated
    const userId = req.session.userId || null;
    
    const sessionId = uuidv4();
    console.log(`Processing direct text input, length: ${text.length}`);
    
    const result = await processTextContent(text, sessionId, {
      contentType: 'text',
      source: 'direct-input'
    }, userId);
    
    // If title provided, update the document
    if (title && title.trim()) {
      result.title = title.trim();
      await result.save();
    }
    
    res.json({ 
      sessionId, 
      content: result.content,
      title: result.title,
      message: 'Text processed successfully' 
    });
  } catch (error) {
    console.error('Error processing text:', error);
    res.status(500).json({ error: error.message || 'Unknown error occurred' });
  }
});

// Get content by session ID
app.get('/api/content/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }
    
    const content = await Content.findOne({ sessionId });
    
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }
    
    res.json({ 
      content: content.content,
      title: content.title,
      id: content._id,
      sessionId: content.sessionId
    });
  } catch (error) {
    console.error('Error retrieving content:', error);
    res.status(500).json({ error: error.message || 'Unknown error occurred' });
  }
});

// Get user's content (requires authentication)
app.get('/api/user/content', auth, async (req, res) => {
  try {
    const userId = req.user._id;
    
    // Get list of user's content (just basic info, not full content)
    const userContent = await Content.find(
      { userId }, 
      { 
        title: 1, 
        sessionId: 1, 
        createdAt: 1, 
        'content.metadata': 1 
      }
    ).sort({ createdAt: -1 });
    
    res.json({ content: userContent });
  } catch (error) {
    console.error('Error retrieving user content:', error);
    res.status(500).json({ error: error.message || 'Unknown error occurred' });
  }
});

// Download content as PDF
app.get('/api/content/:sessionId/download/pdf', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }
    
    const content = await Content.findOne({ sessionId });
    
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }
    
    // Create a PDF document
    const doc = new PDFDocument();
    
    // Set response headers
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename=${content.title.replace(/\s+/g, '_')}.pdf`);
    
    // Pipe PDF to response
    doc.pipe(res);
    
    // Add content to PDF
    doc.fontSize(24).text(`${content.title}`, { align: 'center' });
    doc.moveDown();
    
    // Summary section
    doc.fontSize(18).text('Summary', { underline: true });
    doc.fontSize(12).text(content.content.summary);
    doc.moveDown(2);
    
    // Flashcards section
    doc.fontSize(18).text('Flashcards', { underline: true });
    doc.moveDown();
    
    content.content.flashcards.forEach((flashcard, index) => {
      doc.fontSize(14).text(`Flashcard ${index + 1}`);
      doc.fontSize(12).text(`Question: ${flashcard.question}`);
      doc.fontSize(12).text(`Answer: ${flashcard.answer}`);
      
      if (flashcard.tags && flashcard.tags.length) {
        doc.fontSize(10).text(`Tags: ${flashcard.tags.join(', ')}`);
      }
      
      doc.moveDown();
    });
    
    doc.moveDown();
    
    // Quiz section
    doc.fontSize(18).text('Quiz Questions', { underline: true });
    doc.moveDown();
    
    content.content.quizzes.forEach((quiz, index) => {
      doc.fontSize(14).text(`Question ${index + 1}: ${quiz.question}`);
      
      quiz.options.forEach(option => {
        doc.fontSize(12).text(`□ ${option}`);
      });
      
      doc.fontSize(12).text(`Answer: ${quiz.answer}`);
      
      if (quiz.explanation) {
        doc.fontSize(12).text(`Explanation: ${quiz.explanation}`);
      }
      
      doc.moveDown();
    });
    
    // Finalize the PDF
    doc.end();
  } catch (error) {
    console.error('Error generating PDF:', error);
    res.status(500).json({ error: error.message || 'Error generating PDF' });
  }
});

// Download flashcards as CSV
app.get('/api/content/:sessionId/download/flashcards', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }
    
    const content = await Content.findOne({ sessionId });
    
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }
    
    // Set response headers
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename=${content.title.replace(/\s+/g, '_')}_flashcards.csv`);
    
    // Create CSV content
    let csvContent = 'Question,Answer,Tags\n';
    
    content.content.flashcards.forEach(flashcard => {
      // Properly escape CSV fields
      const question = `"${flashcard.question.replace(/"/g, '""')}"`;
      const answer = `"${flashcard.answer.replace(/"/g, '""')}"`;
      const tags = flashcard.tags && flashcard.tags.length 
        ? `"${flashcard.tags.join(', ').replace(/"/g, '""')}"`
        : '""';
      
      csvContent += `${question},${answer},${tags}\n`;
    });
    
    res.send(csvContent);
  } catch (error) {
    console.error('Error generating CSV:', error);
    res.status(500).json({ error: error.message || 'Error generating CSV' });
  }
});

// Support for both production and development environments
if (process.env.NODE_ENV === 'production') {
  // Serve static files from the React app
  app.use(express.static(path.join(__dirname, 'public')));
  
  // For any request that doesn't match one above, send back React's index.html file
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
} else {
  // Development mode - serve only the API endpoints
  app.use(express.static(path.join(__dirname, 'public')));
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });
}

// Server Start with proper error handling
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});
