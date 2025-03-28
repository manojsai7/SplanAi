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

// Enhanced MongoDB Atlas Connection
const connectDB = async () => {
  try {
    // 1. Get MongoDB URI from Heroku config
    let uri = process.env.MONGODB_URI;
    if (!uri) {
      console.warn(" MONGODB_URI not set in environment variables");
      return false;
    }

    // 2. Encode password (fixes special characters like @, /, etc.)
    uri = uri.replace(/(mongodb\+srv:\/\/[^:]+):([^@]+)@/, (match, username, password) => {
      const encodedPassword = encodeURIComponent(password);
      console.log(` Password encoded for MongoDB connection`);
      return `${username}:${encodedPassword}@`;
    });

    // 3. Add SSL/TLS options for Heroku if missing
    if (!uri.includes("ssl=")) {
      uri += (uri.includes("?") ? "&" : "?") + "ssl=true";
    }
    
    if (!uri.includes("tls=")) {
      uri += "&tls=true";
    }
    
    // Add retryWrites if not already in the URI
    if (!uri.includes("retryWrites=")) {
      uri += "&retryWrites=true";
    }
    
    // Add maxPoolSize for better connection management
    if (!uri.includes("maxPoolSize=")) {
      uri += "&maxPoolSize=10";
    }
    
    console.log(" Connecting to MongoDB Atlas...");

    // 4. MongoDB Connection Options - carefully configured for Heroku + MongoDB Atlas
    const options = {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      ssl: true,
      tls: true,
      tlsInsecure: process.env.NODE_ENV === 'production', // Only bypass in production (Heroku)
      retryWrites: true,
      w: "majority",
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 30000,
      connectTimeoutMS: 30000,
      socketTimeoutMS: 45000
    };

    // 5. Connect to MongoDB
    await mongoose.connect(uri, options);
    console.log(" MongoDB Connected Successfully!");
    return true;
  } catch (err) {
    console.error(" MongoDB Connection Error:", err.message);
    
    // Helpful error messages
    if (err.message.includes("ENOTFOUND")) {
      console.error(" DNS Error: Check your MongoDB URI hostname!");
    } else if (err.message.includes("SSL") || err.message.includes("TLS")) {
      console.error(" TLS/SSL Error: Try updating the connection string from MongoDB Atlas");
      console.error("   Make sure to select Node.js driver and version 4.0 or later");
    } else if (err.message.includes("whitelist")) {
      console.error(" IP Whitelist Error: Add 0.0.0.0/0 to your MongoDB Atlas Network Access");
    } 
    
    // Still continue in production mode, so the app doesn't crash on Heroku
    return false;
  }
};

// Call connectDB but don't exit on failure
const dbPromise = connectDB();

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

// Wait for database connection before starting server
dbPromise.then(connected => {
  // Set up MongoStore for session if MongoDB is connected
  if (connected && process.env.MONGODB_URI) {
    try {
      // Get the encoded MongoDB URI
      let uri = process.env.MONGODB_URI;
      
      // Encode password
      uri = uri.replace(/(mongodb\+srv:\/\/[^:]+):([^@]+)@/, (match, username, password) => {
        return `${username}:${encodeURIComponent(password)}@`;
      });
      
      // Add SSL parameters if needed
      if (!uri.includes("ssl=")) uri += (uri.includes("?") ? "&" : "?") + "ssl=true";
      if (!uri.includes("tls=")) uri += "&tls=true";
      
      console.log(' Setting up MongoDB session store');
      sessionConfig.store = MongoStore.create({
        mongoUrl: uri,
        ttl: 14 * 24 * 60 * 60, // 14 days
        autoRemove: 'native',
        touchAfter: 24 * 3600, // 24 hours
        collectionName: 'sessions',
        crypto: {
          secret: process.env.SESSION_SECRET || 'fallback_session_secret'
        },
        mongoOptions: {
          useNewUrlParser: true,
          useUnifiedTopology: true,
          ssl: true,
          tls: true,
          tlsInsecure: true
        }
      });
    } catch (sessionErr) {
      console.error(' Error initializing MongoStore:', sessionErr.message);
      console.log(' Falling back to in-memory session store');
    }
  } else {
    console.log(' Using in-memory session store (MongoDB not connected)');
  }
  
  // Start the server after DB connection attempt
  app.listen(PORT, () => {
    console.log(` Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
  });
});

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

// Chat History Schema
const ChatHistorySchema = new mongoose.Schema({
  sessionId: {
    type: String,
    required: true,
    index: true
  },
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User'
  },
  messages: [{
    role: {
      type: String,
      enum: ['user', 'assistant', 'system'],
      required: true
    },
    content: {
      type: String,
      required: true
    },
    timestamp: {
      type: Date,
      default: Date.now
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const User = mongoose.model('User', UserSchema);
const Content = mongoose.model('Content', ContentSchema);
const ChatHistory = mongoose.model('ChatHistory', ChatHistorySchema);

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
    
    // Use gpt-3.5-turbo model instead of gpt-4 for better compatibility
    const MODEL = 'gpt-3.5-turbo';
    
    try {
      const [summaryResponse, flashcardsResponse, quizzesResponse] = await Promise.all([
        openai.chat.completions.create({
          model: MODEL,
          messages: [{ role: 'user', content: `Summarize this in three paragraphs:\n${fullText}` }],
          temperature: 0.7,
          max_tokens: 500
        }),
        openai.chat.completions.create({
          model: MODEL,
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
          }],
          temperature: 0.7,
          response_format: { type: "json_object" },
          max_tokens: 1000
        }),
        openai.chat.completions.create({
          model: MODEL,
          messages: [{ 
            role: 'user', 
            content: `Generate 3 multiple-choice questions with answers from this text in the following format:
            [
              {
                "question": "Question text here?",
                "options": ["Option A", "Option B", "Option C", "Option D"],
                "answer": "Option A",
                "explanation": "Brief explanation here"
              }
            ]
            Text: ${fullText}` 
          }],
          temperature: 0.7,
          response_format: { type: "json_object" },
          max_tokens: 1000
        }),
      ]);
      
      console.log('✅ AI processing completed successfully');
      
      // Extract content from responses
      const summary = summaryResponse.choices[0]?.message?.content?.trim() || '';
      let flashcards = [];
      let quizzes = [];
      
      try {
        // Parse JSON responses with error handling
        const flashcardsContent = flashcardsResponse.choices[0]?.message?.content?.trim() || '[]';
        flashcards = JSON.parse(extractJSONFromString(flashcardsContent));
        
        const quizzesContent = quizzesResponse.choices[0]?.message?.content?.trim() || '[]';
        quizzes = JSON.parse(extractJSONFromString(quizzesContent));
      } catch (jsonError) {
        console.error('Error parsing AI response JSON:', jsonError);
        // Create fallback content if parsing fails
        if (flashcards.length === 0) {
          flashcards = [{ question: "What is this text about?", answer: "Unable to generate specific flashcards", confidence: 0.5, tags: ["general"] }];
        }
        if (quizzes.length === 0) {
          quizzes = [{ 
            question: "What is the main topic discussed?", 
            options: ["Topic A", "Topic B", "Topic C", "Cannot determine"], 
            answer: "Cannot determine", 
            explanation: "Unable to generate specific questions from the text."
          }];
        }
      }
      
      // Generate title using the AI
      let title = metadata.title || '';
      
      if (!title) {
        try {
          const titleResponse = await openai.chat.completions.create({
            model: MODEL,
            messages: [{ 
              role: 'user', 
              content: `Create a very short title (5-7 words max) for this text:\n${fullText.substring(0, 1000)}...` 
            }],
            temperature: 0.7,
            max_tokens: 50
          });
          
          title = titleResponse.choices[0]?.message?.content?.trim() || 'Untitled Document';
        } catch (titleError) {
          console.error('Error generating title:', titleError);
          title = 'Untitled Document';
        }
      }
      
      // Save results to database if connected
      const contentData = {
        sessionId,
        title,
        originalText: fullText,
        summary,
        flashcards,
        quizzes,
        metadata: {
          ...metadata,
          processedAt: new Date(),
          textLength: fullText.length,
          processingStatus: 'completed'
        }
      };
      
      // If user is authenticated, associate content with user
      if (userId) {
        contentData.userId = userId;
      }
      
      // Save to database if mongoose is connected
      if (mongoose.connection.readyState === 1) {
        try {
          await Content.findOneAndUpdate(
            { sessionId },
            contentData,
            { upsert: true, new: true }
          );
          console.log('Content saved to database with sessionId:', sessionId);
        } catch (dbError) {
          console.error('Error saving to database:', dbError);
        }
      } else {
        console.log('Database not connected, skipping save');
      }
      
      return contentData;
    } catch (aiError) {
      console.error('AI Processing Error:', aiError);
      throw new Error(`Advanced content processing failed: ${aiError.message}`);
    }
  } catch (err) {
    console.error('Error processing text:', err);
    throw err;
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

// Chatbot API endpoint
app.post('/api/chatbot', async (req, res) => {
  try {
    const { message, sessionId } = req.body;
    
    if (!message) {
      return res.status(400).json({ error: 'Message is required' });
    }
    
    // Use gpt-3.5-turbo for chatbot functionality
    const response = await openai.chat.completions.create({
      model: 'gpt-3.5-turbo',
      messages: [
        {
          role: 'system',
          content: `You are a helpful study assistant for SplanAI, an app that helps students learn from their notes, documents, and images.
            SplanAI can create summaries, flashcards, and quizzes from uploaded content.
            Be friendly, concise, and helpful. If you don't know something, suggest using the app's features instead.
            Keep responses under 150 words to fit nicely in the chat interface.`
        },
        { role: 'user', content: message }
      ],
      temperature: 0.7,
      max_tokens: 300
    });
    
    const reply = response.choices[0]?.message?.content?.trim() || 
      "I'm sorry, I couldn't process your request. Please try again.";
    
    // Save chat history if connected to database and sessionId provided
    if (mongoose.connection.readyState === 1 && sessionId) {
      try {
        // Find or create a chat history document
        await ChatHistory.findOneAndUpdate(
          { sessionId },
          { 
            $push: { 
              messages: [
                { role: 'user', content: message },
                { role: 'assistant', content: reply }
              ]
            },
            $setOnInsert: { createdAt: new Date() },
            $set: { updatedAt: new Date() }
          },
          { upsert: true, new: true }
        );
      } catch (dbError) {
        console.error('Error saving chat history:', dbError);
      }
    }
    
    res.json({ reply });
  } catch (error) {
    console.error('Chatbot error:', error);
    res.status(500).json({ 
      error: 'Error processing your message',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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

function extractJSONFromString(str) {
  try {
    return JSON.parse(str);
  } catch (e) {
    return str;
  }
}
