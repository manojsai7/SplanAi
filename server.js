// File: server.js (Updated Backend)
require('dotenv').config();
const express = require('express');
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const { ImageAnnotatorClient } = require('@google-cloud/vision');
const fs = require('fs');
const PDFDocument = require('pdfkit');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// Modified MongoDB Atlas Connection to use await properly
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

    // IMPORTANT: Configure mongoose globally before connection
    mongoose.set('bufferCommands', false); // This is critical - disable buffering to prevent waiting for connection
    mongoose.set('autoIndex', false);  // Don't build indexes automatically in production
    
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
      socketTimeoutMS: 45000,
      bufferCommands: false, // Disable command buffering
      autoIndex: false // Don't build indexes automatically
    };

    // 5. Connect to MongoDB - with proper await
    const connection = await mongoose.connect(uri, options);
    console.log(" MongoDB Connected Successfully!");
    
    // Return the connection for further use if needed
    return connection;
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
    
    // Return null to indicate connection failure
    return null;
  }
};

// Initialize models at global scope with null declarations
let User = null;
let Content = null;
let ChatHistory = null;

// Define sessionConfig at the global scope before it's used
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
  },
  originalText: String,
  summary: String,
  flashcards: Array,
  quizzes: Array,
  metadata: Object
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

// Initialize the Google Generative AI client
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Initialize Google Cloud Vision API client
let visionClient;

try {
  // Check if running on Heroku (where we'd use the JSON string in env var)
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
    try {
      // Make sure we parse valid JSON - try different approaches to handle various formats
      let jsonCredentials = process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON;
      
      // Sometimes Heroku adds quotes around the JSON string
      if (jsonCredentials.startsWith('"') && jsonCredentials.endsWith('"')) {
        jsonCredentials = jsonCredentials.slice(1, -1);
      }
      
      // Handle escaped quotes
      jsonCredentials = jsonCredentials.replace(/\\"/g, '"');
      
      // Parse the JSON
      const credentials = JSON.parse(jsonCredentials);
      
      // Initialize the Vision client with the credentials
      visionClient = new ImageAnnotatorClient({ credentials });
      console.log('Vision API client initialized successfully with JSON credentials');
    } catch (jsonError) {
      console.error('Error processing Google credentials:', jsonError);
      // Create a fallback client
      visionClient = createMockVisionClient();
    }
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    // Local development with a credentials file
    try {
      // Initialize the Vision client with the credentials file
      visionClient = new ImageAnnotatorClient();
      console.log('Vision API client initialized successfully with keyfile');
    } catch (fileError) {
      console.error('Error loading Google credentials file:', fileError);
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
  console.warn(' Using mock Vision client - OCR functionality will be limited');
  return {
    documentTextDetection: async () => {
      console.warn('Called mock documentTextDetection');
      return [{ fullTextAnnotation: { text: 'Mock OCR text for testing. Please check your Google Cloud Vision API configuration.' } }];
    }
  };
}

// Authentication middleware
const auth = async (req, res, next) => {
  try {
    // First check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      console.warn('⚠️ Authentication attempted before MongoDB connection is ready');
      // For APIs that require auth, fail with clear message
      return res.status(503).json({ 
        error: 'Database connection not ready',
        message: 'The server database is currently connecting. Please try again in a moment.'
      });
    }
    
    // Check if user is authenticated via session
    if (req.session?.userId) {
      try {
        const user = await User.findById(req.session.userId);
        if (!user) {
          return res.status(401).json({ error: 'Authentication required' });
        }
        req.user = user;
        return next();
      } catch (dbError) {
        console.error('Database error during session auth:', dbError);
        return res.status(500).json({ error: 'Internal server error during authentication' });
      }
    }
    
    // Check if user is authenticated via token
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'splanAI-jwt-secret');
      
      if (!decoded || !decoded.userId) {
        return res.status(401).json({ error: 'Invalid authentication token' });
      }
      
      const user = await User.findById(decoded.userId);
      
      if (!user) {
        return res.status(401).json({ error: 'User not found' });
      }
      
      req.user = user;
      req.token = token;
      next();
    } catch (jwtError) {
      console.error('JWT verification error:', jwtError);
      res.status(401).json({ error: 'Invalid authentication token' });
    }
  } catch (error) {
    console.error('Auth middleware error:', error);
    res.status(500).json({ error: 'Internal server error during authentication' });
  }
};

// IIFE to set up the database and models immediately
(async () => {
  try {
    // Wait for DB connection
    const connection = await connectDB();
    const connected = !!connection;
    
    if (connected) {
      console.log('Initializing MongoDB models...');
      // Create models only after connection is established
      User = mongoose.model('User', UserSchema);
      Content = mongoose.model('Content', ContentSchema);
      ChatHistory = mongoose.model('ChatHistory', ChatHistorySchema);
      console.log('MongoDB models initialized successfully');
      
      // Configure session store with MongoDB if connected
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
        
        console.log(' MongoDB session store configured');
      } catch (sessionErr) {
        console.error(' Error initializing MongoStore:', sessionErr.message);
        console.log(' Falling back to in-memory session store');
      }
    } else {
      console.warn(' MongoDB not connected, initializing models with limited functionality');
      // Create models to avoid errors, but they won't work without DB connection
      User = mongoose.model('User', UserSchema);
      Content = mongoose.model('Content', ContentSchema);
      ChatHistory = mongoose.model('ChatHistory', ChatHistorySchema);
    }
    
    // Express App Configuration
    app.use(express.json({ limit: '50mb' })); // Support for JSON payloads with larger limit
    app.use(express.urlencoded({ extended: true, limit: '50mb' })); // Support for form data
    
    const upload = multer({
      storage: multer.memoryStorage(),
      limits: { fileSize: 20 * 1024 * 1024 } // Limit file size to 20MB
    });

    // Security configuration
    app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
          styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
          fontSrc: ["'self'", 'https://fonts.gstatic.com'],
          imgSrc: ["'self'", 'data:', 'blob:'],
          connectSrc: ["'self'", 'https://generativelanguage.googleapis.com']
        }
      }
    }));

    // CORS configuration
    app.use(cors({
      origin: process.env.NODE_ENV === 'production' 
        ? ['https://splanai.herokuapp.com', 'https://www.splanai.com'] 
        : 'http://localhost:3000',
      methods: ['GET', 'POST', 'PUT', 'DELETE'],
      credentials: true
    }));

    // Rate limiting
    const apiLimiter = rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 100
    });
    app.use('/api/', apiLimiter);
    
    // Apply session middleware after all configuration is done
    app.use(session(sessionConfig));
    
    // Serve static files in production
    if (process.env.NODE_ENV === 'production') {
      app.use(express.static(path.join(__dirname, 'public')));
    } else {
      app.use(express.static('public'));
    }
    
    // Add basic health check endpoint
    app.get('/health', (req, res) => {
      res.status(200).json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
      });
    });
    
    // Start the server after all setup is complete
    app.listen(PORT, () => {
      console.log(` Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
      console.log(` MongoDB Connection Status: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    });
  } catch (setupError) {
    console.error(' Fatal error during application setup:', setupError);
    process.exit(1); // Exit with error code
  }
})();

// Process text regardless of source (OCR or direct input)
const processTextContent = async (text, sessionId, metadata = {}, userId = null) => {
  try {
    // Trim and validate input
    if (!text || typeof text !== 'string' || text.trim().length === 0) {
      throw new Error('Invalid or empty text content');
    }
    
    const fullText = text.trim();
    
    // AI Processing with Google Generative AI
    console.log(' Processing with Google Generative AI, text length:', fullText.length);
    
    try {
      // Get the Gemini Pro model
      const model = genAI.getGenerativeModel({ model: "gemini-pro" });
      
      // Process content in parallel with Gemini
      console.log('Starting Gemini processing...');
      
      // Generate summary
      const summaryPrompt = `Summarize this in three paragraphs:\n${fullText.substring(0, Math.min(fullText.length, 15000))}`;
      const summaryResult = await model.generateContent(summaryPrompt);
      const summary = summaryResult.response.text();
      
      // Generate flashcards
      const flashcardsPrompt = `Generate 5 flashcards from this text in the following JSON format:
      [
        {
          "question": "Question here?",
          "answer": "Answer here",
          "confidence": 0.9,
          "tags": ["tag1", "tag2"]
        }
      ]
      Text: ${fullText.substring(0, Math.min(fullText.length, 15000))}`;
      
      const flashcardsResult = await model.generateContent(flashcardsPrompt);
      const flashcardsText = flashcardsResult.response.text();
      
      // Generate quizzes
      const quizzesPrompt = `Generate 3 multiple-choice questions with answers from this text in the following format:
      [
        {
          "question": "Question text here?",
          "options": ["Option A", "Option B", "Option C", "Option D"],
          "answer": "Option A",
          "explanation": "Brief explanation here"
        }
      ]
      Text: ${fullText.substring(0, Math.min(fullText.length, 15000))}`;
      
      const quizzesResult = await model.generateContent(quizzesPrompt);
      const quizzesText = quizzesResult.response.text();
      
      console.log(' AI processing completed successfully');
      
      // Parse JSON responses with error handling
      let flashcards = [];
      let quizzes = [];
      
      try {
        // Parse JSON responses with error handling
        flashcards = JSON.parse(extractJSONFromString(flashcardsText)) || [];
        quizzes = JSON.parse(extractJSONFromString(quizzesText)) || [];
        
        // Validate the arrays
        if (!Array.isArray(flashcards)) flashcards = [];
        if (!Array.isArray(quizzes)) quizzes = [];
      } catch (jsonError) {
        console.error('Error parsing AI response JSON:', jsonError);
        // Create fallback content if parsing fails
        flashcards = [{ question: "What is this text about?", answer: "Unable to generate specific flashcards", confidence: 0.5, tags: ["general"] }];
        quizzes = [{ 
          question: "What is the main topic discussed?", 
          options: ["Topic A", "Topic B", "Topic C", "Cannot determine"], 
          answer: "Cannot determine", 
          explanation: "Unable to generate specific questions from the text."
        }];
      }
      
      // Generate title using the AI
      let title = metadata.title || '';
      
      if (!title) {
        try {
          const titlePrompt = `Create a very short title (5-7 words max) for this text:\n${fullText.substring(0, Math.min(fullText.length, 1000))}`;
          const titleResult = await model.generateContent(titlePrompt);
          title = titleResult.response.text().trim();
          if (!title) title = 'Untitled Document';
        } catch (titleError) {
          console.error('Error generating title:', titleError);
          title = 'Untitled Document';
        }
      }
      
      // Create result object
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
          // Try to find existing document first
          let existingContent = await Content.findOne({ sessionId });
          
          if (existingContent) {
            // Update existing document
            Object.assign(existingContent, contentData);
            await existingContent.save();
            console.log('Updated existing content in database with sessionId:', sessionId);
          } else {
            // Create new document
            await Content.create(contentData);
            console.log('Created new content in database with sessionId:', sessionId);
          }
        } catch (dbError) {
          console.error('Error saving to database:', dbError);
          // Continue with the processing even if DB save fails
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
    if (!buffer || !sessionId || !fileType) {
      throw new Error('Missing required parameters for content processing');
    }
    
    console.log(` Processing file of type: ${fileType}`);
    
    // Default to text for fallback
    let contentType = 'Unknown';
    let text = '';
    
    // Process based on file type
    if (fileType.includes('image/')) {
      contentType = 'Image';
      
      try {
        // Validate buffer
        if (!buffer || buffer.length === 0) {
          throw new Error('Empty image buffer');
        }
        
        // Run OCR with error handling
        console.log(' Running OCR on image...');
        const [result] = await visionClient.documentTextDetection(buffer);
        
        if (!result || !result.fullTextAnnotation) {
          throw new Error('No text detected in image');
        }
        
        text = result.fullTextAnnotation.text || '';
        console.log(` OCR complete. Extracted ${text.length} characters`);
        
        if (text.trim().length === 0) {
          throw new Error('No text content extracted from image');
        }
      } catch (ocrError) {
        console.error('OCR processing error:', ocrError);
        throw new Error(`OCR processing failed: ${ocrError.message}`);
      }
    } else if (fileType.includes('application/pdf')) {
      contentType = 'PDF';
      text = 'PDF processing is currently not supported directly. Please extract text and submit it directly.';
      throw new Error('PDF processing not implemented');
    } else if (fileType.includes('text/')) {
      contentType = 'Text';
      
      try {
        // Convert buffer to text
        text = buffer.toString('utf8');
        if (!text || text.trim().length === 0) {
          throw new Error('Text file contains no content');
        }
        console.log(` Text file processed. ${text.length} characters extracted`);
      } catch (textError) {
        console.error('Text processing error:', textError);
        throw new Error(`Text processing failed: ${textError.message}`);
      }
    } else {
      throw new Error(`Unsupported file type: ${fileType}`);
    }
    
    // Process the extracted text content with AI
    console.log(' Processing content with AI...');
    const result = await processTextContent(text, sessionId, {
      fileType,
      contentType,
      source: 'file-upload'
    }, userId);
    
    return result;
  } catch (err) {
    console.error('Content processing error:', err);
    throw err;
  }
};

// =================== MIDDLEWARE ===================

// Security configuration
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      connectSrc: ["'self'", 'https://*.googleapis.com'],
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

// =================== API Endpoints ===================

// User Authentication Routes
// Register User
app.post('/api/auth/register', async (req, res) => {
  try {
    // First check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      console.warn(' Registration attempted before MongoDB connection is ready');
      // For APIs that require auth, fail with clear message
      return res.status(503).json({ 
        error: 'Database connection not ready',
        message: 'The server database is currently connecting. Please try again in a moment.'
      });
    }
    
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
    // First check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      console.warn(' Login attempted before MongoDB connection is ready');
      // For APIs that require auth, fail with clear message
      return res.status(503).json({ 
        error: 'Database connection not ready',
        message: 'The server database is currently connecting. Please try again in a moment.'
      });
    }
    
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
    const userId = req.session?.userId || null;
    
    const sessionId = uuidv4();
    const fileType = req.file.mimetype;
    
    console.log(`Processing uploaded file: ${fileType}`);
    
    // First check if MongoDB is connected before proceeding
    if (mongoose.connection.readyState !== 1) {
      console.warn('MongoDB not connected during file processing');
    }
    
    const result = await processContent(req.file.buffer, sessionId, fileType, userId);
    
    // Send a more complete response with all necessary data
    res.json({ 
      sessionId, 
      title: result.title || 'Untitled Document',
      summary: result.summary,
      flashcards: result.flashcards,
      quizzes: result.quizzes,
      originalText: result.originalText,
      message: 'File processed successfully' 
    });
  } catch (error) {
    console.error('Error processing file:', error);
    res.status(500).json({ 
      error: 'Failed to process file',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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
    const userId = req.session?.userId || null;
    
    const sessionId = uuidv4();
    console.log(`Processing direct text input, length: ${text.length}`);
    
    // First check if MongoDB is connected before proceeding
    if (mongoose.connection.readyState !== 1) {
      console.warn('MongoDB not connected during text processing');
    }
    
    const metadata = {
      contentType: 'text',
      source: 'direct-input',
      title: title && title.trim() ? title.trim() : undefined
    };
    
    const result = await processTextContent(text, sessionId, metadata, userId);
    
    // Return the processed data
    res.json({ 
      sessionId,
      title: result.title || 'Untitled Document',
      summary: result.summary,
      flashcards: result.flashcards,
      quizzes: result.quizzes,
      message: 'Text processed successfully'
    });
  } catch (error) {
    console.error('Error processing text:', error);
    res.status(500).json({ 
      error: 'Failed to process text',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get content by sessionId
app.get('/api/content/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }
    
    // Check if MongoDB is connected
    if (mongoose.connection.readyState !== 1) {
      console.warn(' Content retrieval attempted before MongoDB connection is ready');
      return res.status(503).json({ 
        error: 'Database connection not ready',
        message: 'The server database is currently connecting. Please try again in a moment.'
      });
    }
    
    const content = await Content.findOne({ sessionId });
    
    if (!content) {
      return res.status(404).json({ error: 'Content not found' });
    }
    
    res.json({ 
      sessionId,
      title: content.title || 'Untitled Document',
      summary: content.summary,
      flashcards: content.flashcards || [],
      quizzes: content.quizzes || [],
      originalText: content.originalText
    });
  } catch (error) {
    console.error('Error retrieving content:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve content',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
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
    
    // Use Gemini model for chatbot functionality
    const model = genAI.getGenerativeModel({ model: "gemini-pro" });
    
    // Prepare chat history if available
    let chatHistory = [];
    if (sessionId && mongoose.connection.readyState === 1) {
      try {
        const history = await ChatHistory.findOne({ sessionId });
        if (history && history.messages) {
          // Convert to format Gemini can use
          chatHistory = history.messages.map(msg => ({
            role: msg.role === 'assistant' ? 'model' : 'user',
            parts: [{ text: msg.content }]
          }));
        }
      } catch (historyError) {
        console.error('Error retrieving chat history:', historyError);
      }
    }
    
    // Create the Gemini chat
    const chat = model.startChat({
      history: chatHistory.length > 0 ? chatHistory : [
        {
          role: "model",
          parts: [{ 
            text: `I am a helpful study assistant for SplanAI, an app that helps students learn from their notes, documents, and images.
            SplanAI can create summaries, flashcards, and quizzes from uploaded content.
            I'll be friendly, concise, and helpful. If I don't know something, I'll suggest using the app's features instead.
            I'll keep responses under 150 words to fit nicely in the chat interface.`
          }]
        }
      ],
      generationConfig: {
        temperature: 0.7,
        maxOutputTokens: 300
      }
    });
    
    // Send the message and get a response
    const result = await chat.sendMessage(message);
    const reply = result.response.text();
    
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

// Helper function to extract JSON from a string that might contain other text
function extractJSONFromString(str) {
  try {
    // If it's already valid JSON, return it
    try {
      JSON.parse(str);
      return str;
    } catch (e) {
      // Continue with extraction
    }
    
    // Find the first occurrence of '[' or '{'
    const firstBracketIndex = str.indexOf('[');
    const firstBraceIndex = str.indexOf('{');
    
    let startIndex;
    let endIndex;
    let openChar;
    let closeChar;
    
    // Determine which comes first: [ or {
    if (firstBracketIndex !== -1 && (firstBraceIndex === -1 || firstBracketIndex < firstBraceIndex)) {
      startIndex = firstBracketIndex;
      openChar = '[';
      closeChar = ']';
    } else if (firstBraceIndex !== -1) {
      startIndex = firstBraceIndex;
      openChar = '{';
      closeChar = '}';
    } else {
      // No JSON found
      return '[]';
    }
    
    // Find the matching closing bracket/brace
    let count = 1;
    let i = startIndex + 1;
    
    while (count > 0 && i < str.length) {
      if (str[i] === openChar) count++;
      else if (str[i] === closeChar) count--;
      i++;
    }
    
    if (count === 0) {
      endIndex = i;
      // Extract the JSON string
      const jsonStr = str.substring(startIndex, endIndex);
      
      // Validate it's valid JSON
      try {
        JSON.parse(jsonStr);
        return jsonStr;
      } catch (e) {
        console.error('Extracted string is not valid JSON:', e);
        return openChar === '[' ? '[]' : '{}';
      }
    }
    
    // If we couldn't find matching brackets/braces, return a default empty array or object
    return openChar === '[' ? '[]' : '{}';
  } catch (error) {
    console.error('JSON extraction error:', error);
    return '[]';
  }
}
