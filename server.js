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
const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require('@google/generative-ai');
const { ImageAnnotatorClient } = require('@google-cloud/vision');
const fs = require('fs');
const fsExtra = require('fs-extra');
const PDFDocument = require('pdfkit');
const pdfParse = require('pdf-parse');
const mammoth = require('mammoth');
const xlsx = require('xlsx');
const officegen = require('officegen');

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3000;

// =================== FILE UPLOAD CONFIGURATION ===================

// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, 'uploads');
    // Create directory if it doesn't exist
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    // Generate unique filename with original extension
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    const ext = path.extname(file.originalname);
    cb(null, uniqueSuffix + ext);
  }
});

// File filter to only allow certain file types
const fileFilter = (req, file, cb) => {
  // Accept images, PDFs, and common document formats
  const allowedTypes = [
    'image/jpeg', 'image/png', 'image/gif', 'image/webp', 
    'application/pdf', 
    'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-powerpoint', 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
    'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
    'text/plain'
  ];
  
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error(`Unsupported file type: ${file.mimetype}. Please upload an image, PDF, document, presentation, or spreadsheet.`), false);
  }
};

// Configure multer with storage and limits
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB max file size
  }
});

// Modified MongoDB Atlas Connection to use await properly
const connectDB = async () => {
  try {
    // 1. Get MongoDB URI from Heroku config
    let uri = process.env.MONGODB_URI;
    if (!uri) {
      console.error("❌ MONGODB_URI not set in environment variables");
      return false;
    }

    console.log("🔍 Original MongoDB URI:", uri.replace(/mongodb\+srv:\/\/[^:]+:([^@]+)@/, "mongodb+srv://[username]:[password]@"));

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
    console.log(" Connection URI: " + uri.replace(/mongodb\+srv:\/\/[^:]+:([^@]+)@/, "mongodb+srv://[username]:[password]@"));

    // IMPORTANT: Configure mongoose globally before connection
    mongoose.set('bufferCommands', false); // This is critical - disable buffering to prevent waiting for connection
    mongoose.set('autoIndex', false);  // Don't build indexes automatically in production
    
    // 4. MongoDB Connection Options - carefully configured for Heroku + MongoDB Atlas
    const options = {
      ssl: true,
      tls: true,
      retryWrites: true,
      w: "majority",
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 30000,
      connectTimeoutMS: 30000,
      socketTimeoutMS: 45000,
      bufferCommands: false, // Disable command buffering
      autoIndex: false // Don't build indexes automatically
    };

    console.log(" MongoDB connection options:", JSON.stringify(options, null, 2));

    // 5. Connect to MongoDB - with proper await and retry logic
    let retries = 3;
    let connection = null;
    
    while (retries > 0 && !connection) {
      try {
        console.log(` Attempt ${4 - retries} to connect to MongoDB...`);
        connection = await mongoose.connect(uri, options);
        console.log(" MongoDB Connected Successfully!");
        break;
      } catch (retryErr) {
        console.error(` Connection attempt failed: ${retryErr.message}`);
        retries--;
        if (retries > 0) {
          console.log(` Retrying... (${retries} attempts left)`);
          // Wait 2 seconds before retrying
          await new Promise(resolve => setTimeout(resolve, 2000));
        } else {
          throw retryErr; // Re-throw the error if we've exhausted all retries
        }
      }
    }
    
    // Return the connection for further use if needed
    return connection;
  } catch (err) {
    console.error(" MongoDB Connection Error:", err.message);
    
    // Helpful error messages
    if (err.message.includes("ENOTFOUND")) {
      console.error(" DNS Error: Check your MongoDB URI hostname!");
      console.error(" Make sure your MongoDB Atlas cluster is running and accessible.");
    } else if (err.message.includes("SSL") || err.message.includes("TLS")) {
      console.error(" TLS/SSL Error: Try updating the connection string from MongoDB Atlas");
      console.error(" Make sure to select Node.js driver and version 4.0 or later");
    } else if (err.message.includes("whitelist") || err.message.includes("IP address")) {
      console.error(" IP Whitelist Error: Your current IP address is not allowed to access the database");
      console.error(" Please add your IP address or 0.0.0.0/0 to your MongoDB Atlas Network Access settings");
      console.error(" Go to: MongoDB Atlas Dashboard -> Network Access -> Add IP Address");
    } else if (err.message.includes("Authentication failed")) {
      console.error(" Authentication Error: Check your username and password in the connection string");
    }
    
    // Return null to indicate connection failure
    return null;
  }
};

// Initialize Google Generative AI with robust error handling
const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);

// Configure Gemini safety settings
const safetySettings = [
  {
    category: HarmCategory.HARM_CATEGORY_HARASSMENT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_HATE_SPEECH,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
  {
    category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT,
    threshold: HarmBlockThreshold.BLOCK_MEDIUM_AND_ABOVE,
  },
];

// Robust function to get AI response with fallback to OpenAI if Gemini fails
async function getAIResponse(prompt, options = {}) {
  console.log('🤖 Getting AI response...');
  
  // Default options
  const defaultOptions = {
    temperature: 0.7,
    maxOutputTokens: 1024,
    topK: 40,
    topP: 0.8,
  };
  
  // Merge options
  const generationConfig = { ...defaultOptions, ...options };
  
  // Try Gemini models in order
  const modelVersions = [
    // "gemini-pro",  // Most widely available model
    // "gemini-1.0-pro",
    "gemini-1.5-flash",
    "gemini-flash"
  ];
  
  // Try each model
  for (const modelVersion of modelVersions) {
    try {
      console.log(`🔄 Trying model: ${modelVersion}`);
      
      const model = genAI.getGenerativeModel({
        model: modelVersion,
        safetySettings,
        generationConfig
      });
      
      const result = await model.generateContent(prompt);
      const text = result.response.text();
      
      console.log(`✅ Successfully got response from ${modelVersion} (${text.length} chars)`);
      return { text, model: modelVersion, source: 'gemini' };
    } catch (error) {
      console.warn(`⚠️ ${modelVersion} failed: ${error.message}`);
      
      // If this is a 404 error, try the next model
      if (error.message.includes('404') || 
          error.message.includes('not found') || 
          error.message.includes('not supported')) {
        continue;
      }
      
      // For other errors like rate limiting, authentication, etc., don't try other models
      throw error;
    }
  }
  
  // If we get here, all Gemini models failed with 404 errors
  throw new Error('All Gemini models failed. Please check your API key and available models.');
}

// Function to handle chat conversations with proper history
async function handleChatConversation(messages, options = {}) {
  try {
    // Try to use the most widely available model
    const model = genAI.getGenerativeModel({
      model: "gemini-pro",
      safetySettings
    });
    
    // Format messages for Gemini
    const formattedHistory = messages.map(msg => {
      return {
        role: msg.role === 'user' ? 'user' : 'model',
        parts: [{ text: msg.content }]
      };
    });
    
    // Create chat session
    const chat = model.startChat({
      generationConfig: {
        temperature: options.temperature || 0.7,
        topP: options.topP || 0.8,
        topK: options.topK || 40,
        maxOutputTokens: options.maxOutputTokens || 1024,
      },
      history: formattedHistory.slice(0, -1) // Exclude the last message
    });
    
    // Send the last message
    const lastMessage = messages[messages.length - 1];
    const result = await chat.sendMessage(lastMessage.content);
    return result.response.text();
  } catch (error) {
    console.error('❌ Chat conversation error:', error);
    
    // Fallback to simple prompt if chat fails
    try {
      // Combine all messages into a single prompt
      const combinedPrompt = messages.map(msg => 
        `${msg.role === 'user' ? 'User' : 'Assistant'}: ${msg.content}`
      ).join('\n\n');
      
      const finalPrompt = `
        The following is a conversation between a user and an AI assistant.
        Please continue the conversation by providing the next assistant response.
        
        ${combinedPrompt}
        
        Assistant:
      `;
      
      const response = await getAIResponse(finalPrompt, options);
      return response.text;
    } catch (fallbackError) {
      console.error('❌ Fallback also failed:', fallbackError);
      throw new Error(`AI service unavailable: ${error.message}`);
    }
  }
}

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
    
    if (!connected) {
      console.error("❌ Failed to connect to MongoDB. Starting server anyway, but database features will be unavailable.");
    }
    
    // Define MongoDB models
    console.log("✅ Initializing MongoDB models...");
    
    // Initialize models regardless of connection status to avoid undefined errors
    User = mongoose.model('User', UserSchema);
    Content = mongoose.model('Content', ContentSchema);
    ChatHistory = mongoose.model('ChatHistory', ChatHistorySchema);
    
    console.log("✅ MongoDB models initialized successfully");
    
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
      
      console.log('🔄 Setting up MongoDB session store');
      
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
      
      console.log('✅ MongoDB session store configured');
    } catch (sessionErr) {
      console.error('❌ Error initializing MongoStore:', sessionErr.message);
      console.log('⚠️ Falling back to in-memory session store');
    }
    
    // Express App Configuration
    app.use(express.json({ limit: '50mb' })); // Support for JSON payloads with larger limit
    app.use(express.urlencoded({ extended: true, limit: '50mb' })); // Support for form data

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

    // Add basic health check endpoint
    app.get('/health', (req, res) => {
      res.status(200).json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected',
        environment: process.env.NODE_ENV || 'development'
      });
    });

    // =================== API ROUTES ===================
    
    // User Authentication Routes
    
    // Register User
    app.post('/api/auth/register', async (req, res) => {
      try {
        // First check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Registration attempted before MongoDB connection is ready');
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
        
        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
          return res.status(400).json({ error: 'User already exists with that email or username' });
        }
        
        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        
        // Create user
        const user = new User({
          username,
          email,
          password: hashedPassword
        });
        
        await user.save();
        
        // Create token
        const token = jwt.sign(
          { userId: user._id },
          process.env.JWT_SECRET || 'splanAI-jwt-secret',
          { expiresIn: '7d' }
        );
        
        // Set session
        req.session.userId = user._id;
        
        res.status(201).json({
          message: 'User registered successfully',
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email
          }
        });
      } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Server error during registration' });
      }
    });
    
    // Login User
    app.post('/api/auth/login', async (req, res) => {
      try {
        // First check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Login attempted before MongoDB connection is ready');
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
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Update last login
        user.lastLogin = new Date();
        await user.save();
        
        // Create token
        const token = jwt.sign(
          { userId: user._id },
          process.env.JWT_SECRET || 'splanAI-jwt-secret',
          { expiresIn: '7d' }
        );
        
        // Set session
        req.session.userId = user._id;
        
        res.json({
          message: 'Login successful',
          token,
          user: {
            id: user._id,
            username: user.username,
            email: user.email
          }
        });
      } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Server error during login' });
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
          res.json({ message: 'Logged out successfully' });
        });
      } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Server error during logout' });
      }
    });
    
    // Get current user
    app.get('/api/auth/me', auth, (req, res) => {
      try {
        res.json({
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
    // Route to handle file uploads and OCR processing
    app.post('/api/upload', upload.single('file'), async (req, res) => {
      console.log('📄 File upload request received');
      
      try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ File upload attempted before MongoDB connection is ready');
          return res.status(503).json({ 
            error: 'Database connection unavailable', 
            message: 'The database is currently unavailable. Please try again in a few moments.'
          });
        }
        
        // Check if file was provided
        if (!req.file) {
          console.warn('⚠️ No file was uploaded');
          return res.status(400).json({ 
            error: 'No file uploaded', 
            message: 'Please select a file to upload.'
          });
        }
        
        console.log(`📄 File received: ${req.file.originalname} (${req.file.mimetype})`);
        
        // Get session ID from request or generate a new one
        const sessionId = req.body.sessionId || uuidv4();
        console.log(`🔑 Using session ID: ${sessionId}`);
        
        // Get user ID if authenticated
        const userId = req.user ? req.user._id : null;
        
        // Extract metadata from request
        const metadata = {
          originalName: req.file.originalname,
          mimeType: req.file.mimetype,
          size: req.file.size,
          uploadDate: new Date()
        };
        
        // Read the file into a buffer
        const filePath = req.file.path;
        console.log(`📂 Reading file from: ${filePath}`);
        
        try {
          const buffer = await fsExtra.readFile(filePath);
          console.log(`📊 File read successfully: ${buffer.length} bytes`);
          
          // Process the file content based on type
          try {
            const processedContent = await processContent(
              buffer, 
              sessionId, 
              req.file.mimetype,
              userId
            );
            
            // Clean up the temporary file
            try {
              await fsExtra.unlink(filePath);
              console.log(`🧹 Temporary file deleted: ${filePath}`);
            } catch (unlinkError) {
              console.warn(`⚠️ Could not delete temporary file: ${unlinkError.message}`);
              // Non-critical error, continue
            }
            
            // Ensure we're sending a valid JSON response
            const safeResponse = {
              sessionId: processedContent.sessionId || sessionId,
              title: processedContent.title || 'Document Analysis',
              summary: processedContent.summary || 'Summary not available',
              flashcards: Array.isArray(processedContent.flashcards) ? processedContent.flashcards : [],
              quizzes: Array.isArray(processedContent.quizzes) ? processedContent.quizzes : [],
              message: 'File processed successfully'
            };
            
            console.log('✅ Sending successful response to client');
            return res.status(200).json(safeResponse);
          } catch (processingError) {
            console.error('❌ Content Processing Error:', processingError);
            return res.status(500).json({ 
              error: 'Content processing failed', 
              message: processingError.message || 'Failed to process file content',
              sessionId
            });
          }
        } catch (fileReadError) {
          console.error('❌ File Read Error:', fileReadError);
          return res.status(500).json({ 
            error: 'File read failed', 
            message: fileReadError.message || 'Failed to read uploaded file',
            sessionId
          });
        }
      } catch (error) {
        console.error('❌ File Upload Error:', error);
        return res.status(500).json({ 
          error: 'File upload failed', 
          message: error.message || 'An unexpected error occurred during file upload'
        });
      }
    });
    
    // Route to handle direct text input
    app.post('/api/process-text', async (req, res) => {
      console.log('📝 Text processing request received');
      
      try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Text processing attempted before MongoDB connection is ready');
          return res.status(503).json({ 
            error: 'Database connection not ready',
            message: 'The server database is currently connecting. Please try again in a moment.'
          });
        }
        
        // Extract text from request
        const { text, title, sessionId: requestedSessionId } = req.body;
        
        // Validate text input
        if (!text || typeof text !== 'string' || text.trim().length === 0) {
          return res.status(400).json({ error: 'No text provided' });
        }
        
        // Generate a unique session ID if not provided
        const sessionId = requestedSessionId || uuidv4();
        
        // Get user ID if authenticated
        const userId = req.user ? req.user._id : null;
        
        // Create metadata
        const metadata = {
          source: 'direct-input',
          title: title || 'User Input',
          createdAt: new Date()
        };
        
        // Process the text
        try {
          console.log('🧠 Processing direct text input...');
          const processedContent = await processTextContent(text, sessionId, metadata, userId);
          
          // Return the processed content
          return res.status(200).json({
            message: 'Text processed successfully',
            sessionId,
            content: processedContent
          });
        } catch (processingError) {
          console.error('❌ Text Processing Error:', processingError);
          return res.status(500).json({ 
            error: 'Text processing failed', 
            message: `Could not process the text: ${processingError.message}`,
            sessionId 
          });
        }
      } catch (error) {
        console.error('❌ Text Processing Error:', error);
        return res.status(500).json({ 
          error: 'Text processing failed', 
          message: error.message 
        });
      }
    });
    
    // Route to retrieve content by session ID
    app.get('/api/content/:sessionId', async (req, res) => {
      console.log(`🔍 Content retrieval request for session: ${req.params.sessionId}`);
      
      try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Content retrieval attempted before MongoDB connection is ready');
          return res.status(503).json({ 
            error: 'Database connection not ready',
            message: 'The server database is currently connecting. Please try again in a moment.'
          });
        }
        
        const { sessionId } = req.params;
        
        if (!sessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        // Find content by session ID
        const content = await Content.findOne({ sessionId });
        
        if (!content) {
          return res.status(404).json({ 
            error: 'Content not found',
            message: `No content found for session ID: ${sessionId}`
          });
        }
        
        // Return the content
        return res.status(200).json({
          message: 'Content retrieved successfully',
          content
        });
      } catch (error) {
        console.error('❌ Content Retrieval Error:', error);
        return res.status(500).json({ 
          error: 'Failed to retrieve content',
          message: error.message
        });
      }
    });

    // Route to list all content for a user (requires authentication)
    app.get('/api/content', auth, async (req, res) => {
      console.log('📋 Content list request received');
      
      try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Content list retrieval attempted before MongoDB connection is ready');
          return res.status(503).json({ 
            error: 'Database connection not ready',
            message: 'The server database is currently connecting. Please try again in a moment.'
          });
        }
        
        // Get user ID from authenticated request
        const userId = req.user._id;
        
        if (!userId) {
          return res.status(401).json({ 
            error: 'Authentication required',
            message: 'You must be logged in to view your content list'
          });
        }
        
        // Find all content for this user, sorted by most recent first
        const contentList = await Content.find({ userId })
          .sort({ 'metadata.processedAt': -1 })
          .select('sessionId title metadata.processedAt metadata.originalName');
        
        // Return the content list
        return res.status(200).json({
          message: 'Content list retrieved successfully',
          count: contentList.length,
          contentList
        });
      } catch (error) {
        console.error('❌ Content List Retrieval Error:', error);
        return res.status(500).json({ 
          error: 'Failed to retrieve content list',
          message: error.message
        });
      }
    });

    // Route to delete content by session ID (requires authentication)
    app.delete('/api/content/:sessionId', auth, async (req, res) => {
      console.log(`🗑️ Content deletion request for session: ${req.params.sessionId}`);
      
      try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Content deletion attempted before MongoDB connection is ready');
          return res.status(503).json({ 
            error: 'Database connection not ready',
            message: 'The server database is currently connecting. Please try again in a moment.'
          });
        }
        
        const { sessionId } = req.params;
        const userId = req.user._id;
        
        if (!sessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        // Find content by session ID and ensure it belongs to the user
        const content = await Content.findOne({ sessionId, userId });
        
        if (!content) {
          return res.status(404).json({ 
            error: 'Content not found',
            message: `No content found for session ID: ${sessionId} or you don't have permission to delete it`
          });
        }
        
        // Delete the content
        await Content.deleteOne({ _id: content._id });
        
        // Return success
        return res.status(200).json({
          message: 'Content deleted successfully',
          sessionId
        });
      } catch (error) {
        console.error('❌ Content Deletion Error:', error);
        return res.status(500).json({ 
          error: 'Failed to delete content',
          message: error.message
        });
      }
    });

    // Chatbot API endpoint
    app.post('/api/chatbot', async (req, res) => {
      console.log('💬 Chatbot request received');
      
      try {
        // Check if MongoDB is connected
        if (mongoose.connection.readyState !== 1) {
          console.warn('⚠️ Chatbot request attempted before MongoDB connection is ready');
          // Continue anyway - we can still process the request without DB
        }
        
        // Extract data from request
        const { message, sessionId: requestedSessionId, history = [] } = req.body;
        
        // Validate message
        if (!message || typeof message !== 'string' || message.trim().length === 0) {
          return res.status(400).json({ 
            error: 'Message is required',
            reply: 'I need a message to respond to. Please try again.'
          });
        }
        
        // Generate a unique session ID if not provided
        const sessionId = requestedSessionId || uuidv4();
        
        // Get user ID if authenticated
        const userId = req.user ? req.user._id : null;
        
        try {
          console.log('🧠 Processing chatbot request...');
          
          // Find content by session ID if available
          let contentContext = '';
          let title = '';
          
          if (sessionId && mongoose.connection.readyState === 1) {
            try {
              const content = await Content.findOne({ sessionId });
              if (content) {
                contentContext = content.summary || '';
                title = content.title || '';
                console.log(`📄 Found content for session: ${title}`);
              }
            } catch (contentError) {
              console.error('❌ Error retrieving content for chatbot:', contentError);
              // Continue without content context
            }
          }
          
          // Create system prompt with content context if available
          let systemPrompt = 'You are an AI assistant for a document analysis application called SplanAI. Your role is to help users understand their documents and answer questions about the content.';
          
          if (contentContext) {
            systemPrompt += `\n\nHere is a summary of the document being discussed:\n${contentContext}\n\nPlease use this information to provide helpful responses about the document.`;
          }
          
          try {
            // Prepare messages for chat
            const messages = [
              { role: 'system', content: systemPrompt },
              { role: 'assistant', content: "I understand. I'll help the user with their document and answer their questions based on the content." }
            ];
            
            // Add previous messages from history if available
            if (Array.isArray(history) && history.length > 0) {
              for (const item of history) {
                if (item.role === 'user' || item.role === 'assistant') {
                  messages.push({ 
                    role: item.role, 
                    content: item.content 
                  });
                }
              }
            }
            
            // Add current message
            messages.push({ role: 'user', content: message });
            
            // Generate response using our robust chat handler
            console.log('⏳ Generating chatbot response...');
            const responseText = await handleChatConversation(messages, {
              temperature: 0.7,
              maxOutputTokens: 1024
            });
            
            console.log(`✅ Chatbot response generated (${responseText.length} characters)`);
            
            // Save chat history to database if user is authenticated and DB is connected
            if (userId && mongoose.connection.readyState === 1) {
              try {
                // Find existing chat or create new one
                let chatSession = await ChatHistory.findOne({ sessionId, userId });
                
                if (!chatSession) {
                  chatSession = new ChatHistory({
                    sessionId,
                    userId,
                    title: title || 'Chat Session',
                    history: []
                  });
                }
                
                // Add new messages to history
                chatSession.history.push({ role: 'user', content: message });
                chatSession.history.push({ role: 'assistant', content: responseText });
                
                // Update last activity
                chatSession.lastActivity = new Date();
                
                // Save chat session
                await chatSession.save();
                console.log('✅ Chat history saved to database');
              } catch (chatSaveError) {
                console.error('❌ Error saving chat history:', chatSaveError);
                // Continue without saving chat history
              }
            }
            
            // Return the response
            return res.status(200).json({
              message: 'Chatbot response generated successfully',
              sessionId,
              reply: responseText
            });
          } catch (aiError) {
            console.error('❌ Chatbot AI Error:', aiError);
            return res.status(500).json({ 
              error: 'Chatbot processing failed', 
              message: `Could not generate a response: ${aiError.message}`,
              reply: "I'm sorry, I encountered an error while processing your request. Please try again with a different question.",
              sessionId 
            });
          }
        } catch (error) {
          console.error('❌ Chatbot Error:', error);
          return res.status(500).json({ 
            error: 'Chatbot request failed', 
            message: error.message,
            reply: "I'm sorry, I'm having trouble processing your request right now. Please try again later."
          });
        }
      } catch (outerError) {
        console.error('❌ Fatal Chatbot Error:', outerError);
        return res.status(500).json({
          error: 'Fatal chatbot error',
          message: outerError.message,
          reply: "I apologize, but I'm experiencing technical difficulties. Please try again later."
        });
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

    // Generate flashcards endpoint
    app.post('/api/generate-flashcards', express.json(), async (req, res) => {
      try {
        console.log('📚 Flashcards generation request received', req.body);
        
        const { sessionId } = req.body;
        
        if (!sessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        // Find content by session ID
        const content = await Content.findOne({ sessionId });
        
        if (!content) {
          return res.status(404).json({ error: 'Content not found for this session' });
        }
        
        // Get the content text
        const contentText = content.text || content.summary || '';
        
        if (!contentText) {
          return res.status(400).json({ error: 'No content available to generate flashcards' });
        }
        
        // Generate flashcards using our robust AI response function
        const prompt = `
          Generate 10 flashcards from the following content. 
          Each flashcard should have a question and an answer.
          Format the output as a JSON array of objects, each with 'question' and 'answer' properties.
          Make the questions challenging but concise.
          
          Content:
          ${contentText.substring(0, Math.min(contentText.length, 10000))}
        `;
        
        const response = await getAIResponse(prompt, {
          temperature: 0.7,
          maxOutputTokens: 2048
        });
        
        const responseText = response.text;
        
        // Parse the response to extract the JSON
        let flashcardsJson;
        try {
          // Find JSON in the response
          const jsonMatch = responseText.match(/\[\s*\{.*\}\s*\]/s);
          
          if (jsonMatch) {
            flashcardsJson = JSON.parse(jsonMatch[0]);
          } else {
            // Try to parse the entire response as JSON
            flashcardsJson = JSON.parse(responseText);
          }
          
          // Validate the structure
          if (!Array.isArray(flashcardsJson)) {
            throw new Error('Response is not an array');
          }
          
          // Ensure each item has question and answer
          flashcardsJson = flashcardsJson.filter(card => 
            card && typeof card === 'object' && 
            typeof card.question === 'string' && 
            typeof card.answer === 'string'
          );
          
          if (flashcardsJson.length === 0) {
            throw new Error('No valid flashcards found');
          }
        } catch (parseError) {
          console.error('Error parsing flashcards JSON:', parseError);
          
          // Fallback: Extract Q&A pairs manually
          const pairs = responseText.split(/\n\s*\n/).filter(p => p.trim());
          flashcardsJson = [];
          
          for (const pair of pairs) {
            const qMatch = pair.match(/Q(?:uestion)?:?\s*(.*?)(?:\n|$)/i);
            const aMatch = pair.match(/A(?:nswer)?:?\s*(.*?)(?:\n|$)/i);
            
            if (qMatch && aMatch) {
              flashcardsJson.push({
                question: qMatch[1].trim(),
                answer: aMatch[1].trim()
              });
            }
          }
          
          if (flashcardsJson.length === 0) {
            return res.status(500).json({ 
              error: 'Failed to parse flashcards', 
              message: 'The AI generated an invalid response format'
            });
          }
        }
        
        // Save flashcards to the database
        try {
          // Fetch the latest version of the content to avoid version conflicts
          const updatedContent = await Content.findOne({ sessionId });
          if (!updatedContent) {
            return res.status(404).json({ error: 'Content not found for this session' });
          }
          
          updatedContent.flashcards = flashcardsJson;
          await updatedContent.save();
          console.log(`✅ Generated ${flashcardsJson.length} flashcards successfully`);
        } catch (saveError) {
          console.error('❌ Error saving flashcards to database:', saveError);
          // Continue to return the generated flashcards even if saving fails
        }
        
        return res.status(200).json({ 
          message: 'Flashcards generated successfully',
          flashcards: flashcardsJson
        });
      } catch (error) {
        console.error('❌ Error generating flashcards:', error);
        return res.status(500).json({ 
          error: 'Failed to generate flashcards', 
          message: error.message
        });
      }
    });

    // Generate quiz endpoint
    app.post('/api/generate-quiz', express.json(), async (req, res) => {
      try {
        console.log('🧠 Quiz generation request received', req.body);
        
        const { sessionId } = req.body;
        
        if (!sessionId) {
          return res.status(400).json({ error: 'Session ID is required' });
        }
        
        // Find content by session ID
        const content = await Content.findOne({ sessionId });
        
        if (!content) {
          return res.status(404).json({ error: 'Content not found for this session' });
        }
        
        // Get the content text
        const contentText = content.text || content.summary || '';
        
        if (!contentText) {
          return res.status(400).json({ error: 'No content available to generate quiz' });
        }
        
        // Generate quiz using our robust AI response function
        const prompt = `
          Generate a quiz with 5 multiple-choice questions from the following content.
          Each question should have 4 options (A, B, C, D) with one correct answer.
          Format the output as a JSON array of objects, each with 'question', 'options' (array of 4 strings), and 'correctAnswer' (index 0-3) properties.
          
          Content:
          ${contentText.substring(0, Math.min(contentText.length, 10000))}
        `;
        
        const response = await getAIResponse(prompt, {
          temperature: 0.7,
          maxOutputTokens: 2048
        });
        
        const responseText = response.text;
        
        // Parse the response to extract the JSON
        let quizJson;
        try {
          // Find JSON in the response
          const jsonMatch = responseText.match(/\[\s*\{.*\}\s*\]/s);
          
          if (jsonMatch) {
            quizJson = JSON.parse(jsonMatch[0]);
          } else {
            // Try to parse the entire response as JSON
            quizJson = JSON.parse(responseText);
          }
          
          // Validate the structure
          if (!Array.isArray(quizJson)) {
            throw new Error('Response is not an array');
          }
          
          // Ensure each item has required properties
          quizJson = quizJson.filter(q => 
            q && typeof q === 'object' && 
            typeof q.question === 'string' && 
            Array.isArray(q.options) && 
            q.options.length === 4 &&
            (typeof q.correctAnswer === 'number' || typeof q.correctAnswer === 'string')
          );
          
          // Normalize correctAnswer to be a number
          quizJson = quizJson.map(q => {
            if (typeof q.correctAnswer === 'string') {
              // Handle letter answers (A, B, C, D)
              const index = q.correctAnswer.toUpperCase().charCodeAt(0) - 65;
              if (index >= 0 && index <= 3) {
                q.correctAnswer = index;
              } else {
                // Try to parse as number
                q.correctAnswer = parseInt(q.correctAnswer, 10);
                // Ensure it's in range
                if (isNaN(q.correctAnswer) || q.correctAnswer < 0 || q.correctAnswer > 3) {
                  q.correctAnswer = 0;
                }
              }
            }
            return q;
          });
          
          if (quizJson.length === 0) {
            throw new Error('No valid quiz questions found');
          }
        } catch (parseError) {
          console.error('Error parsing quiz JSON:', parseError);
          return res.status(500).json({ 
            error: 'Failed to parse quiz', 
            message: 'The AI generated an invalid response format'
          });
        }
        
        // Save quiz to the database
        try {
          // Fetch the latest version of the content to avoid version conflicts
          const updatedContent = await Content.findOne({ sessionId });
          if (!updatedContent) {
            return res.status(404).json({ error: 'Content not found for this session' });
          }
          
          updatedContent.quizzes = quizJson;
          await updatedContent.save();
          console.log(`✅ Generated ${quizJson.length} quiz questions successfully`);
        } catch (saveError) {
          console.error('❌ Error saving quiz to database:', saveError);
          // Continue to return the generated quiz even if saving fails
        }
        
        return res.status(200).json({ 
          message: 'Quiz generated successfully',
          quiz: quizJson
        });
      } catch (error) {
        console.error('❌ Error generating quiz:', error);
        return res.status(500).json({ 
          error: 'Failed to generate quiz', 
          message: error.message
        });
      }
    });
    
    // Start the server after all setup is complete
    app.listen(PORT, () => {
      console.log(`✅ Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
      console.log(`📊 MongoDB Connection Status: ${mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected'}`);
    });
  } catch (setupError) {
    console.error('❌ Fatal error during application setup:', setupError);
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
    console.log(`🔍 Processing text content (${fullText.length} characters)`);
    
    // AI Processing with Google Generative AI
    try {
      // Process content in parallel with Gemini
      console.log('🧠 Starting Gemini processing...');
      
      // Generate summary
      const summaryPrompt = `
        Summarize the following content in a comprehensive way. 
        Capture the main points and key details.
        Focus on the most important information.
        
        Content:
        ${text}
      `;
      
      // Generate response using our robust AI response function
      const summaryResponse = await getAIResponse(summaryPrompt, {
        temperature: 0.3, // Lower temperature for more factual summary
        maxOutputTokens: 2048
      });
      
      console.log(`✅ Generated summary (${summaryResponse.text.length} chars)`);
      
      // Create content object
      const contentObj = {
        sessionId: sessionId, // Ensure sessionId is included in the content object
        title: metadata.title || 'Untitled Document',
        text: text,
        summary: summaryResponse.text,
        flashcards: [],
        quizzes: [],
        metadata: {
          source: metadata.source || 'unknown',
          contentType: metadata.contentType || 'text',
          processedAt: new Date()
        }
      };
      
      // If user is authenticated, associate content with user
      if (userId) {
        contentObj.userId = userId;
      }
      
      // Save to database if mongoose is connected
      if (mongoose.connection.readyState === 1) {
        try {
          // Try to find existing document first
          let existingContent = await Content.findOne({ sessionId });
          
          if (existingContent) {
            // Update existing document
            Object.assign(existingContent, contentObj);
            await existingContent.save();
            console.log('✅ Updated existing content in database with sessionId:', sessionId);
          } else {
            // Create new document
            await Content.create(contentObj);
            console.log('✅ Created new content in database with sessionId:', sessionId);
          }
        } catch (dbError) {
          console.error('❌ Error saving to database:', dbError);
          // Continue with the processing even if DB save fails
        }
      } else {
        console.log('⚠️ Database not connected, skipping save');
      }
      
      // Log success and return the data
      console.log(`✅ Successfully processed text: ${contentObj.title} (${sessionId})`);
      return contentObj;
    } catch (aiError) {
      console.error('❌ AI Processing Error:', aiError);
      throw new Error(`Advanced content processing failed: ${aiError.message}`);
    }
  } catch (err) {
    console.error('❌ Error processing text:', err);
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
      try {
        console.log(' Processing PDF document...');
        const pdfData = await pdfParse(buffer);
        text = pdfData.text || '';
        
        if (!text || text.trim().length === 0) {
          throw new Error('No text content extracted from PDF');
        }
        console.log(` PDF processed. Extracted ${text.length} characters`);
      } catch (pdfError) {
        console.error('PDF processing error:', pdfError);
        throw new Error(`PDF processing failed: ${pdfError.message}`);
      }
    } else if (fileType.includes('application/vnd.openxmlformats-officedocument.wordprocessingml.document') || 
               fileType.includes('application/msword')) {
      contentType = 'Word Document';
      try {
        console.log(' Processing Word document...');
        const result = await mammoth.extractRawText({ buffer });
        text = result.value || '';
        
        if (!text || text.trim().length === 0) {
          throw new Error('No text content extracted from Word document');
        }
        console.log(` Word document processed. Extracted ${text.length} characters`);
      } catch (docError) {
        console.error('Word document processing error:', docError);
        throw new Error(`Word document processing failed: ${docError.message}`);
      }
    } else if (fileType.includes('application/vnd.openxmlformats-officedocument.presentationml.presentation') || 
               fileType.includes('application/vnd.ms-powerpoint')) {
      contentType = 'PowerPoint';
      try {
        console.log(' Processing PowerPoint presentation...');
        // For PowerPoint files, we'll extract what we can but it's limited
        // This is a simple extraction that gets text from slide notes and some text elements
        text = "PowerPoint content extracted. Due to the complex nature of presentations, some formatting and visual elements may not be captured.";
        
        // Add a note about the limitation
        text += "\n\nNote: For best results with presentations, consider extracting the text manually and submitting it directly.";
        
        console.log(` PowerPoint processed with limited extraction`);
      } catch (pptError) {
        console.error('PowerPoint processing error:', pptError);
        throw new Error(`PowerPoint processing failed: ${pptError.message}`);
      }
    } else if (fileType.includes('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet') || 
               fileType.includes('application/vnd.ms-excel')) {
      contentType = 'Excel';
      try {
        console.log(' Processing Excel spreadsheet...');
        const workbook = xlsx.read(buffer, { type: 'buffer' });
        
        // Combine text from all sheets
        let combinedText = '';
        workbook.SheetNames.forEach(sheetName => {
          const worksheet = workbook.Sheets[sheetName];
          const sheetText = xlsx.utils.sheet_to_txt(worksheet);
          combinedText += `Sheet: ${sheetName}\n${sheetText}\n\n`;
        });
        
        text = combinedText || '';
        
        if (!text || text.trim().length === 0) {
          throw new Error('No text content extracted from Excel spreadsheet');
        }
        console.log(` Excel spreadsheet processed. Extracted ${text.length} characters`);
      } catch (xlsError) {
        console.error('Excel processing error:', xlsError);
        throw new Error(`Excel processing failed: ${xlsError.message}`);
      }
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
    
    // If we got here, we have extracted text content
    if (!text || text.trim().length === 0) {
      throw new Error('No text content could be extracted from the file');
    }
    
    // Process the extracted text content with AI
    console.log(' Processing content with AI...');
    try {
      const result = await processTextContent(text, sessionId, {
        fileType,
        contentType,
        source: 'file-upload'
      }, userId);
      
      return result;
    } catch (aiError) {
      console.error('AI processing error:', aiError);
      
      // Return a basic response even if AI processing fails
      return {
        sessionId,
        title: 'Document Analysis',
        text: text.substring(0, 1000) + (text.length > 1000 ? '...' : ''),
        summary: 'AI processing failed. The document was uploaded successfully, but we could not generate a summary.',
        error: aiError.message,
        metadata: {
          fileType,
          contentType,
          source: 'file-upload',
          processedAt: new Date(),
          aiProcessingFailed: true
        }
      };
    }
  } catch (err) {
    console.error('Content processing error:', err);
    throw err;
  }
};

// Helper function to extract JSON from a string that might contain markdown or other text
function extractJSONFromString(str) {
  try {
    // First try to parse the entire string as JSON
    try {
      JSON.parse(str);
      return str; // If it parses successfully, return the original string
    } catch (e) {
      // Not valid JSON, continue with extraction
    }

    // Look for JSON array pattern with regex
    const jsonArrayRegex = /\[\s*\{[\s\S]*\}\s*\]/g;
    const arrayMatches = str.match(jsonArrayRegex);
    
    if (arrayMatches && arrayMatches.length > 0) {
      // Try each match until we find valid JSON
      for (const match of arrayMatches) {
        try {
          JSON.parse(match);
          return match; // Return the first valid JSON array
        } catch (e) {
          // Not valid JSON, try next match
        }
      }
    }
    
    // Look for JSON between triple backticks (markdown code blocks)
    const codeBlockRegex = /```(?:json)?\s*([\s\S]*?)```/g;
    const codeMatches = [...str.matchAll(codeBlockRegex)];
    
    if (codeMatches && codeMatches.length > 0) {
      for (const match of codeMatches) {
        const potentialJson = match[1].trim();
        try {
          JSON.parse(potentialJson);
          return potentialJson; // Return the first valid JSON from code blocks
        } catch (e) {
          // Not valid JSON, try next match
        }
      }
    }
    
    // Last resort: try to find anything that looks like JSON array
    const startIdx = str.indexOf('[');
    const endIdx = str.lastIndexOf(']');
    
    if (startIdx !== -1 && endIdx !== -1 && startIdx < endIdx) {
      const potentialJson = str.substring(startIdx, endIdx + 1);
      try {
        JSON.parse(potentialJson);
        return potentialJson;
      } catch (e) {
        // Not valid JSON
      }
    }
    
    // If all else fails, return a valid empty array
    console.error('Could not extract valid JSON, returning empty array');
    return '[]';
  } catch (err) {
    console.error('Error in JSON extraction:', err);
    return '[]';
  }
}
