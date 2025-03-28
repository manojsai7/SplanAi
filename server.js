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
  
  // Try to format the URI if it's missing the protocol
  if (uri.includes('@') && (uri.includes('.mongodb.net') || uri.includes('.mongo.cosmos'))) {
    return `mongodb+srv://${uri}`;
  }
  
  console.error('Invalid MongoDB URI format, unable to automatically correct');
  return null;
};

// Enhanced MongoDB Atlas Connection
const connectDB = async () => {
  try {
    const mongoUri = getValidMongoDBURI(process.env.MONGODB_URI);
    if (!mongoUri) {
      throw new Error('Invalid MongoDB URI. Please check your environment variables.');
    }
    
    await mongoose.connect(mongoUri, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      retryWrites: true,
      w: 'majority'
    });
    console.log('MongoDB Connected with Advanced Configuration');
  } catch (err) {
    console.error('Database Connection Error:', err);
    // Don't exit process in production - let the app continue without DB
    if (process.env.NODE_ENV !== 'production') {
      process.exit(1);
    }
  }
};
connectDB();

// AI Clients Configuration
let visionClient;
try {
  // Check if running on Heroku (where we'd use the JSON string in env var)
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON) {
    visionClient = new ImageAnnotatorClient({
      credentials: JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON)
    });
  } else {
    // Local development (where we use the file path)
    visionClient = new ImageAnnotatorClient({
      keyFilename: process.env.GOOGLE_APPLICATION_CREDENTIALS
    });
  }
  console.log('Vision API client initialized successfully');
} catch (error) {
  console.error('Error initializing Vision client:', error);
  // Create a dummy client for testing without failing the app
  visionClient = {
    documentTextDetection: async () => {
      console.warn('Using mock Vision API client');
      return [{ fullTextAnnotation: { text: 'Mock OCR text for testing' } }];
    }
  };
}

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 30000,
  maxRetries: 3
});

// Express App Configuration
const app = express();
app.use(express.json()); // Support for JSON payloads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 20 * 1024 * 1024 } // Limit file size to 20MB
});

// Advanced Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"]
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
app.use(session({
  secret: process.env.SESSION_SECRET || 'splanAI-super-secret',
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: getValidMongoDBURI(process.env.MONGODB_URI),
    collectionName: 'sessions'
  }),
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    maxAge: 1000 * 60 * 60 * 24 * 7 // 1 week
  }
}));

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
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});
