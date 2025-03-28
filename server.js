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

// Enhanced MongoDB Atlas Connection
const connectDB = async () => {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
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
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
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

// Add basic health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Database Schemas
const ContentSchema = new mongoose.Schema({
  sessionId: { type: String, index: true },
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
      processedAt: Date
    }
  }
}, { timestamps: true });

const Content = mongoose.model('Content', ContentSchema);

// Enhanced AI Processing Pipeline
const processContent = async (buffer, sessionId) => {
  try {
    // Advanced OCR with Google Vision
    const [ocrResult] = await visionClient.documentTextDetection({
      image: { content: buffer.toString('base64') }
    });

    const fullText = ocrResult.fullTextAnnotation?.text || '';
    
    // AI Processing with OpenAI
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

    // Save to Database
    const contentDoc = new Content({
      sessionId,
      content: {
        text: fullText,
        flashcards: flashcards,
        quizzes: quizzes,
        summary: summaryResponse.choices[0].message.content,
        metadata: {
          pages: ocrResult.fullTextAnnotation?.pages?.length || 0,
          languages: ocrResult.textAnnotations ? [...new Set(ocrResult.textAnnotations.map(ta => ta.locale).filter(Boolean))] : [],
          processedAt: new Date()
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

// API Endpoints
app.post('/api/process', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    const sessionId = uuidv4();
    const result = await processContent(req.file.buffer, sessionId);
    res.json({ sessionId, content: result.content });
  } catch (error) {
    console.error('Error processing file:', error);
    res.status(500).json({ error: error.message || 'Unknown error occurred' });
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
  app.get('/', (req, res) => {
    res.json({ message: 'SplanAI API Server is running' });
  });
}

// Server Start with proper error handling
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});
