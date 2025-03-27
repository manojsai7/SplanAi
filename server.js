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
    process.exit(1);
  }
};
connectDB();

// AI Clients Configuration
const visionClient = new ImageAnnotatorClient({
  credentials: JSON.parse(process.env.GOOGLE_APPLICATION_CREDENTIALS_JSON)
});

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
app.use(helmet());
app.use(cors({
  origin: process.env.CLIENT_URL,
  credentials: true
}));
app.use(rateLimit({
  windowMs: 15 * 60 * 1000, // Limit each IP to 100 requests per windowMs
  max: 100
}));

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
        messages: [{ role: 'user', content: `Generate flashcards from this text:\n${fullText}` }]
      }),
      openai.chat.completions.create({
        model: 'gpt-4',
        messages: [{ role: 'user', content: `Create quizzes based on this text:\n${fullText}` }]
      })
    ]);

    // Save to Database
    const contentDoc = new Content({
      sessionId,
      content: {
        text: fullText,
        flashcards: JSON.parse(flashcardsResponse.choices[0].message.content),
        quizzes: JSON.parse(quizzesResponse.choices[0].message.content),
        summary: summaryResponse.choices[0].message.content,
        metadata: {
          pages: ocrResult.fullTextAnnotation?.pages?.length || 0,
          languages: [...new Set(ocrResult.textAnnotations?.map(ta => ta.locale))],
          processedAt: new Date()
        }
      }
    });

    await contentDoc.save();
    return contentDoc;
  } catch (error) {
    console.error('AI Processing Error:', error);
    throw new Error('Advanced content processing failed');
  }
};

// API Endpoints
app.post('/api/process', upload.single('file'), async (req, res) => {
  try {
    const sessionId = uuidv4();
    const result = await processContent(req.file.buffer, sessionId);
    res.json({ sessionId, content: result.content });
  } catch (error) {
    console.error('Error processing file:', error);
    res.status(500).json({ error: error.message });
  }
});

// Serve Frontend
app.use(express.static(path.join(__dirname, 'client', 'build')));
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'client', 'build', 'index.html'));
});

// Server Start
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

const { v4: uuidv4 } = require('uuid');
console.log(uuidv4()); // Generates a unique UUID
