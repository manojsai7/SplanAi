require('dotenv').config();
const express = require('express');
const multer = require('multer');
const mongoose = require('mongoose');
const { ImageAnnotatorClient } = require('@google-cloud/vision');
const { Configuration, OpenAIApi ,OpenAI} = require('openai');
const cors = require('cors');
const session = require('express-session');
const MongoStore = require('connect-mongo');

const app = express();
const upload = multer({ dest: 'uploads/' });

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public'));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: true,
  store: MongoStore.create({ mongoUrl: process.env.MONGODB_URI }),
}));

// MongoDB Setup
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const ContentSchema = new mongoose.Schema({
  sessionId: String,
  text: String,
  flashcards: [{ question: String, answer: String }],
  summary: String,
});
const Content = mongoose.model('Content', ContentSchema);

// Google Vision API
const visionClient = new ImageAnnotatorClient();

// OpenAI API
//const { OpenAI } = require('openai');
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

// Upload Route
app.post('/upload', upload.single('file'), async (req, res) => {
  try {
    const [visionResult] = await visionClient.textDetection(req.file.path);
    const text = visionResult.textAnnotations[0]?.description || 'No text found';

    const flashcardsResponse = await openai.createCompletion({
      model: 'text-davinci-003',
      prompt: `Generate 5 flashcards (question and answer pairs) from this text: ${text}`,
      max_tokens: 200,
    });
    const flashcardsText = flashcardsResponse.data.choices[0].text.trim();
    const flashcards = flashcardsText.split('\n').map(line => {
      const [question, answer] = line.split(' - ');
      return { question: question || 'What?', answer: answer || 'Define this' };
    }).filter(f => f.question && f.answer);

    const summaryResponse = await openai.createCompletion({
      model: 'text-davinci-003',
      prompt: `Summarize this text in 50 words: ${text}`,
      max_tokens: 60,
    });
    const summary = summaryResponse.data.choices[0].text.trim();

    const content = new Content({ sessionId: req.session.id, text, flashcards, summary });
    await content.save();
    res.json({ id: content._id });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Something went wrong!' });
  }
});

// Fetch Content
app.get('/content', async (req, res) => {
  const content = await Content.findOne({ sessionId: req.session.id });
  if (!content) return res.status(404).json({ error: 'No content found' });
  res.json(content);
});

// Start Server
const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server live on port ${port}`));