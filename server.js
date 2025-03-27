const express = require('express');
const app = express();
require('dotenv').config();

// Basic setup
app.use(express.json());

// Database connection
const mongoose = require('mongoose');
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost/hackathon');

// Simple routes
app.get('/', (req, res) => res.send('Hello Hackathon! 🚀'));

// Start server
const PORT = 5000;
app.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));