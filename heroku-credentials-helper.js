// Helper script to generate Heroku-compatible Google credentials
const fs = require('fs');
const path = require('path');

// Path to Google credentials file
const googleKeyPath = path.join(__dirname, 'google-key.json');

try {
  // Read the Google credentials file
  const googleKeyContent = fs.readFileSync(googleKeyPath, 'utf8');
  
  // Parse and stringify to ensure it's valid JSON
  const parsedCredentials = JSON.parse(googleKeyContent);
  const minifiedCredentials = JSON.stringify(parsedCredentials);
  
  console.log('\n=== HEROKU SETUP INSTRUCTIONS ===');
  console.log('Run the following command to set your Google credentials in Heroku:');
  console.log(`\nheroku config:set GOOGLE_APPLICATION_CREDENTIALS_JSON='${minifiedCredentials}'`);
  console.log('\nMake sure to also set these other required environment variables:');
  console.log('heroku config:set NODE_ENV="production"');
  console.log('heroku config:set MONGODB_URI="your-mongodb-uri"');
  console.log('heroku config:set OPENAI_API_KEY="your-openai-api-key"');
  console.log('=================================\n');
} catch (error) {
  console.error('Error reading or parsing Google credentials file:', error.message);
  console.error('Make sure google-key.json exists in the project root and contains valid JSON.');
}
