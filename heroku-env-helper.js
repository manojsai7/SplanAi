/**
 * Heroku Environment Variable Helper Script
 * 
 * This script helps you prepare environment variables for Heroku deployment.
 * It will:
 * 1. Format MongoDB connection strings correctly with proper encoding
 * 2. Format Google Cloud credentials for Heroku environment variables
 * 
 * Run this script with Node.js:
 * node heroku-env-helper.js
 */

const fs = require('fs');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// Helper to properly encode MongoDB URI
function formatMongoDBUri(uri) {
  if (!uri) return null;
  
  // Make sure the URI has the proper protocol
  if (!uri.startsWith('mongodb://') && !uri.startsWith('mongodb+srv://')) {
    uri = 'mongodb+srv://' + uri;
  }
  
  // Check if we need to encode the password in the URI
  const uriRegex = /^mongodb(\+srv)?:\/\/([^:]+):([^@]+)@(.+)$/;
  const match = uri.match(uriRegex);
  
  if (match) {
    // Extract parts
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
    
    // Rebuild URI
    return `${protocol}${username}:${password}@${hostAndRest}`;
  }
  
  return uri;
}

// Helper to format Google Cloud credentials JSON
function formatGoogleCredentials(filePath) {
  try {
    // Read and parse the credentials file
    const credentialsRaw = fs.readFileSync(filePath, 'utf8');
    const credentials = JSON.parse(credentialsRaw);
    
    // Validate it has required fields
    if (!credentials.type || !credentials.project_id) {
      console.error('Error: Invalid Google credentials format in file');
      return null;
    }
    
    // Format for Heroku: stringify without extra whitespace
    return JSON.stringify(credentials);
  } catch (error) {
    console.error(`Error reading/parsing Google credentials: ${error.message}`);
    return null;
  }
}

// Main menu
function showMainMenu() {
  console.log('\n=== Heroku Environment Variable Helper ===\n');
  console.log('1. Format MongoDB Connection String');
  console.log('2. Format Google Cloud Credentials');
  console.log('3. Exit');
  
  rl.question('\nSelect an option (1-3): ', (answer) => {
    switch (answer) {
      case '1':
        formatMongoDB();
        break;
      case '2':
        formatGoogleCreds();
        break;
      case '3':
        console.log('Exiting script. Goodbye!');
        rl.close();
        break;
      default:
        console.log('Invalid option. Please try again.');
        showMainMenu();
    }
  });
}

// MongoDB formatter workflow
function formatMongoDB() {
  rl.question('\nEnter your MongoDB URI: ', (uri) => {
    const formattedUri = formatMongoDBUri(uri);
    
    if (formattedUri) {
      console.log('\n=== Formatted MongoDB URI ===');
      console.log(formattedUri);
      
      console.log('\n=== Heroku CLI Command ===');
      console.log(`heroku config:set MONGODB_URI="${formattedUri}"`);
    } else {
      console.log('Error formatting MongoDB URI');
    }
    
    askContinue();
  });
}

// Google Cloud credentials workflow
function formatGoogleCreds() {
  rl.question('\nEnter the path to your Google Cloud credentials JSON file: ', (path) => {
    const formattedCreds = formatGoogleCredentials(path);
    
    if (formattedCreds) {
      console.log('\n=== Formatted Google Credentials for Heroku ===');
      console.log(formattedCreds);
      
      console.log('\n=== Heroku CLI Command ===');
      console.log(`heroku config:set GOOGLE_APPLICATION_CREDENTIALS_JSON='${formattedCreds}'`);
    }
    
    askContinue();
  });
}

// Ask to continue or exit
function askContinue() {
  rl.question('\nReturn to main menu? (y/n): ', (answer) => {
    if (answer.toLowerCase() === 'y') {
      showMainMenu();
    } else {
      console.log('Exiting script. Goodbye!');
      rl.close();
    }
  });
}

// Start the script
showMainMenu();
