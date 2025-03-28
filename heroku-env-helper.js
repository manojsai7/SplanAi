/**
 * Heroku Environment Variable Helper Script
 * 
 * This script helps you prepare environment variables for Heroku deployment.
 * It will:
 * 1. Format MongoDB connection strings correctly with proper encoding
 * 2. Format Google Cloud credentials for Heroku environment variables
 * 3. Provide guidance on MongoDB Atlas IP whitelisting
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
  console.log('3. MongoDB Atlas IP Whitelist Guide');
  console.log('4. Generate Heroku Config Commands');
  console.log('5. Exit');
  
  rl.question('\nSelect an option (1-5): ', (answer) => {
    switch (answer) {
      case '1':
        formatMongoDB();
        break;
      case '2':
        formatGoogleCreds();
        break;
      case '3':
        showMongoDBWhitelistGuide();
        break;
      case '4':
        generateHerokuConfig();
        break;
      case '5':
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

// MongoDB IP Whitelist guide
function showMongoDBWhitelistGuide() {
  console.log('\n=== MongoDB Atlas IP Whitelist Guide ===\n');
  console.log('The SSL/TLS error and IP whitelist issues are common when deploying to Heroku.');
  console.log('\nTo fix IP whitelist issues:');
  console.log('1. Log in to your MongoDB Atlas account');
  console.log('2. Select your cluster');
  console.log('3. Navigate to Network Access in the left sidebar');
  console.log('4. Click "+ Add IP Address"');
  console.log('5. OPTION A (Temporary): Click "Allow Access from Anywhere" to add 0.0.0.0/0');
  console.log('   This will allow any IP to connect (use for testing only)');
  console.log('6. OPTION B (Recommended): Add Heroku\'s IP ranges');
  console.log('   You can find Heroku\'s current IP ranges at: https://devcenter.heroku.com/articles/heroku-cloud-ip-ranges');
  console.log('\nNote: For a SSL/TLS error, we\'ve already added code to bypass the certificate validation.');
  console.log('This is a workaround and not ideal for production environments with sensitive data.');
  
  askContinue();
}

// Generate Heroku Config Commands
function generateHerokuConfig() {
  console.log('\n=== Generate Heroku Config Commands ===\n');
  console.log('This will help you generate all the config commands needed for Heroku.');
  
  let configVars = {};
  
  const askForMongo = () => {
    rl.question('Enter your MongoDB URI: ', (uri) => {
      if (uri) {
        configVars.MONGODB_URI = formatMongoDBUri(uri);
      }
      askForOpenAI();
    });
  };
  
  const askForOpenAI = () => {
    rl.question('Enter your OpenAI API Key: ', (key) => {
      if (key) {
        configVars.OPENAI_API_KEY = key;
      }
      askForSessionSecret();
    });
  };
  
  const askForSessionSecret = () => {
    rl.question('Enter a session secret (or press enter to generate one): ', (secret) => {
      if (!secret) {
        // Generate a random string
        const randomBytes = require('crypto').randomBytes(32);
        secret = randomBytes.toString('hex');
        console.log(`Generated session secret: ${secret}`);
      }
      configVars.SESSION_SECRET = secret;
      askForGoogleCredentials();
    });
  };
  
  const askForGoogleCredentials = () => {
    rl.question('Enter path to Google credentials file (or press enter to skip): ', (path) => {
      if (path && path.trim()) {
        const creds = formatGoogleCredentials(path.trim());
        if (creds) {
          configVars.GOOGLE_APPLICATION_CREDENTIALS_JSON = creds;
        }
      }
      
      // Now show all the config commands
      console.log('\n=== Heroku Config Commands ===');
      Object.entries(configVars).forEach(([key, value]) => {
        console.log(`heroku config:set ${key}="${value}"`);
      });
      
      console.log('\n=== Copy and run these commands in your terminal ===');
      
      askContinue();
    });
  };
  
  askForMongo();
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
