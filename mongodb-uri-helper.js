/**
 * MongoDB URI Helper for Heroku Deployment
 * 
 * This script helps format and encode MongoDB connection strings
 * for proper use in Heroku environment variables.
 */

// Read command line arguments
const args = process.argv.slice(2);
if (args.length === 0) {
  console.log(`
MongoDB URI Helper for Heroku
============================

This tool helps properly format MongoDB connection strings for Heroku deployment.

Usage:
  node mongodb-uri-helper.js <mongodb-connection-string>

Examples:
  node mongodb-uri-helper.js "mongodb+srv://username:p@ssw0rd@cluster0.mongodb.net/mydb"
  node mongodb-uri-helper.js "username:my_complex_p@ssw0rd!@cluster0.mongodb.net/mydb"
  
Output:
  The tool will output a properly formatted and encoded connection string
  that you can safely use in your Heroku environment variables.
  `);
  process.exit(0);
}

// The MongoDB URI from command line
const inputUri = args[0];

// Format and encode the MongoDB URI
function formatMongoDBUri(uri) {
  try {
    // Check if URI already has the correct format
    if (uri.startsWith('mongodb://') || uri.startsWith('mongodb+srv://')) {
      // For URIs with the correct protocol, make sure the password is properly encoded
      const uriParts = uri.split('://')[1];
      const authAndRest = uriParts.split('@');
      
      // If there's no @ sign or multiple @ signs in auth part, it might be a malformed URI
      if (authAndRest.length < 2) {
        throw new Error('Malformed MongoDB URI: Missing authentication part');
      }
      
      // Handle complex cases where @ might appear in the password
      const auth = authAndRest[0];
      // Join back anything after the first @ as it might be part of the connection details
      const rest = authAndRest.slice(1).join('@');
      
      // Split auth into username and password
      const colonIndex = auth.indexOf(':');
      if (colonIndex === -1) {
        throw new Error('Malformed authentication in MongoDB URI: Missing password separator');
      }
      
      const username = auth.substring(0, colonIndex);
      const password = auth.substring(colonIndex + 1);
      
      // Encode the password - this handles special characters
      const encodedPassword = encodeURIComponent(password);
      
      // Reconstruct the URI with encoded password
      const protocol = uri.startsWith('mongodb+srv') ? 'mongodb+srv' : 'mongodb';
      return `${protocol}://${username}:${encodedPassword}@${rest}`;
    } 
    // Try to format the URI if it's missing the protocol
    else if (uri.includes('@')) {
      // Similar process for URIs without protocol
      const authAndRest = uri.split('@');
      
      if (authAndRest.length < 2) {
        throw new Error('Malformed MongoDB URI: Missing host part');
      }
      
      const auth = authAndRest[0];
      const rest = authAndRest.slice(1).join('@');
      
      const colonIndex = auth.indexOf(':');
      if (colonIndex === -1) {
        throw new Error('Malformed authentication in MongoDB URI: Missing password separator');
      }
      
      const username = auth.substring(0, colonIndex);
      const password = auth.substring(colonIndex + 1);
      
      // Encode the password
      const encodedPassword = encodeURIComponent(password);
      
      // Determine the protocol based on the host
      const protocol = rest.includes('.mongodb.net') ? 'mongodb+srv' : 'mongodb';
      return `${protocol}://${username}:${encodedPassword}@${rest}`;
    } else {
      throw new Error('Invalid MongoDB URI format: URI must include at least a username, password, and hostname');
    }
  } catch (error) {
    console.error('Error processing MongoDB URI:', error.message);
    return null;
  }
}

// Process the input URI
const formattedUri = formatMongoDBUri(inputUri);

if (formattedUri) {
  console.log("\nFormatted and Encoded MongoDB URI:");
  console.log("----------------------------------");
  console.log(formattedUri);
  
  console.log("\nFor Heroku CLI:");
  console.log("---------------");
  console.log(`heroku config:set MONGODB_URI="${formattedUri}" --app your-app-name`);
  
  console.log("\nRemember to replace 'your-app-name' with your actual Heroku app name.");
} else {
  console.error("\nFailed to process the MongoDB URI. Please check the format and try again.");
}
