# Heroku Deployment Guide for SplanAI

This guide will help you properly set up your SplanAI application on Heroku.

## Required Environment Variables

Set up the following environment variables in Heroku:

1. **MONGODB_URI**: Your MongoDB connection string
2. **OPENAI_API_KEY**: Your OpenAI API key
3. **GOOGLE_APPLICATION_CREDENTIALS_JSON**: The entire contents of your google-key.json file
4. **NODE_ENV**: Set to "production"

## Setting Up Google Cloud Vision Credentials

Since Heroku doesn't support persistent file storage for credentials, we need to store the Google credentials as an environment variable.

### Steps:

1. Run this command to convert your google-key.json to a string that can be added to Heroku:

```bash
cat google-key.json | tr -d '\n\t' | tr -d ' '
```

2. In Heroku, add a new config var called `GOOGLE_APPLICATION_CREDENTIALS_JSON` and paste the output from step 1.

## Heroku CLI Commands

```bash
# Login to Heroku
heroku login

# Create a new Heroku app (if not already created)
heroku create my-splanai-app

# Set environment variables
heroku config:set MONGODB_URI="your-mongodb-uri"
heroku config:set OPENAI_API_KEY="your-openai-api-key"
heroku config:set GOOGLE_APPLICATION_CREDENTIALS_JSON="$(cat google-key.json | tr -d '\n\t')"
heroku config:set NODE_ENV="production"

# Deploy to Heroku
git push heroku main
```

## Troubleshooting

If you encounter errors during deployment:

1. Check Heroku logs: `heroku logs --tail`
2. Verify all environment variables are set correctly: `heroku config`
3. Ensure the Node.js version in package.json is supported by Heroku
4. Make sure the Procfile is formatted correctly

Remember that the application requires:
- MongoDB connection
- OpenAI API access
- Google Cloud Vision API access

All these services must be properly configured for the application to work correctly.
