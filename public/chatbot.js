// SplanAI Chatbot Assistant
document.addEventListener('DOMContentLoaded', function() {
    // Initialize elements
    const toggleChatBtn = document.getElementById('toggle-chat');
    const closeChatBtn = document.getElementById('close-chat');
    const minimizeChatBtn = document.getElementById('minimize-chat');
    const chatbotContainer = document.getElementById('chatbot-container');
    const userInput = document.getElementById('user-input');
    const sendButton = document.getElementById('send-button');
    const chatMessages = document.getElementById('chat-messages');
    
    // Event listeners
    if (toggleChatBtn) {
        toggleChatBtn.addEventListener('click', toggleChat);
    }
    
    if (closeChatBtn) {
        closeChatBtn.addEventListener('click', toggleChat);
    }
    
    if (minimizeChatBtn) {
        minimizeChatBtn.addEventListener('click', toggleChat);
    }
    
    if (userInput) {
        userInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                sendMessage();
            }
        });
    }
    
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
    }
    
    // Initialize chat state
    if (chatbotContainer) {
        chatbotContainer.style.display = 'none';
    }
    
    // Function to toggle chat visibility
    function toggleChat() {
        if (chatbotContainer.style.display === 'flex' || chatbotContainer.style.display === 'block') {
            chatbotContainer.style.display = 'none';
        } else {
            chatbotContainer.style.display = 'flex';
            // Show welcome message if chat is empty
            if (chatMessages && chatMessages.childElementCount === 0) {
                showWelcomeMessage();
            }
            // Focus the input field
            if (userInput) {
                userInput.focus();
            }
        }
    }
    
    // Show welcome message
    function showWelcomeMessage() {
        addBotMessage("Hi there! I'm your SplanAI assistant. How can I help you today?");
        addServiceButtons();
    }
    
    // Add service buttons
    function addServiceButtons() {
        const serviceContainer = createButtonContainer();
        
        ["Upload Document", "Create Flashcards", "Generate Quiz", "Summarize Text", "Ask Questions"].forEach(service => {
            serviceContainer.appendChild(createButton(service, () => handleServiceSelection(service)));
        });
        
        chatMessages.appendChild(serviceContainer);
    }
    
    // Handle service selection
    function handleServiceSelection(service) {
        switch(service) {
            case "Upload Document":
                addUserMessage("I want to upload a document");
                addBotMessage("Great! Please go to the 'Input Content' tab to upload your document or enter text directly.");
                addActionButton("Go to Upload", () => {
                    document.querySelector('[data-tab="input-tab"]').click();
                });
                break;
            case "Create Flashcards":
                addUserMessage("I want to create flashcards");
                addBotMessage("To create flashcards, first upload your document or enter text in the 'Input Content' tab. After processing, you can view your flashcards in the 'Flashcards' tab.");
                addActionButton("Go to Upload", () => {
                    document.querySelector('[data-tab="input-tab"]').click();
                });
                break;
            case "Generate Quiz":
                addUserMessage("I want to generate a quiz");
                addBotMessage("To generate a quiz, first upload your document or enter text in the 'Input Content' tab. After processing, you can take your quiz in the 'Quiz' tab.");
                addActionButton("Go to Upload", () => {
                    document.querySelector('[data-tab="input-tab"]').click();
                });
                break;
            case "Summarize Text":
                addUserMessage("I want to summarize text");
                addBotMessage("To get a summary, upload your document or enter text in the 'Input Content' tab. After processing, you can view your summary in the 'Summary' tab.");
                addActionButton("Go to Upload", () => {
                    document.querySelector('[data-tab="input-tab"]').click();
                });
                break;
            case "Ask Questions":
                addUserMessage("I want to ask questions");
                addBotMessage("What would you like to know? You can ask me anything about your documents or how to use SplanAI.");
                break;
            default:
                addBotMessage("I'm not sure how to help with that. Please try one of the other options or ask me a specific question.");
        }
    }
    
    // Add action button
    function addActionButton(text, onClick) {
        const actionContainer = createButtonContainer();
        actionContainer.appendChild(createButton(text, onClick));
        chatMessages.appendChild(actionContainer);
    }
    
    // Create button
    function createButton(text, onClick) {
        const button = document.createElement("button");
        button.innerText = text;
        button.className = "capsule-button";
        button.onclick = onClick;
        return button;
    }
    
    // Create button container
    function createButtonContainer() {
        const container = document.createElement("div");
        container.className = "button-container";
        return container;
    }
    
    // Add bot message
    function addBotMessage(text) {
        const messageElement = document.createElement("div");
        messageElement.className = "chat-message bot-message";
        
        const avatar = document.createElement("div");
        avatar.className = "avatar bot-avatar";
        avatar.innerHTML = '<i class="fas fa-robot"></i>';
        
        const messageContent = document.createElement("div");
        messageContent.className = "message-content";
        messageContent.innerHTML = text;
        
        messageElement.appendChild(avatar);
        messageElement.appendChild(messageContent);
        
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Add user message
    function addUserMessage(text) {
        const messageElement = document.createElement("div");
        messageElement.className = "chat-message user-message";
        
        const avatar = document.createElement("div");
        avatar.className = "avatar user-avatar";
        avatar.innerHTML = '<i class="fas fa-user"></i>';
        
        const messageContent = document.createElement("div");
        messageContent.className = "message-content";
        messageContent.innerHTML = text;
        
        messageElement.appendChild(avatar);
        messageElement.appendChild(messageContent);
        
        chatMessages.appendChild(messageElement);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Send message
    function sendMessage() {
        const message = userInput.value.trim();
        
        if (message === "") return;
        
        // Clear input field
        userInput.value = "";
        
        // Display user message
        addUserMessage(message);
        
        // Show typing indicator
        showTypingIndicator();
        
        // Process message and get response
        processUserMessage(message);
    }
    
    // Show typing indicator
    function showTypingIndicator() {
        const typingIndicator = document.createElement("div");
        typingIndicator.id = "typing-indicator";
        typingIndicator.className = "chat-message bot-typing";
        
        typingIndicator.innerHTML = `
            <div class="avatar bot-avatar">
                <i class="fas fa-robot"></i>
            </div>
            <div class="message-content">
                <div class="typing-indicator">
                    <span></span><span></span><span></span>
                </div>
            </div>
        `;
        
        chatMessages.appendChild(typingIndicator);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Hide typing indicator
    function hideTypingIndicator() {
        const typingIndicator = document.getElementById("typing-indicator");
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }
    
    // Process user message
    async function processUserMessage(message) {
        try {
            // Get or create session ID
            let sessionId = localStorage.getItem('chatSessionId');
            if (!sessionId) {
                sessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
                localStorage.setItem('chatSessionId', sessionId);
            }
            
            // Call the chatbot API
            const response = await fetch('/api/chatbot', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    message: message,
                    sessionId: sessionId
                })
            });
            
            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.message || errorData.error || 'Network response was not ok');
            }
            
            const data = await response.json();
            
            // Hide typing indicator
            hideTypingIndicator();
            
            // Display bot response
            addBotMessage(data.reply || data.message || "I'm not sure how to respond to that.");
            
            // Check for suggested actions
            checkForSuggestedActions(data.reply || data.message || "");
        } catch (error) {
            console.error('Error:', error);
            
            // Hide typing indicator
            hideTypingIndicator();
            
            // Display error message
            addBotMessage("I'm sorry, I encountered an error while processing your request. Please try again later.");
        }
    }
    
    // Check for suggested actions based on bot response
    function checkForSuggestedActions(reply) {
        const lowerReply = reply.toLowerCase();
        
        // Check for upload mentions
        if ((lowerReply.includes('upload') || lowerReply.includes('document')) && 
            (lowerReply.includes('file') || lowerReply.includes('content'))) {
            setTimeout(() => {
                addActionButton("Go to Upload", () => {
                    document.querySelector('[data-tab="input-tab"]').click();
                });
            }, 500);
        }
        
        // Check for flashcard mentions
        if (lowerReply.includes('flashcard')) {
            setTimeout(() => {
                addActionButton("View Flashcards", () => {
                    document.querySelector('[data-tab="flashcards-tab"]').click();
                });
            }, 500);
        }
        
        // Check for quiz mentions
        if (lowerReply.includes('quiz') || lowerReply.includes('test')) {
            setTimeout(() => {
                addActionButton("Take Quiz", () => {
                    document.querySelector('[data-tab="quiz-tab"]').click();
                });
            }, 500);
        }
        
        // Check for summary mentions
        if (lowerReply.includes('summary') || lowerReply.includes('summarize')) {
            setTimeout(() => {
                addActionButton("View Summary", () => {
                    document.querySelector('[data-tab="summary-tab"]').click();
                });
            }, 500);
        }
    }
});
