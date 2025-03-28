// SplanAI Chatbot Assistant
function toggleChat() {
    var chat = document.getElementById("chatbot-container");
    var chatMessages = document.getElementById("chat-messages");
    
    if (chat.style.display === "block") {
        chat.style.display = "none";
    } else {
        chat.style.display = "block";
        // Clear chat only if it's not empty
        if (chatMessages.childElementCount === 0) {
            showWelcomeMessage();
        }
    }
}

function showWelcomeMessage() {
    addBotMessage("Hi there! I'm your SplanAI assistant. Do you need help with anything?");
    addYesNoButtons(showServices);
}

function showServices() {
    addBotMessage("I can help you with the following services:");
    addServiceButtons();
}

function addServiceButtons() {
    var chatMessages = document.getElementById("chat-messages");
    var serviceContainer = createButtonContainer();

    ["Flashcards", "Quiz", "Summary"].forEach(service => {
        serviceContainer.appendChild(createButton(service, () => informUserToStart(service)));
    });

    chatMessages.appendChild(serviceContainer);
}

function informUserToStart(service) {
    var chatMessages = document.getElementById("chat-messages");
    
    // Remove existing "Get Started" buttons if already present
    var existingStartButton = document.getElementById("start-button-container");
    if (existingStartButton) {
        existingStartButton.remove();
    }

    addBotMessage(`To create <strong>${service}</strong>, please click the <strong>'Input Content'</strong> tab and upload your file, notes, or image.`);

    var startContainer = createButtonContainer();
    startContainer.id = "start-button-container";
    startContainer.appendChild(createButton("Input Content", redirectToUpload));
    chatMessages.appendChild(startContainer);
}

function redirectToUpload() {
    addUserMessage("Input Content");
    document.querySelector('[data-tab="input-tab"]').click();
    setTimeout(askForMoreHelp, 1500);
}

function askForMoreHelp() {
    addBotMessage("Is there anything else I can help you with?");
    addYesNoButtons(showServices, thankUser);
}

function thankUser() {
    addBotMessage("Thank you for using SplanAI! Have a great study session!");
}

/** Utility Functions **/

function createButton(text, onClick) {
    var button = document.createElement("button");
    button.innerText = text;
    button.className = "capsule-button";
    button.onclick = onClick;
    return button;
}

function createButtonContainer() {
    var container = document.createElement("div");
    container.className = "button-container";
    return container;
}

function addYesNoButtons(yesCallback, noCallback = noHelpResponse) {
    var chatMessages = document.getElementById("chat-messages");
    var buttonContainer = createButtonContainer();

    buttonContainer.appendChild(createButton("Yes", yesCallback));
    buttonContainer.appendChild(createButton("No", noCallback));

    chatMessages.appendChild(buttonContainer);
}

function addBotMessage(text) {
    var chatMessages = document.getElementById("chat-messages");
    var botMsg = document.createElement("p");
    botMsg.className = "bot-message";
    botMsg.innerHTML = `<strong>SplanAI:</strong> ${text}`;
    chatMessages.appendChild(botMsg);
    
    // Auto-scroll to the bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function addUserMessage(text) {
    var chatMessages = document.getElementById("chat-messages");
    var userMsg = document.createElement("p");
    userMsg.className = "user-message";
    userMsg.innerHTML = `<strong>You:</strong> ${text}`;
    chatMessages.appendChild(userMsg);
    
    // Auto-scroll to the bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function noHelpResponse() {
    addBotMessage("No worries! I'm here whenever you need me.");
}

function sendMessage() {
    var userInput = document.getElementById("user-input");
    var message = userInput.value.trim();
    
    if (message) {
        addUserMessage(message);
        userInput.value = '';
        
        // Show typing indicator
        showTypingIndicator();
        
        // Process the message and respond
        setTimeout(() => {
            hideTypingIndicator();
            processUserMessage(message);
        }, 1000);
    }
}

function handleKeyPress(event) {
    if (event.key === "Enter") {
        sendMessage();
    }
}

function showTypingIndicator() {
    var chatMessages = document.getElementById("chat-messages");
    var typingIndicator = document.createElement("p");
    typingIndicator.className = "bot-message typing";
    typingIndicator.id = "typing-indicator";
    typingIndicator.innerHTML = "SplanAI is typing...";
    chatMessages.appendChild(typingIndicator);
    typingIndicator.style.display = "block";
    
    // Auto-scroll to the bottom
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

function hideTypingIndicator() {
    var typingIndicator = document.getElementById("typing-indicator");
    if (typingIndicator) {
        typingIndicator.remove();
    }
}

function processUserMessage(message) {
    // Simple keyword-based responses
    const messageLower = message.toLowerCase();
    
    if (messageLower.includes("flashcard") || messageLower.includes("card")) {
        informUserToStart("Flashcards");
    } else if (messageLower.includes("quiz") || messageLower.includes("test")) {
        informUserToStart("Quiz");
    } else if (messageLower.includes("summary") || messageLower.includes("summarize")) {
        informUserToStart("Summary");
    } else if (messageLower.includes("help") || messageLower.includes("how")) {
        showServices();
    } else if (messageLower.includes("thank")) {
        addBotMessage("You're welcome! Happy to help.");
    } else {
        // Default response
        addBotMessage("I can help you create study materials from your content. What would you like to do?");
        addServiceButtons();
    }
}

// Initialize chatbot when the page loads
document.addEventListener("DOMContentLoaded", function() {
    // Check if chatbot elements exist before adding event listeners
    if (document.getElementById("user-input")) {
        document.getElementById("user-input").addEventListener("keypress", handleKeyPress);
    }
    
    if (document.getElementById("send-button")) {
        document.getElementById("send-button").addEventListener("click", sendMessage);
    }
});
