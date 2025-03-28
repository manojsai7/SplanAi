// SplanAI Frontend JavaScript
document.addEventListener('DOMContentLoaded', function() {
  // Global Variables
  let currentSessionId = null;
  let currentContent = null;
  let currentFlashcardIndex = 0;
  let flashcards = [];
  let quizzes = [];
  let currentUser = null;
  
  // DOM Elements
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');
  const themeToggle = document.getElementById('theme-toggle');
  const fileInput = document.getElementById('file-input');
  const fileDropArea = document.getElementById('drop-area');
  const uploadPreview = document.getElementById('upload-preview');
  const fileName = document.getElementById('file-name');
  const removeFileBtn = document.getElementById('remove-file');
  const uploadBtn = document.getElementById('upload-btn');
  const directTextInput = document.getElementById('direct-text-input');
  const contentTitle = document.getElementById('content-title');
  const processTextBtn = document.getElementById('process-text-btn');
  const processingIndicator = document.getElementById('processing-indicator');
  const summaryContent = document.getElementById('summary-content');
  const documentTitle = document.getElementById('document-title');
  const downloadPdfBtn = document.getElementById('download-pdf');
  const shareContentBtn = document.getElementById('share-content');
  const saveContentBtn = document.getElementById('save-content');
  const downloadFlashcardsBtn = document.getElementById('download-flashcards');
  const printFlashcardsBtn = document.getElementById('print-flashcards');
  const printQuizBtn = document.getElementById('print-quiz');
  const flashcardsContainer = document.getElementById('flashcards-container');
  const prevCardBtn = document.getElementById('prev-card');
  const nextCardBtn = document.getElementById('next-card');
  const cardCounter = document.getElementById('card-counter');
  const quizContainer = document.getElementById('quiz-container');
  const quizContent = document.getElementById('quiz-content');
  const quizQuestion = document.getElementById('quiz-question');
  const quizProgress = document.getElementById('quiz-progress');
  const quizOptions = document.querySelector('.quiz-options');
  const quizFeedback = document.querySelector('.quiz-feedback');
  const quizExplanation = document.getElementById('quiz-explanation');
  const quizNextBtn = document.getElementById('quiz-next');
  const quizFinishBtn = document.getElementById('quiz-finish');
  const quizRestartBtn = document.getElementById('quiz-restart');
  const quizResults = document.getElementById('quiz-results');
  const quizScore = document.getElementById('quiz-score');
  const quizPercentage = document.getElementById('quiz-percentage');
  const chatMessages = document.getElementById('chat-messages');
  const chatInput = document.getElementById('chat-input');
  const sendMessageBtn = document.getElementById('send-message');
  const notification = document.getElementById('notification');
  const notificationMessage = document.getElementById('notification-message');
  
  // User Profile Elements
  const profileButton = document.getElementById('profile-button');
  const profileDropdown = document.getElementById('profile-dropdown');
  const usernameDisplay = document.getElementById('username-display');
  const userEmail = document.getElementById('user-email');
  const accountType = document.getElementById('account-type');
  const myDocumentsBtn = document.getElementById('my-documents');
  const accountSettingsBtn = document.getElementById('account-settings');
  const loginButton = document.getElementById('login-button');
  const logoutButton = document.getElementById('logout-button');
  
  // Modal Elements
  const loginRequiredModal = document.getElementById('login-required-modal');
  const goToLoginBtn = document.getElementById('go-to-login');
  const shareModal = document.getElementById('share-modal');
  const shareUrl = document.getElementById('share-url');
  const copyShareUrlBtn = document.getElementById('copy-share-url');
  const shareOptions = document.querySelectorAll('.share-option');
  const closeModalButtons = document.querySelectorAll('.close-modal');
  
  // ============= INITIALIZATION =============
  
  // Check Authentication on Load
  checkAuthStatus();
  
  function checkAuthStatus() {
    const token = localStorage.getItem('authToken');
    const user = localStorage.getItem('user');
    
    if (token && user) {
      // User is logged in
      currentUser = JSON.parse(user);
      updateUserInterface(true);
    } else {
      // User is not logged in
      currentUser = null;
      updateUserInterface(false);
    }
  }
  
  function updateUserInterface(isLoggedIn) {
    if (isLoggedIn && currentUser) {
      // Update profile display
      usernameDisplay.textContent = currentUser.username || 'User';
      userEmail.textContent = currentUser.email || '';
      accountType.textContent = 'Member Account';
      accountType.classList.add('member');
      
      // Update buttons visibility
      loginButton.classList.add('hidden');
      logoutButton.classList.remove('hidden');
      saveContentBtn.disabled = false;
    } else {
      // Reset to default/guest state
      usernameDisplay.textContent = 'Guest';
      userEmail.textContent = 'Not logged in';
      accountType.textContent = 'Guest Account';
      accountType.classList.remove('member');
      
      // Update buttons visibility
      loginButton.classList.remove('hidden');
      logoutButton.classList.add('hidden');
      saveContentBtn.disabled = true;
    }
  }
  
  // Tab Navigation
  tabButtons.forEach(button => {
    button.addEventListener('click', () => {
      const tabId = button.getAttribute('data-tab');
      
      // Deactivate all tab buttons and content
      tabButtons.forEach(btn => btn.classList.remove('active'));
      tabContents.forEach(content => content.classList.remove('active'));
      
      // Activate selected tab
      button.classList.add('active');
      document.getElementById(tabId).classList.add('active');
    });
  });
  
  // Theme Toggle
  themeToggle.addEventListener('click', () => {
    document.body.classList.toggle('dark-theme');
    
    if (document.body.classList.contains('dark-theme')) {
      themeToggle.innerHTML = '<i class="fas fa-sun"></i>';
    } else {
      themeToggle.innerHTML = '<i class="fas fa-moon"></i>';
    }
  });
  
  // Profile Dropdown Toggle
  profileButton.addEventListener('click', () => {
    profileDropdown.classList.toggle('show');
  });
  
  // Close profile dropdown when clicking outside
  document.addEventListener('click', (e) => {
    if (!profileButton.contains(e.target) && !profileDropdown.contains(e.target)) {
      profileDropdown.classList.remove('show');
    }
  });
  
  // Login Button
  loginButton.addEventListener('click', () => {
    window.location.href = '/login.html';
  });
  
  // Logout Button
  logoutButton.addEventListener('click', () => {
    // Clear authentication data
    localStorage.removeItem('authToken');
    localStorage.removeItem('user');
    
    // Update UI
    currentUser = null;
    updateUserInterface(false);
    
    // Show notification
    showNotification('You have been logged out successfully', 'success');
  });
  
  // My Documents Button
  myDocumentsBtn.addEventListener('click', () => {
    if (currentUser) {
      // Show documents tab
      profileDropdown.classList.remove('show');
      loadUserDocuments();
      
      // Create a new tab button if it doesn't exist
      const documentsTabExists = Array.from(tabButtons).some(btn => btn.getAttribute('data-tab') === 'documents-tab');
      
      if (!documentsTabExists) {
        // Add a temporary tab for documents
        const documentsTab = document.createElement('button');
        documentsTab.className = 'tab-btn';
        documentsTab.setAttribute('data-tab', 'documents-tab');
        documentsTab.innerHTML = 'My Documents';
        
        // Insert before the last tab (chat)
        const tabNavigation = document.querySelector('.tab-navigation');
        tabNavigation.appendChild(documentsTab);
        
        // Add event listener
        documentsTab.addEventListener('click', () => {
          tabButtons.forEach(btn => btn.classList.remove('active'));
          tabContents.forEach(content => content.classList.remove('active'));
          
          documentsTab.classList.add('active');
          document.getElementById('documents-tab').classList.add('active');
        });
      }
      
      // Switch to the documents tab
      document.querySelector('[data-tab="documents-tab"]').click();
    } else {
      // Show login required modal
      loginRequiredModal.classList.add('show');
    }
  });
  
  // Close Modal Buttons
  closeModalButtons.forEach(button => {
    button.addEventListener('click', () => {
      const modal = button.closest('.modal');
      modal.classList.remove('show');
    });
  });
  
  // Go to Login Button (in login required modal)
  goToLoginBtn.addEventListener('click', () => {
    window.location.href = '/login.html';
  });
  
  // ============= FILE UPLOAD =============
  
  // File Drop Area Events
  ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
    fileDropArea.addEventListener(eventName, preventDefaults, false);
  });
  
  function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
  }
  
  ['dragenter', 'dragover'].forEach(eventName => {
    fileDropArea.addEventListener(eventName, () => {
      fileDropArea.classList.add('active');
    });
  });
  
  ['dragleave', 'drop'].forEach(eventName => {
    fileDropArea.addEventListener(eventName, () => {
      fileDropArea.classList.remove('active');
    });
  });
  
  fileDropArea.addEventListener('drop', (e) => {
    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles.length) {
      fileInput.files = droppedFiles;
      updateFilePreview(droppedFiles[0]);
    }
  });
  
  // File Input Change
  fileInput.addEventListener('change', () => {
    if (fileInput.files.length) {
      updateFilePreview(fileInput.files[0]);
    }
  });
  
  // Update File Preview
  function updateFilePreview(file) {
    fileName.textContent = file.name;
    uploadPreview.classList.remove('hidden');
    
    // Set appropriate icon based on file type
    const iconElement = uploadPreview.querySelector('.preview-icon i');
    if (file.type.includes('image')) {
      iconElement.className = 'fas fa-image';
    } else if (file.type.includes('pdf')) {
      iconElement.className = 'fas fa-file-pdf';
    } else {
      iconElement.className = 'fas fa-file-alt';
    }
  }
  
  // Remove Selected File
  removeFileBtn.addEventListener('click', () => {
    fileInput.value = '';
    uploadPreview.classList.add('hidden');
  });
  
  // File Upload Button
  uploadBtn.addEventListener('click', async () => {
    if (!fileInput.files.length) {
      showNotification('Please select a file first', 'error');
      return;
    }
    
    try {
      showProcessing(true);
      
      // Generate a session ID if not already set
      if (!currentSessionId) {
        currentSessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
      }
      const file = fileInput.files[0];
      const formData = new FormData();
      formData.append('file', file);
      formData.append('sessionId', currentSessionId);
      
      // Add user ID if logged in
      if (currentUser) {
        formData.append('userId', currentUser.id);
      }
      
      const headers = {};
      const authToken = localStorage.getItem('authToken');
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }
      
      const response = await fetch('/api/upload', {
        method: 'POST',
        headers,
        body: formData
      });
      
      let data;
      try {
        // Try to parse the response as JSON
        const responseText = await response.text();
        
        try {
          // Attempt to parse the text as JSON
          data = JSON.parse(responseText);
        } catch (parseError) {
          console.error('JSON parsing error:', parseError, 'Response text:', responseText);
          
          // Create a fallback response object
          data = {
            error: 'Invalid server response',
            message: 'The server returned an invalid response that could not be processed.',
            responseText: responseText.substring(0, 100) + (responseText.length > 100 ? '...' : '')
          };
          throw new Error('Failed to parse server response as JSON');
        }
      } catch (textError) {
        console.error('Error reading response text:', textError);
        throw new Error('Failed to read server response');
      }
      
      // Check if the response indicates an error
      if (!response.ok || data.error) {
        throw new Error(data.message || data.error || 'Failed to process file');
      }
      
      // Process the successful response
      handleProcessedContent(data);
      
      showNotification('File processed successfully!', 'success');
      
      // Set document title if not already set
      if (documentTitle) {
        documentTitle.textContent = data.title || file.name || 'Content Summary';
      }
      
      // Switch to Summary tab
      document.querySelector('[data-tab="summary-tab"]').click();
    } catch (error) {
      console.error('Error uploading file:', error);
      showNotification(error.message || 'Error processing file', 'error');
    } finally {
      showProcessing(false);
    }
  });
  
  // ============= DIRECT TEXT INPUT =============
  
  // Process Text Button
  processTextBtn.addEventListener('click', async () => {
    const text = directTextInput.value.trim();
    const title = contentTitle ? contentTitle.value.trim() : 'Untitled Document';
    
    if (!text) {
      showNotification('Please enter some text first', 'error');
      return;
    }
    
    try {
      showProcessing(true);
      
      // Generate a session ID if not already set
      if (!currentSessionId) {
        currentSessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
      }
      
      // Include auth token if available
      const headers = {
        'Content-Type': 'application/json'
      };
      
      const authToken = localStorage.getItem('authToken');
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }
      
      const requestData = { 
        text,
        title,
        sessionId: currentSessionId
      };
      
      // Add user ID if logged in
      if (currentUser) {
        requestData.userId = currentUser.id;
      }
      
      const response = await fetch('/api/process-text', {
        method: 'POST',
        headers,
        body: JSON.stringify(requestData)
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || errorData.error || 'Failed to process text');
      }
      
      const data = await response.json();
      handleProcessedContent(data);
      
      // Set document title
      if (documentTitle) {
        documentTitle.textContent = title || 'Content Summary';
      }
      
      showNotification('Text processed successfully!', 'success');
      
      // Switch to Summary tab
      document.querySelector('[data-tab="summary-tab"]').click();
    } catch (error) {
      console.error('Error processing text:', error);
      showNotification(error.message || 'Error processing text', 'error');
    } finally {
      showProcessing(false);
    }
  });
  
  // ============= PROCESS CONTENT HANDLER =============
  
  // Handle Processed Content
  function handleProcessedContent(data) {
    try {
      // Store the current session ID for later use
      currentSessionId = data.sessionId || currentSessionId;
      
      // Store the processed content
      currentContent = data;
      
      // Update Summary Tab
      if (summaryContent) {
        if (data.summary) {
          summaryContent.innerHTML = `
            <div class="summary-section">
              <h3>Summary</h3>
              <div class="content-text">${data.summary}</div>
            </div>
          `;
        } else if (data.content && data.content.summary) {
          summaryContent.innerHTML = `
            <div class="summary-section">
              <h3>Summary</h3>
              <div class="content-text">${data.content.summary}</div>
            </div>
          `;
        } else {
          summaryContent.innerHTML = '<p class="no-content-message">No summary was generated. The content may be too short or not suitable for summarization.</p>';
        }
      }
      
      // Update Flashcards Tab
      if (data.flashcards) {
        flashcards = data.flashcards;
      } else if (data.content && data.content.flashcards) {
        flashcards = data.content.flashcards;
      } else {
        flashcards = [];
      }
      
      currentFlashcardIndex = 0;
      updateFlashcardsUI();
      
      // Update Quiz Tab
      if (data.quiz) {
        quizzes = data.quiz;
      } else if (data.content && data.content.quiz) {
        quizzes = data.content.quiz;
      } else {
        quizzes = [];
      }
      
      updateQuizUI();
      
      // Add a message to the chat
      addChatMessage('bot', 'I\'ve processed your content! You can now view the summary, flashcards, and quiz. How can I help you understand this material better?');
    } catch (error) {
      console.error('Error handling processed content:', error);
      showNotification('Error displaying processed content', 'error');
    }
  }
  
  // ============= FLASHCARDS =============
  
  // Update Flashcards UI
  function updateFlashcardsUI() {
    if (!flashcards || flashcards.length === 0) {
      flashcardsContainer.innerHTML = '<div class="no-content-message">No flashcards available. Upload a document or enter text first.</div>';
      prevCardBtn.disabled = true;
      nextCardBtn.disabled = true;
      cardCounter.textContent = '0/0';
      return;
    }
    
    // Enable navigation buttons
    prevCardBtn.disabled = flashcards.length <= 1;
    nextCardBtn.disabled = flashcards.length <= 1;
    
    // Reset to first card
    currentFlashcardIndex = 0;
    
    // Create flashcard elements
    flashcardsContainer.innerHTML = '';
    displayCurrentFlashcard();
  }
  
  // Display Current Flashcard
  function displayCurrentFlashcard() {
    if (!flashcards || flashcards.length === 0) return;
    
    const flashcard = flashcards[currentFlashcardIndex];
    cardCounter.textContent = `${currentFlashcardIndex + 1}/${flashcards.length}`;
    
    // Clone flashcard template
    const template = document.getElementById('flashcard-template');
    if (!template) {
      console.error('Flashcard template not found in the DOM');
      return;
    }
    
    const cardElement = template.cloneNode(true);
    cardElement.id = '';
    cardElement.classList.remove('hidden');
    
    // Set content
    const frontText = cardElement.querySelector('.flashcard-front .card-text');
    const backText = cardElement.querySelector('.flashcard-back .card-text');
    const tagsContainer = cardElement.querySelector('.tags-container');
    
    if (!frontText || !backText) {
      console.error('Card text elements not found in the template');
      return;
    }
    
    frontText.textContent = flashcard.question;
    backText.textContent = flashcard.answer;
    
    // Add tags if available
    if (tagsContainer && flashcard.tags && flashcard.tags.length) {
      tagsContainer.innerHTML = '';
      flashcard.tags.forEach(tag => {
        const tagElement = document.createElement('span');
        tagElement.className = 'tag';
        tagElement.textContent = tag;
        tagsContainer.appendChild(tagElement);
      });
    }
    
    // Add flip functionality
    const flipButtons = cardElement.querySelectorAll('.flip-btn');
    const cardInner = cardElement.querySelector('.flashcard-inner');
    
    if (flipButtons && cardInner) {
      flipButtons.forEach(button => {
        button.addEventListener('click', () => {
          cardInner.classList.toggle('flipped');
        });
      });
    }
    
    // Clear container and add card
    flashcardsContainer.innerHTML = '';
    flashcardsContainer.appendChild(cardElement);
  }
  
  // Flashcard Navigation
  prevCardBtn.addEventListener('click', () => {
    if (currentFlashcardIndex > 0) {
      currentFlashcardIndex--;
      displayCurrentFlashcard();
    }
  });
  
  nextCardBtn.addEventListener('click', () => {
    if (currentFlashcardIndex < flashcards.length - 1) {
      currentFlashcardIndex++;
      displayCurrentFlashcard();
    }
  });
  
  // ============= QUIZ =============
  
  let currentQuizIndex = 0;
  let selectedOption = null;
  let quizAnswered = false;
  let correctAnswers = 0;
  
  // Update Quiz UI
  function updateQuizUI() {
    if (!quizzes || quizzes.length === 0) {
      quizContainer.innerHTML = '<div class="no-content-message">No quiz available. Upload a document or enter text first.</div>';
      return;
    }
    
    // Reset quiz state
    currentQuizIndex = 0;
    correctAnswers = 0;
    
    // Show quiz content
    document.querySelector('.no-content-message')?.classList.add('hidden');
    quizContent.classList.remove('hidden');
    
    // Start quiz
    showQuizQuestion();
  }
  
  // Show Quiz Question
  function showQuizQuestion() {
    // Hide feedback and reset state
    quizFeedback.classList.add('hidden');
    quizAnswered = false;
    selectedOption = null;
    
    // Update buttons
    quizNextBtn.disabled = true;
    quizNextBtn.classList.remove('hidden');
    quizFinishBtn.classList.add('hidden');
    quizRestartBtn.classList.add('hidden');
    quizResults.classList.add('hidden');
    
    const quiz = quizzes[currentQuizIndex];
    
    // Set question
    quizQuestion.textContent = quiz.question;
    quizProgress.textContent = `Question ${currentQuizIndex + 1} of ${quizzes.length}`;
    
    // Create options
    quizOptions.innerHTML = '';
    quiz.options.forEach((option, index) => {
      const optionElement = document.createElement('div');
      optionElement.className = 'quiz-option';
      optionElement.textContent = option;
      optionElement.dataset.index = index;
      
      optionElement.addEventListener('click', () => {
        if (quizAnswered) return;
        
        // Remove selection from all options
        quizOptions.querySelectorAll('.quiz-option').forEach(opt => {
          opt.classList.remove('selected');
        });
        
        // Select this option
        optionElement.classList.add('selected');
        selectedOption = option;
        
        // Enable next/finish button
        quizNextBtn.disabled = false;
      });
      
      quizOptions.appendChild(optionElement);
    });
  }
  
  // Check Answer
  function checkAnswer() {
    if (!selectedOption) return;
    
    quizAnswered = true;
    const quiz = quizzes[currentQuizIndex];
    const correctOption = quiz.answer;
    const isCorrect = selectedOption === correctOption;
    
    // Show feedback
    quizFeedback.classList.remove('hidden');
    
    // Update feedback icons
    document.querySelector('.correct-icon').classList.toggle('hidden', !isCorrect);
    document.querySelector('.incorrect-icon').classList.toggle('hidden', isCorrect);
    
    // Show explanation
    quizExplanation.textContent = quiz.explanation || (isCorrect ? 'Correct! Well done.' : `Incorrect. The correct answer is: ${correctOption}`);
    
    // Update score
    if (isCorrect) {
      correctAnswers++;
    }
    
    // Mark options as correct/incorrect
    quizOptions.querySelectorAll('.quiz-option').forEach(option => {
      if (option.textContent === correctOption) {
        option.classList.add('correct');
      } else if (option.classList.contains('selected')) {
        option.classList.add('incorrect');
      }
    });
    
    // Update buttons for next or finish
    if (currentQuizIndex === quizzes.length - 1) {
      quizNextBtn.classList.add('hidden');
      quizFinishBtn.classList.remove('hidden');
    }
  }
  
  // Show Quiz Results
  function showQuizResults() {
    quizContent.querySelector('.quiz-header').classList.add('hidden');
    quizOptions.classList.add('hidden');
    quizFeedback.classList.add('hidden');
    quizResults.classList.remove('hidden');
    quizFinishBtn.classList.add('hidden');
    quizRestartBtn.classList.remove('hidden');
    
    // Calculate score
    const totalQuestions = quizzes.length;
    const percentage = Math.round((correctAnswers / totalQuestions) * 100);
    
    // Update score display
    quizScore.textContent = `${correctAnswers}/${totalQuestions}`;
    quizPercentage.textContent = `${percentage}%`;
    
    // Send score to chat
    addChatMessage('bot', `You've completed the quiz with a score of ${correctAnswers}/${totalQuestions} (${percentage}%)! Would you like to review any particular question?`);
  }
  
  // Quiz Navigation & Actions
  quizNextBtn.addEventListener('click', () => {
    if (!quizAnswered) {
      checkAnswer();
    } else {
      currentQuizIndex++;
      showQuizQuestion();
    }
  });
  
  quizFinishBtn.addEventListener('click', showQuizResults);
  
  quizRestartBtn.addEventListener('click', () => {
    currentQuizIndex = 0;
    correctAnswers = 0;
    
    // Show quiz question UI again
    quizContent.querySelector('.quiz-header').classList.remove('hidden');
    quizOptions.classList.remove('hidden');
    quizResults.classList.add('hidden');
    
    // Start quiz again
    showQuizQuestion();
  });
  
  // ============= CHAT =============
  
  // Send Chat Message
  function sendChatMessage() {
    const chatInput = document.getElementById('chat-input');
    const message = chatInput.value.trim();
    
    if (!message) return;
    
    // Clear input
    chatInput.value = '';
    
    // Add user message to chat
    addChatMessage('user', message);
    
    // Show typing indicator
    const typingIndicator = document.createElement('div');
    typingIndicator.className = 'chat-message bot-typing';
    typingIndicator.innerHTML = `
      <div class="avatar bot-avatar">
        <i class="fas fa-robot"></i>
      </div>
      <div class="message-content">
        <div class="typing-indicator">
          <span></span>
          <span></span>
          <span></span>
        </div>
      </div>
    `;
    chatMessages.appendChild(typingIndicator);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    
    // Process message with AI
    processChatMessage(message, typingIndicator);
  }
  
  // Process Chat Message with AI
  async function processChatMessage(message, typingIndicator) {
    try {
      // Generate a session ID if not already set
      if (!currentSessionId) {
        currentSessionId = Date.now().toString() + Math.random().toString(36).substring(2, 8);
      }
      
      const headers = {
        'Content-Type': 'application/json'
      };
      
      const authToken = localStorage.getItem('authToken');
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }
      
      const response = await fetch('/api/chatbot', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          message,
          sessionId: currentSessionId,
          context: currentContent ? {
            hasProcessedContent: true,
            contentType: currentContent.metadata?.contentType || 'unknown',
            title: documentTitle ? documentTitle.textContent : 'Untitled Document'
          } : {
            hasProcessedContent: false
          }
        })
      });
      
      // Remove typing indicator
      if (typingIndicator) {
        typingIndicator.remove();
      }
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.message || errorData.error || 'Failed to get response');
      }
      
      const data = await response.json();
      
      // Add bot response to chat
      addChatMessage('bot', data.reply || data.message || 'I\'m not sure how to respond to that.');
      
      // Check for any actions to perform
      if (data.actions) {
        handleChatActions(data.actions);
      }
    } catch (error) {
      console.error('Chat processing error:', error);
      
      // Remove typing indicator if it exists
      if (typingIndicator) {
        typingIndicator.remove();
      }
      
      // Add error message
      addChatMessage('bot', 'Sorry, I encountered an error while processing your message. Please try again.');
    }
  }
  
  // Handle Chat Actions
  function handleChatActions(actions) {
    if (!actions) return;
    
    if (actions.switchTab) {
      const tabButton = document.querySelector(`[data-tab="${actions.switchTab}"]`);
      if (tabButton) {
        tabButton.click();
      }
    }
    
    if (actions.showNotification) {
      showNotification(actions.showNotification.message, actions.showNotification.type || 'info');
    }
  }
  
  // Add Chat Message
  function addChatMessage(sender, text) {
    const messageElement = document.createElement('div');
    messageElement.className = `chat-message ${sender}-message`;
    
    const avatar = document.createElement('div');
    avatar.className = `avatar ${sender}-avatar`;
    
    if (sender === 'user') {
      avatar.innerHTML = '<i class="fas fa-user"></i>';
    } else {
      avatar.innerHTML = '<i class="fas fa-robot"></i>';
    }
    
    const messageContent = document.createElement('div');
    messageContent.className = 'message-content';
    messageContent.innerHTML = text;
    
    messageElement.appendChild(avatar);
    messageElement.appendChild(messageContent);
    
    chatMessages.appendChild(messageElement);
    chatMessages.scrollTop = chatMessages.scrollHeight;
  }
  
  // Add chat input event listeners
  if (document.getElementById('chat-input')) {
    document.getElementById('chat-input').addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        sendChatMessage();
      }
    });
  }
  
  if (document.getElementById('send-message')) {
    document.getElementById('send-message').addEventListener('click', sendChatMessage);
  }
  
  // ============= UTILITIES =============
  
  // Show Processing Indicator
  function showProcessing(show) {
    if (show) {
      processingIndicator.classList.remove('hidden');
    } else {
      processingIndicator.classList.add('hidden');
    }
  }
  
  // Show Notification
  function showNotification(message, type = 'success') {
    notificationMessage.textContent = message;
    
    // Update icon
    const iconElement = notification.querySelector('.notification-icon');
    if (iconElement) {
      iconElement.className = 'notification-icon ' + type;
      
      if (type === 'success') {
        iconElement.innerHTML = '<i class="fas fa-check-circle"></i>';
      } else {
        iconElement.innerHTML = '<i class="fas fa-exclamation-circle"></i>';
      }
    }
    
    // Show notification
    notification.classList.add('show');
    
    // Hide after 3 seconds
    setTimeout(() => {
      notification.classList.remove('show');
    }, 3000);
  }
  
  // Initial greeting message for chat
  addChatMessage('bot', 'Welcome to SplanAI! Upload a document or enter text to get started.');
  
  // ============= DOCUMENT MANAGEMENT & DOWNLOAD =============
  
  // Download PDF Button
  downloadPdfBtn.addEventListener('click', async () => {
    if (!currentContent || !currentContent.summary) {
      showNotification('No content available to download', 'error');
      return;
    }
    
    try {
      const headers = {};
      const authToken = localStorage.getItem('authToken');
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }
      
      const response = await fetch(`/api/download/pdf/${currentSessionId}`, {
        method: 'GET',
        headers
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate PDF');
      }
      
      // Create a blob from the PDF Stream
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      // Create a link and click it to start the download
      const a = document.createElement('a');
      a.href = url;
      const title = documentTitle ? documentTitle.textContent : 'summary';
      a.download = `${title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.pdf`;
      document.body.appendChild(a);
      a.click();
      
      // Clean up
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      showNotification('PDF downloaded successfully!', 'success');
    } catch (error) {
      console.error('Error downloading PDF:', error);
      showNotification(error.message || 'Error generating PDF', 'error');
    }
  });
  
  // Download Flashcards Button
  downloadFlashcardsBtn.addEventListener('click', async () => {
    if (!flashcards || flashcards.length === 0) {
      showNotification('No flashcards available to download', 'error');
      return;
    }
    
    try {
      const headers = {};
      const authToken = localStorage.getItem('authToken');
      if (authToken) {
        headers['Authorization'] = `Bearer ${authToken}`;
      }
      
      const response = await fetch(`/api/download/flashcards/${currentSessionId}`, {
        method: 'GET',
        headers
      });
      
      if (!response.ok) {
        throw new Error('Failed to generate CSV');
      }
      
      // Create a blob from the CSV Stream
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      // Create a link and click it to start the download
      const a = document.createElement('a');
      a.href = url;
      const title = documentTitle ? documentTitle.textContent : 'flashcards';
      a.download = `${title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_flashcards.csv`;
      document.body.appendChild(a);
      a.click();
      
      // Clean up
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      showNotification('Flashcards downloaded successfully!', 'success');
    } catch (error) {
      console.error('Error downloading flashcards:', error);
      showNotification(error.message || 'Error generating CSV', 'error');
    }
  });
  
  // Print Flashcards Button
  printFlashcardsBtn.addEventListener('click', () => {
    if (!flashcards || flashcards.length === 0) {
      showNotification('No flashcards available to print', 'error');
      return;
    }
    
    // Create a new window for printing
    const printWindow = window.open('', '_blank');
    
    // Generate print-friendly HTML
    let printContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Flashcards - ${documentTitle ? documentTitle.textContent : 'SplanAI'}</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; }
          .flashcard { 
            border: 1px solid #ccc; 
            border-radius: 5px; 
            padding: 15px; 
            margin-bottom: 20px; 
            page-break-inside: avoid; 
          }
          .question { 
            font-weight: bold; 
            margin-bottom: 10px; 
            font-size: 16px;
          }
          .answer { 
            border-top: 1px dashed #ccc; 
            margin-top: 10px; 
            padding-top: 10px; 
          }
          @media print {
            .no-print { display: none; }
            @page { margin: 0.5cm; }
          }
        </style>
      </head>
      <body>
        <div class="no-print" style="margin-bottom: 20px; text-align: right;">
          <button onclick="window.print()">Print Flashcards</button>
        </div>
        <h1>Flashcards - ${documentTitle ? documentTitle.textContent : 'SplanAI'}</h1>
    `;
    
    // Add each flashcard
    flashcards.forEach((card, index) => {
      printContent += `
        <div class="flashcard">
          <div class="question">Q${index + 1}: ${card.question}</div>
          <div class="answer">A: ${card.answer}</div>
        </div>
      `;
    });
    
    printContent += `
      </body>
      </html>
    `;
    
    // Write to the new window and trigger print
    printWindow.document.open();
    printWindow.document.write(printContent);
    printWindow.document.close();
  });
  
  // Print Quiz Button
  printQuizBtn.addEventListener('click', () => {
    if (!quizzes || quizzes.length === 0) {
      showNotification('No quiz available to print', 'error');
      return;
    }
    
    // Create a new window for printing
    const printWindow = window.open('', '_blank');
    
    // Generate print-friendly HTML
    let printContent = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Quiz - ${documentTitle ? documentTitle.textContent : 'SplanAI'}</title>
        <style>
          body { font-family: Arial, sans-serif; padding: 20px; }
          .question { 
            margin-bottom: 30px; 
            page-break-inside: avoid; 
          }
          .question-text { 
            font-weight: bold; 
            margin-bottom: 15px; 
            font-size: 16px;
          }
          .options { 
            margin-bottom: 10px;
          }
          .option {
            margin-bottom: 5px;
            padding: 5px;
          }
          .answer-key {
            margin-top: 40px;
            border-top: 2px solid #000;
            padding-top: 20px;
          }
          @media print {
            .no-print { display: none; }
            @page { margin: 0.5cm; }
            .answer-key { page-break-before: always; }
          }
        </style>
      </head>
      <body>
        <div class="no-print" style="margin-bottom: 20px; text-align: right;">
          <button onclick="window.print()">Print Quiz</button>
        </div>
        <h1>Quiz - ${documentTitle ? documentTitle.textContent : 'SplanAI'}</h1>
    `;
    
    // Add each question
    quizzes.forEach((quiz, index) => {
      printContent += `
        <div class="question">
          <div class="question-text">Q${index + 1}: ${quiz.question}</div>
          <div class="options">
      `;
      
      // Add each option
      quiz.options.forEach((option, optIndex) => {
        printContent += `
          <div class="option">
            ${String.fromCharCode(65 + optIndex)}. ${option}
          </div>
        `;
      });
      
      printContent += `
          </div>
        </div>
      `;
    });
    
    // Add answer key
    printContent += `
      <div class="answer-key">
        <h2>Answer Key</h2>
    `;
    
    quizzes.forEach((quiz, index) => {
      const correctOptionLetter = String.fromCharCode(65 + quiz.options.indexOf(quiz.answer));
      printContent += `
        <p>Q${index + 1}: ${correctOptionLetter} - ${quiz.explanation}</p>
      `;
    });
    
    printContent += `
        </div>
      </body>
      </html>
    `;
    
    // Write to the new window and trigger print
    printWindow.document.open();
    printWindow.document.write(printContent);
    printWindow.document.close();
  });
  
  // Share Content Button
  shareContentBtn.addEventListener('click', () => {
    if (!currentSessionId) {
      showNotification('No content available to share', 'error');
      return;
    }
    
    // Create share URL
    const shareLink = `${window.location.origin}/shared/${currentSessionId}`;
    shareUrl.value = shareLink;
    
    // Show share modal
    shareModal.classList.add('show');
  });
  
  // Copy Share URL Button
  copyShareUrlBtn.addEventListener('click', () => {
    shareUrl.select();
    document.execCommand('copy');
    
    // Change button icon temporarily
    const originalIcon = copyShareUrlBtn.innerHTML;
    copyShareUrlBtn.innerHTML = '<i class="fas fa-check"></i>';
    
    setTimeout(() => {
      copyShareUrlBtn.innerHTML = originalIcon;
    }, 2000);
    
    showNotification('Share link copied to clipboard!', 'success');
  });
  
  // Share Options
  shareOptions.forEach(option => {
    option.addEventListener('click', () => {
      const platform = option.getAttribute('data-platform');
      const shareLink = shareUrl.value;
      const title = documentTitle ? documentTitle.textContent : 'SplanAI Document';
      
      let url = '';
      
      switch (platform) {
        case 'email':
          url = `mailto:?subject=Check out this SplanAI document: ${title}&body=I wanted to share this document with you: ${shareLink}`;
          break;
        case 'twitter':
          url = `https://twitter.com/intent/tweet?text=Check out this document: ${title}&url=${encodeURIComponent(shareLink)}`;
          break;
        case 'facebook':
          url = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareLink)}`;
          break;
        case 'linkedin':
          url = `https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareLink)}`;
          break;
      }
      
      if (url) {
        window.open(url, '_blank');
      }
    });
  });
  
  // Save Content Button
  saveContentBtn.addEventListener('click', async () => {
    if (!currentContent || !currentSessionId) {
      showNotification('No content available to save', 'error');
      return;
    }
    
    if (!currentUser) {
      loginRequiredModal.classList.add('show');
      return;
    }
    
    try {
      const title = documentTitle ? documentTitle.textContent : 'Unnamed Document';
      
      const response = await fetch('/api/documents/save', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        },
        body: JSON.stringify({
          sessionId: currentSessionId,
          title: title,
          userId: currentUser.id
        })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to save document');
      }
      
      showNotification('Document saved successfully!', 'success');
    } catch (error) {
      console.error('Error saving document:', error);
      showNotification(error.message || 'Error saving document', 'error');
    }
  });
  
  // Load User Documents
  async function loadUserDocuments() {
    if (!currentUser) return;
    
    const documentsList = document.getElementById('documents-list');
    if (!documentsList) return;
    
    try {
      const response = await fetch('/api/documents/list', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to load documents');
      }
      
      const documents = await response.json();
      
      // Clear previous content
      documentsList.innerHTML = '';
      
      if (documents.length === 0) {
        documentsList.innerHTML = '<p class="no-content-message">You don\'t have any saved documents yet.</p>';
        return;
      }
      
      // Add each document to the list
      documents.forEach(doc => {
        const docItem = document.createElement('div');
        docItem.className = 'document-item';
        
        // Format date
        const createdDate = new Date(doc.createdAt);
        const formattedDate = createdDate.toLocaleDateString('en-US', {
          year: 'numeric',
          month: 'short',
          day: 'numeric'
        });
        
        docItem.innerHTML = `
          <div class="doc-title">${doc.title}</div>
          <div class="doc-date">${formattedDate}</div>
          <div class="doc-type">${doc.type || 'Document'}</div>
          <div class="doc-actions">
            <button class="icon-button open-doc" data-id="${doc.sessionId}" title="Open">
              <i class="fas fa-folder-open"></i>
            </button>
            <button class="icon-button download-doc" data-id="${doc.sessionId}" title="Download">
              <i class="fas fa-download"></i>
            </button>
            <button class="icon-button delete-doc" data-id="${doc._id}" title="Delete">
              <i class="fas fa-trash"></i>
            </button>
          </div>
        `;
        
        documentsList.appendChild(docItem);
      });
      
      // Add event listeners to document action buttons
      documentsList.querySelectorAll('.open-doc').forEach(button => {
        button.addEventListener('click', () => {
          const sessionId = button.getAttribute('data-id');
          loadDocument(sessionId);
        });
      });
      
      documentsList.querySelectorAll('.download-doc').forEach(button => {
        button.addEventListener('click', () => {
          const sessionId = button.getAttribute('data-id');
          downloadDocument(sessionId);
        });
      });
      
      documentsList.querySelectorAll('.delete-doc').forEach(button => {
        button.addEventListener('click', () => {
          const docId = button.getAttribute('data-id');
          deleteDocument(docId);
        });
      });
      
    } catch (error) {
      console.error('Error loading documents:', error);
      showNotification(error.message || 'Error loading documents', 'error');
    }
  }
  
  // Load a document
  async function loadDocument(sessionId) {
    try {
      const response = await fetch(`/api/documents/${sessionId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to load document');
      }
      
      const data = await response.json();
      
      // Load the document content
      handleProcessedContent(data);
      
      // Set the document title
      if (documentTitle) {
        documentTitle.textContent = data.title || 'Content Summary';
      }
      
      // Switch to Summary tab
      document.querySelector('[data-tab="summary-tab"]').click();
      
      showNotification('Document loaded successfully!', 'success');
    } catch (error) {
      console.error('Error loading document:', error);
      showNotification(error.message || 'Error loading document', 'error');
    }
  }
  
  // Download a document
  async function downloadDocument(sessionId) {
    try {
      const response = await fetch(`/api/download/pdf/${sessionId}`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to download document');
      }
      
      // Create a blob from the PDF Stream
      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      
      // Create a link and click it to start the download
      const a = document.createElement('a');
      a.href = url;
      a.download = `document_${sessionId}.pdf`;
      document.body.appendChild(a);
      a.click();
      
      // Clean up
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      
      showNotification('Document downloaded successfully!', 'success');
    } catch (error) {
      console.error('Error downloading document:', error);
      showNotification(error.message || 'Error downloading document', 'error');
    }
  }
  
  // Delete a document
  async function deleteDocument(docId) {
    if (!confirm('Are you sure you want to delete this document?')) {
      return;
    }
    
    try {
      const response = await fetch(`/api/documents/${docId}`, {
        method: 'DELETE',
        headers: {
          'Authorization': `Bearer ${localStorage.getItem('authToken')}`
        }
      });
      
      if (!response.ok) {
        throw new Error('Failed to delete document');
      }
      
      // Reload the documents list
      loadUserDocuments();
      
      showNotification('Document deleted successfully!', 'success');
    } catch (error) {
      console.error('Error deleting document:', error);
      showNotification(error.message || 'Error deleting document', 'error');
    }
  }
  
  // Generate Flashcards Button
  const generateFlashcardsBtn = document.createElement('button');
  generateFlashcardsBtn.className = 'primary-btn';
  generateFlashcardsBtn.innerHTML = '<i class="fas fa-layer-group"></i> Generate Flashcards';
  generateFlashcardsBtn.addEventListener('click', generateFlashcards);
  
  // Generate Quiz Button
  const generateQuizBtn = document.createElement('button');
  generateQuizBtn.className = 'primary-btn';
  generateQuizBtn.innerHTML = '<i class="fas fa-question-circle"></i> Generate Quiz';
  generateQuizBtn.addEventListener('click', generateQuiz);
  
  // Add buttons to the summary tab
  if (summaryContent) {
    const actionButtons = document.createElement('div');
    actionButtons.className = 'action-buttons';
    actionButtons.appendChild(generateFlashcardsBtn);
    actionButtons.appendChild(generateQuizBtn);
    
    // Insert after summary content
    summaryContent.parentNode.insertBefore(actionButtons, summaryContent.nextSibling);
  }
  
  // Generate Flashcards Function
  async function generateFlashcards() {
    if (!currentSessionId) {
      showNotification('Please upload a document or enter text first', 'error');
      return;
    }
    
    try {
      showProcessing(true);
      
      // Call the API to generate flashcards
      const response = await fetch('/api/generate-flashcards', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sessionId: currentSessionId })
      });
      
      // Handle response with better error handling
      let data;
      try {
        // Get response as text first
        const responseText = await response.text();
        
        try {
          // Try to parse as JSON
          data = JSON.parse(responseText);
        } catch (parseError) {
          console.error('JSON parsing error:', parseError);
          console.log('Raw response:', responseText);
          throw new Error('Failed to parse server response');
        }
      } catch (textError) {
        console.error('Error reading response:', textError);
        throw new Error('Failed to read server response');
      }
      
      if (!response.ok) {
        throw new Error(data.message || data.error || 'Failed to generate flashcards');
      }
      
      // Update flashcards
      flashcards = data.flashcards || [];
      currentFlashcardIndex = 0;
      updateFlashcardsUI();
      
      // Show notification
      showNotification('Flashcards generated successfully!', 'success');
      
      // Switch to Flashcards tab
      document.querySelector('[data-tab="flashcards-tab"]').click();
    } catch (error) {
      console.error('Error generating flashcards:', error);
      showNotification(error.message || 'Error generating flashcards', 'error');
    } finally {
      showProcessing(false);
    }
  }
  
  // Generate Quiz Function
  async function generateQuiz() {
    if (!currentSessionId) {
      showNotification('Please upload a document or enter text first', 'error');
      return;
    }
    
    try {
      showProcessing(true);
      
      // Call the API to generate quiz
      const response = await fetch('/api/generate-quiz', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ sessionId: currentSessionId })
      });
      
      // Handle response with better error handling
      let data;
      try {
        // Get response as text first
        const responseText = await response.text();
        
        try {
          // Try to parse as JSON
          data = JSON.parse(responseText);
        } catch (parseError) {
          console.error('JSON parsing error:', parseError);
          console.log('Raw response:', responseText);
          throw new Error('Failed to parse server response');
        }
      } catch (textError) {
        console.error('Error reading response:', textError);
        throw new Error('Failed to read server response');
      }
      
      if (!response.ok) {
        throw new Error(data.message || data.error || 'Failed to generate quiz');
      }
      
      // Update quiz
      quizzes = data.quiz || [];
      currentQuizIndex = 0;
      correctAnswers = 0;
      updateQuizUI();
      
      // Show notification
      showNotification('Quiz generated successfully!', 'success');
      
      // Switch to Quiz tab
      document.querySelector('[data-tab="quiz-tab"]').click();
    } catch (error) {
      console.error('Error generating quiz:', error);
      showNotification(error.message || 'Error generating quiz', 'error');
    } finally {
      showProcessing(false);
    }
  }
});