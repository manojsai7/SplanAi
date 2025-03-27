const messagesDiv = document.getElementById('messages');
let contentId = null;

// Page Navigation
document.querySelectorAll('nav button').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
    document.getElementById(btn.dataset.page).classList.add('active');
  });
});

// Theme Toggle
document.getElementById('theme-toggle').addEventListener('click', () => {
  document.body.classList.toggle('dark');
  document.getElementById('theme-toggle').textContent = document.body.classList.contains('dark') ? '☀️' : '🌙';
});

// Mouse Trail
document.addEventListener('mousemove', (e) => {
  const trail = document.createElement('div');
  trail.className = 'trail';
  trail.style.left = e.pageX + 'px';
  trail.style.top = e.pageY + 'px';
  document.body.appendChild(trail);
});

// Upload File
document.getElementById('upload-btn').addEventListener('click', async () => {
  const file = document.getElementById('file-input').files[0];
  if (!file) return displayMessage('Bot', 'No file? Come on, give me something to work with! 😜');
  const formData = new FormData();
  formData.append('file', file);
  try {
    const res = await fetch('/upload', { method: 'POST', body: formData });
    const data = await res.json();
    contentId = data.id;
    displayMessage('Bot', 'File processed! Ready to rock your study game! 🚀');
  } catch (e) {
    displayMessage('Bot', 'Oops, something crashed. Maybe it’s not meant to be... yet! 😅');
  }
});

// Show Flashcards
document.getElementById('flashcards-btn').addEventListener('click', async () => {
  if (!contentId) return displayMessage('Bot', 'Upload something first, genius! 😏');
  const res = await fetch('/content');
  const data = await res.json();
  data.flashcards.forEach(f => displayMessage('Bot', `Q: ${f.question} | A: ${f.answer}`));
});

// Show Summary
document.getElementById('summary-btn').addEventListener('click', async () => {
  if (!contentId) return displayMessage('Bot', 'No file, no summary. Simple math! 😛');
  const res = await fetch('/content');
  const data = await res.json();
  displayMessage('Bot', `Summary: ${data.summary}`);
});

// Quiz (Simple Version)
document.getElementById('quiz-btn').addEventListener('click', async () => {
  if (!contentId) return displayMessage('Bot', 'Quiz time? Upload a file first! 😜');
  const res = await fetch('/content');
  const data = await res.json();
  let index = 0;
  messagesDiv.innerHTML = '';
  function nextQuestion() {
    if (index >= data.flashcards.length) {
      displayMessage('Bot', 'Quiz done! You’re a star! 🌟');
      return;
    }
    const f = data.flashcards[index];
    displayMessage('Bot', `Question: ${f.question}`);
    const btn = document.createElement('button');
    btn.textContent = 'Show Answer';
    btn.onclick = () => {
      displayMessage('Bot', `Answer: ${f.answer}`);
      index++;
      setTimeout(nextQuestion, 500);
    };
    messagesDiv.appendChild(btn);
  }
  nextQuestion();
});

// Display Message
function displayMessage(sender, text) {
  const msg = document.createElement('div');
  msg.className = `message ${sender === 'Bot' ? 'bot-message' : ''}`;
  msg.textContent = `${sender}: ${text}`;
  messagesDiv.appendChild(msg);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}

// Initial Greeting
displayMessage('Bot', 'Hey there! Upload your notes and let’s launch your learning into orbit! 🚀');