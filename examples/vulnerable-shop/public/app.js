// DEMO ONLY: deliberately insecure browser code for the vulnerable shop.

// MISTAKE: a secret API key in a file every visitor downloads
const apiKey = 'demo1234secret5678key9012abcd';

// Show a customer review on the product page
function showReview(review) {
  // Find the reviews box
  const box = document.getElementById('reviews');
  // MISTAKE: the review text goes into the page as HTML, so a review can contain a <script> (XSS)
  box.innerHTML += `<div class="review"><b>${review.author}</b><p>${review.text}</p></div>`;
}

// After login, send the visitor on
function afterLogin() {
  // Read the address bar's ?next= value
  const params = new URLSearchParams(window.location.search);
  // MISTAKE: go wherever ?next= says, even another website (open redirect)
  window.location.href = params.get('next');
}

// Make both functions available to the page
window.shop = { showReview, afterLogin, apiKey };
