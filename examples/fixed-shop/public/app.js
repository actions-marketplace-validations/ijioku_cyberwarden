// DEMO ONLY: the fixed browser code. No secrets here: the server holds them.

// Show a customer review on the product page
function showReview(review) {
  // Make the review's box
  const div = document.createElement('div');
  // Make the author line
  const author = document.createElement('b');
  // textContent shows text as text, so a <script> in a review is harmless
  author.textContent = review.author;
  // Make the review text
  const text = document.createElement('p');
  // Again, plain text only
  text.textContent = review.text;
  // Put the pieces together
  div.append(author, text);
  // Add it to the reviews list
  document.getElementById('reviews').append(div);
}

// After login, send the visitor on
function afterLogin() {
  // Read the address bar's ?next= value
  const next = new URLSearchParams(window.location.search).get('next') || '/';
  // Only follow local paths, never other websites
  if (next.startsWith('/') && !next.startsWith('//')) window.location.assign(next);
}

// Make both functions available to the page
window.shop = { showReview, afterLogin };
