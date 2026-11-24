// CyberWarden demo page: theme switch and the one-time scanner beam.
// Kept in its own file so the page's security policy can block all inline scripts.

// Find the three theme buttons
const themeButtons = document.querySelectorAll(".theme button");
// Apply a theme choice and highlight its button
function applyTheme(choice) {
  // "system" lets the device decide, so remove any forced theme
  if (choice === "system") document.documentElement.removeAttribute("data-theme");
  // Dark or Light forces that theme
  else document.documentElement.setAttribute("data-theme", choice);
  // Mark which button is selected
  themeButtons.forEach(b => b.setAttribute("aria-pressed", String(b.dataset.set === choice)));
}
// Start with the visitor's last choice, if the browser kept it
let savedTheme = "system";
// Reading storage can fail in private windows, so guard it
try { savedTheme = localStorage.getItem("cw-theme") || "system"; } catch (e) {}
// Apply the starting theme
applyTheme(savedTheme);
// Switch and remember the theme when a button is clicked
themeButtons.forEach(b => b.addEventListener("click", () => {
  // Change the theme
  applyTheme(b.dataset.set);
  // Remember it for next time, if allowed
  try { localStorage.setItem("cw-theme", b.dataset.set); } catch (e) {}
}));

// The before/after area the beam sweeps over
const scanBox = document.getElementById("scan");
// Skip all motion for people who ask for less
const calm = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
// Counts a score up from 0 to its real value
function countUp(el) {
  // The real score
  const target = Number(el.dataset.count);
  // When counting started
  const start = performance.now();
  // One frame of the count
  function frame(now) {
    // How far through the 700 ms count we are (0 to 1)
    const t = Math.min(1, (now - start) / 700);
    // Show the number at that point, slowing down at the end
    el.textContent = Math.round(target * (1 - Math.pow(1 - t, 3)));
    // Keep going until the real score is shown
    if (t < 1) requestAnimationFrame(frame);
  }
  // Start counting
  requestAnimationFrame(frame);
}
// Runs the beam once and lights each report card as the beam reaches it
function runScan() {
  // Start the beam moving
  scanBox.classList.add("sweeping");
  // Top of the area on screen
  const boxTop = scanBox.getBoundingClientRect().top;
  // Height of the area
  const boxHeight = scanBox.offsetHeight;
  // For each report card
  scanBox.querySelectorAll(".report").forEach(card => {
    // How far down the area the card's grade sits (0 to 1)
    const pos = (card.querySelector(".grade").getBoundingClientRect().top - boxTop) / boxHeight;
    // The beam takes 1.8 seconds, so reach this card at its share of that time
    const delay = Math.max(0, pos) * 1800;
    // When the beam arrives
    setTimeout(() => {
      // Glow the card
      card.classList.add("lit");
      // Count its score up
      countUp(card.querySelector("[data-count]"));
      // Let the glow fade after a moment
      setTimeout(() => card.classList.remove("lit"), 1000);
    }, delay);
  });
}
// Only animate when motion is welcome and the browser supports watching visibility
if (scanBox && !calm && "IntersectionObserver" in window) {
  // Watch for the cards coming into view
  const watcher = new IntersectionObserver(entries => {
    // Wait until they're on screen
    if (!entries[0].isIntersecting) return;
    // Run the scan once
    runScan();
    // Stop watching
    watcher.disconnect();
  }, { threshold: 0.3 });
  // Start watching
  watcher.observe(scanBox);
}
