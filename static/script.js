/**
 * script.js
 * Polls GET /api/events every 15 seconds and displays
 * the latest formatted GitHub events in the <ul id="event-list">.
 */

const EVENTS_ENDPOINT = "/api/events";
const POLL_INTERVAL_MS = 15000; // 15 seconds

// Fetch events and render them into the <ul>
async function fetchAndRenderEvents() {
  try {
    const response = await fetch(EVENTS_ENDPOINT);
    if (!response.ok) {
      console.error("Error fetching events:", response.status, response.statusText);
      return;
    }
    const eventsArray = await response.json(); // array of strings
    const ul = document.getElementById("event-list");
    ul.innerHTML = ""; // clear old items

    eventsArray.forEach((formattedMsg) => {
      const li = document.createElement("li");
      li.textContent = formattedMsg;
      ul.appendChild(li);
    });
  } catch (err) {
    console.error("Failed to fetch events:", err);
  }
}

// Run once immediately, then every 15 seconds
fetchAndRenderEvents();
setInterval(fetchAndRenderEvents, POLL_INTERVAL_MS);