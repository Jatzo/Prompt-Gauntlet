// The live feed. Every value from the server is set with textContent, never parsed as HTML.
"use strict";

const MAX_ROWS = 2000;
const rows = document.getElementById("rows");
const scroller = document.getElementById("scroller");
const end = document.getElementById("end");
const empty = document.getElementById("empty");
const dropped = document.getElementById("dropped");
const jump = document.getElementById("jump");
const status = document.getElementById("status");
const eventCount = document.getElementById("event-count");
const anomalyCount = document.getElementById("anomaly-count");
const anomalyWrap = document.getElementById("anomaly-wrap");
const eventWord = document.getElementById("event-word");
const anomalyWord = document.getElementById("anomaly-word");

const STATES = {
  connecting: ["Connecting", "Connecting to the run's database."],
  waiting: [
    "Waiting for the database",
    "No run database yet. Events appear here once a cycle starts: python -m arena.cli run-cycle.",
  ],
  // "Connected", not "Live": the arena badge says whether a cycle ran live or simulated.
  live: ["Connected", "Connected. No events yet."],
  reconnecting: ["Reconnecting", "Lost the connection. Retrying."],
};

let events = 0;
let anomalies = 0;
let removed = 0;
let unseen = 0;
let following = true;
let pending = document.createDocumentFragment();
let scheduled = false;

function setStatus(state) {
  const [label, hint] = STATES[state] || STATES.connecting;
  status.dataset.state = state;
  status.textContent = label;
  empty.textContent = hint;
}

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function clock(iso) {
  const time = new Date(iso);
  return Number.isNaN(time.getTime())
    ? ""
    : time.toLocaleTimeString("en-GB", { hour12: false });
}

function outcome(event, anomaly) {
  const td = document.createElement("td");
  const words = (event.kind || "event").replaceAll("_", " ");
  if (anomaly) {
    const flag = document.createElement("strong");
    flag.className = "flag";
    flag.textContent = "Anomaly";
    td.append(flag, " ", words);
  } else if (event.outcome) {
    td.textContent = event.outcome;
  } else {
    td.textContent = words;
    td.className = "quiet";
  }
  return td;
}

function row(event) {
  const anomaly = event.severity === "anomaly";
  const tr = document.createElement("tr");
  tr.className = anomaly ? "anomaly fresh" : "fresh";
  // For the dashboard's agent filter (dashboard.js); a role is an identifier or empty.
  tr.dataset.role = event.role || "";
  const time = cell(clock(event.time), "num");
  time.title = event.time || "";
  const tool = cell(event.tool || "");
  if (event.step) tool.title = `step ${event.step}`;
  tr.append(
    time,
    cell(event.cycle == null ? "" : String(event.cycle), "num"),
    cell(event.role || ""),
    tool,
    outcome(event, anomaly),
  );
  events += 1;
  if (anomaly) anomalies += 1;
  return tr;
}

function flush() {
  scheduled = false;
  const added = pending.childElementCount;
  rows.append(pending);
  pending = document.createDocumentFragment();
  while (rows.childElementCount > MAX_ROWS) {
    rows.firstElementChild.remove();
    removed += 1;
  }
  if (removed) {
    dropped.hidden = false;
    dropped.textContent = `Showing the latest ${MAX_ROWS.toLocaleString("en-GB")} events. ${removed.toLocaleString("en-GB")} older ones have left the page.`;
  }
  empty.hidden = events > 0;
  eventCount.textContent = events.toLocaleString("en-GB");
  anomalyCount.textContent = anomalies.toLocaleString("en-GB");
  eventWord.textContent = events === 1 ? "event" : "events";
  anomalyWord.textContent = anomalies === 1 ? "anomaly" : "anomalies";
  anomalyWrap.toggleAttribute("data-some", anomalies > 0);
  if (following) {
    end.scrollIntoView({ block: "end" });
  } else if (added) {
    unseen += added;
    jump.hidden = false;
    jump.textContent = `${unseen.toLocaleString("en-GB")} new, jump to latest`;
  }
}

function queue(tr) {
  pending.append(tr);
  if (!scheduled) {
    scheduled = true;
    requestAnimationFrame(flush);
  }
}

new IntersectionObserver(
  ([entry]) => {
    following = entry.isIntersecting;
    if (following) {
      unseen = 0;
      jump.hidden = true;
    }
  },
  { root: scroller },
).observe(end);

jump.addEventListener("click", () => end.scrollIntoView({ block: "end" }));

function clear() {
  rows.replaceChildren();
  pending = document.createDocumentFragment();
  events = anomalies = removed = unseen = 0;
  dropped.hidden = true;
  jump.hidden = true;
  flush();
}

const source = new EventSource("/events");
source.addEventListener("status", (message) => {
  const state = JSON.parse(message.data).state;
  // A new run database replaced the old one, and its events start again from the first.
  if (state === "reset") clear();
  else setStatus(state);
  document.dispatchEvent(new CustomEvent("feed:status", { detail: state }));
});
source.addEventListener("message", (message) => {
  queue(row(JSON.parse(message.data)));
  // The arena asks for finished cycles whenever something happens in the run.
  document.dispatchEvent(new CustomEvent("feed:event"));
});
source.addEventListener("error", () => setStatus("reconnecting"));
