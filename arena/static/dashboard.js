// The dashboard's other panels: attack counts with filters, the Judge's scores, memory and the
// briefing, and the operator's controls (PLAN section 15). Data comes from /dashboard/* and
// /arena/cycles. Every value is set with textContent or setAttribute, never as markup: the memory
// panel carries agent text, which may quote an attack.
// Its own scope: app.js and arena.js share the page and declare names of their own.
(() => {
  "use strict";

  const POLL_MS = 5000;
  const NS = "http://www.w3.org/2000/svg";
  const RUN = new URLSearchParams(location.search).get("run") || "";
  const runQuery = RUN ? `?run=${encodeURIComponent(RUN)}` : "";
  const $ = (id) => document.getElementById(id);
  const OUTCOME_NAMES = {
    through: "got past",
    caught: "caught",
    no_effect: "no effect",
    refused: "refused by the model",
  };

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  function svgEl(tag, attrs) {
    const node = document.createElementNS(NS, tag);
    for (const [key, value] of Object.entries(attrs || {})) node.setAttribute(key, String(value));
    return node;
  }

  function clear(node) {
    while (node.firstChild) node.removeChild(node.firstChild);
  }

  function pct(value) {
    return typeof value === "number" ? `${(value * 100).toFixed(1)}%` : "-";
  }

  function when(iso) {
    const date = new Date(iso);
    if (Number.isNaN(date.getTime())) return "";
    const parts = { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" };
    return date.toLocaleString("en-GB", parts);
  }

  function signed(value) {
    return typeof value === "number" ? `${value >= 0 ? "+" : ""}${value.toFixed(3)}` : "-";
  }

  async function getJson(url) {
    const response = await fetch(url, { cache: "no-store" });
    if (!response.ok) throw new Error(`${url} answered ${response.status}`);
    return response.json();
  }

  // Run picker ----------------------------------------------------------------------------------

  const runPick = $("run-pick");
  runPick.addEventListener("change", () => {
    const params = new URLSearchParams(location.search);
    if (runPick.value) params.set("run", runPick.value);
    else params.delete("run");
    location.search = params.toString();
  });

  function showRuns(runs) {
    const wanted = ["", ...runs];
    const have = [...runPick.options].map((option) => option.value);
    if (wanted.join("\n") === have.join("\n")) return;
    while (runPick.options.length > 1) runPick.remove(1);
    for (const run of runs) runPick.add(new Option(run, run));
    runPick.value = runs.includes(RUN) ? RUN : "";
  }

  // Attacks this run: counts by technique and outcome, with filters -----------------------------

  const cycles = new Map();
  let after = 0;
  const techniqueFilter = $("filter-technique");
  const outcomeFilter = $("filter-outcome");
  const agentFilter = $("filter-agent");

  function outcome(attack) {
    if (attack.refused) return "refused";
    if (!attack.valid) return "no_effect";
    return attack.evaded ? "through" : "caught";
  }

  function showTally() {
    const counts = new Map();
    for (const cycle of cycles.values()) {
      for (const attack of cycle.attacks || []) {
        const row = counts.get(attack.technique) || { through: 0, caught: 0, no_effect: 0, refused: 0 };
        row[outcome(attack)] += 1;
        counts.set(attack.technique, row);
      }
    }
    const techniques = [...counts.keys()].sort();
    const chosen = techniqueFilter.value;
    while (techniqueFilter.options.length > 1) techniqueFilter.remove(1);
    for (const technique of techniques) techniqueFilter.add(new Option(technique, technique));
    techniqueFilter.value = techniques.includes(chosen) ? chosen : "";

    const wrap = $("tally-wrap");
    wrap.querySelector("table")?.remove();
    $("tally-empty").hidden = techniques.length > 0;
    if (!techniques.length) return;

    const columns = outcomeFilter.value ? [outcomeFilter.value] : Object.keys(OUTCOME_NAMES);
    const shown = techniqueFilter.value ? [techniqueFilter.value] : techniques;
    const table = el("table", undefined, "tally");
    const head = table.createTHead().insertRow();
    head.append(el("th", "Technique"));
    for (const column of columns) {
      const th = el("th", OUTCOME_NAMES[column]);
      th.dataset.outcome = column;
      head.append(th);
    }
    const body = table.createTBody();
    for (const technique of shown) {
      const row = body.insertRow();
      const name = el("th", technique);
      name.scope = "row";
      row.append(name);
      for (const column of columns) {
        const count = counts.get(technique)[column];
        const td = el("td", count);
        td.dataset.outcome = column;
        if (!count) td.dataset.zero = "";
        row.append(td);
      }
    }
    wrap.append(table);
  }

  async function pollCycles() {
    try {
      const run = RUN ? `&run=${encodeURIComponent(RUN)}` : "";
      const page = await getJson(`/arena/cycles?after=${after}${run}`);
      for (const cycle of page.cycles) if (!cycle.unreadable) cycles.set(cycle.cycle, cycle);
      after = page.next_after;
      // Rebuilding the filter's options closes it if it is open, so only when there is news.
      if (page.cycles.length) showTally();
    } catch {
      // The status line in the bar already says when the run cannot be reached.
    }
  }

  function filterEvents() {
    const role = agentFilter.value;
    for (const row of document.querySelectorAll("#rows tr")) {
      row.classList.toggle("filtered-out", Boolean(role) && row.dataset.role !== role);
    }
  }

  techniqueFilter.addEventListener("change", showTally);
  outcomeFilter.addEventListener("change", showTally);
  agentFilter.addEventListener("change", filterEvents);
  new MutationObserver(filterEvents).observe($("rows"), { childList: true });

  // Scores ---------------------------------------------------------------------------------------

  const PLOT = { width: 320, height: 150, left: 34, right: 10, top: 10, bottom: 22 };

  function placeholder(svg, width, height, words) {
    const note = svgEl("text", { x: width / 2, y: height / 2, "text-anchor": "middle" });
    note.textContent = words;
    svg.append(note);
  }

  function axes(svg, low, high, ticks) {
    const { width, height, left, right, top, bottom } = PLOT;
    const y = (value) => top + (1 - (value - low) / (high - low)) * (height - top - bottom);
    for (const tick of ticks) {
      svg.append(svgEl("line", { class: "grid", x1: left, x2: width - right, y1: y(tick), y2: y(tick) }));
      const label = svgEl("text", { x: left - 6, y: y(tick) + 4, "text-anchor": "end" });
      label.textContent = pct(tick).replace(".0%", "%");
      svg.append(label);
    }
    return y;
  }

  function series(svg, points, key) {
    clear(svg);
    const { width, height, left, right, bottom } = PLOT;
    const y = axes(svg, 0, 1, [0, 0.5, 1]);
    const usable = points.filter((point) => point[key]);
    if (!usable.length) {
      placeholder(svg, width, height, "Not measured yet");
      return null;
    }
    const span = Math.max(usable.length - 1, 1);
    const x = (index) => left + (index / span) * (width - left - right);
    const upper = usable.map((point, i) => `${x(i)},${y(point[key].ci_high)}`);
    const lower = usable.map((point, i) => `${x(i)},${y(point[key].ci_low)}`).reverse();
    svg.append(svgEl("polygon", { class: "band", points: [...upper, ...lower].join(" ") }));
    const line = svgEl("polyline", {
      class: "line",
      points: usable.map((point, i) => `${x(i)},${y(point[key].value)}`).join(" "),
      pathLength: 1,
      "stroke-dasharray": 1,
    });
    svg.append(line);
    // The line draws itself in; the caller only redraws when a new cycle arrived.
    if (document.documentElement.dataset.motion === "on") {
      line.animate([{ strokeDashoffset: 1 }, { strokeDashoffset: 0 }], {
        duration: 900,
        easing: "cubic-bezier(0.3, 0, 0.2, 1)",
      });
    }
    usable.forEach((point, i) => {
      // A kept cycle is a square as well as amber, so the shape says it without the colour.
      const cx = x(i);
      const cy = y(point[key].value);
      const kept = point.decision === "keep";
      const dot = kept
        ? svgEl("rect", { class: "point kept", x: cx - 4, y: cy - 4, width: 8, height: 8 })
        : svgEl("circle", { class: "point", cx, cy, r: 3 });
      const tip = svgEl("title");
      const standing = point.standing ? `, ${point.standing.replace("_", " ")}` : "";
      const interval = `${pct(point[key].ci_low)} to ${pct(point[key].ci_high)}`;
      tip.textContent = `Cycle ${point.cycle}: ${pct(point[key].value)} (${interval}), ${point.decision}${standing}`;
      dot.append(tip);
      svg.append(dot);
    });
    for (const [index, anchor] of [[0, "start"], [usable.length - 1, "end"]]) {
      const label = svgEl("text", { x: x(index), y: height - bottom + 15, "text-anchor": anchor });
      label.textContent = `cycle ${usable[index].cycle}`;
      svg.append(label);
    }
    return usable[usable.length - 1][key];
  }

  function categories(svg, point, cap) {
    clear(svg);
    const { width, height, left, right, bottom } = PLOT;
    const entries = Object.entries((point && point.category_fpr) || {}).sort();
    if (!entries.length) {
      placeholder(svg, width, height, "Not measured yet");
      return;
    }
    const high = Math.max(cap * 2, ...entries.map(([, value]) => value));
    const y = axes(svg, 0, high, [0, cap, high]);
    const step = (width - left - right) / entries.length;
    entries.forEach(([name, value], i) => {
      const bar = svgEl("rect", {
        class: "fpr-bar",
        // At most 36 wide, so one category does not fill the chart.
        x: left + i * step + (step - Math.min(step * 0.6, 36)) / 2,
        width: Math.min(step * 0.6, 36),
        y: y(value),
        height: Math.max(y(0) - y(value), 1),
      });
      if (value > cap) bar.setAttribute("data-over", "");
      const tip = svgEl("title");
      tip.textContent = `${name}: ${pct(value)}`;
      bar.append(tip);
      svg.append(bar);
      const label = svgEl("text", {
        x: left + i * step + step / 2,
        y: height - bottom + 15,
        "text-anchor": "middle",
      });
      label.textContent = name.length > 9 ? `${name.slice(0, 8)}.` : name;
      svg.append(label);
    });
    svg.append(svgEl("line", { class: "cap", x1: left, x2: width - right, y1: y(cap), y2: y(cap) }));
  }

  let drawnPoints = 0;

  function showScores(data) {
    const points = data.points || [];
    $("scores-empty").hidden = points.length > 0;
    $("charts").hidden = points.length === 0;
    const badge = $("scores-badge");
    const simulated = points.some((point) => point.backend === "simulated");
    badge.hidden = !points.length;
    badge.textContent = simulated ? "simulated Judge" : "live Judge";
    badge.dataset.kind = simulated ? "simulated" : "live";
    // Redraw only when a cycle was added, so the lines draw in once per cycle, not every poll.
    if (!points.length || points.length === drawnPoints) return;
    drawnPoints = points.length;
    for (const [key, id] of [["asr", "asr-now"], ["utility", "utility-now"], ["tpr", "tpr-now"]]) {
      const now = series($(`plot-${key}`), points, key);
      $(id).textContent = now ? `${pct(now.value)} now` : "";
    }
    const latest = points[points.length - 1];
    const cap = data.limits.category_fpr_cap;
    categories($("plot-fpr"), latest, cap);
    $("fpr-now").textContent = `cycle ${latest.cycle}, cap ${pct(cap)}`;
  }

  // Memory and briefing --------------------------------------------------------------------------

  function list(id, emptyId, items, render) {
    const node = $(id);
    clear(node);
    $(emptyId).hidden = items.length > 0;
    for (const item of items) node.append(render(item));
  }

  function calibration(svg, pairs) {
    clear(svg);
    const width = 320;
    const height = 200;
    const pad = 30;
    $("calibration-count").textContent = pairs.length ? `${pairs.length} pairs` : "";
    if (!pairs.length) {
      placeholder(svg, width, height, "No predictions with outcomes yet");
      return;
    }
    const reach = Math.max(
      0.05,
      ...pairs.flatMap((pair) => [Math.abs(pair.expected), Math.abs(pair.actual)]),
    );
    const x = (value) => pad + ((value + reach) / (2 * reach)) * (width - 2 * pad);
    const y = (value) => height - pad - ((value + reach) / (2 * reach)) * (height - 2 * pad);
    svg.append(svgEl("line", { class: "grid", x1: x(-reach), x2: x(reach), y1: y(0), y2: y(0) }));
    svg.append(svgEl("line", { class: "grid", x1: x(0), x2: x(0), y1: y(-reach), y2: y(reach) }));
    svg.append(
      svgEl("line", { class: "diagonal", x1: x(-reach), y1: y(-reach), x2: x(reach), y2: y(reach) }),
    );
    for (const pair of pairs) {
      const dot = svgEl("circle", { class: "point", cx: x(pair.expected), cy: y(pair.actual), r: 3 });
      const tip = svgEl("title");
      tip.textContent = `Cycle ${pair.cycle}: predicted ${signed(pair.expected)}, actual ${signed(pair.actual)}`;
      dot.append(tip);
      svg.append(dot);
    }
    const xLabel = svgEl("text", { x: width - pad, y: height - 8, "text-anchor": "end" });
    xLabel.textContent = "predicted";
    const yLabel = svgEl("text", { x: pad - 4, y: pad - 10, "text-anchor": "start" });
    yLabel.textContent = "actual";
    svg.append(xLabel, yLabel);
  }

  function showMemory(data) {
    const plan = data.plan;
    $("memory-empty").hidden = Boolean(plan || data.briefing);
    $("memory").hidden = !(plan || data.briefing);
    if (plan) {
      $("plan-cycle").textContent = plan.cycle;
      $("plan-focus").textContent = plan.focus;
      const confidence = typeof plan.confidence === "number" ? plan.confidence.toFixed(2) : "-";
      $("plan-prediction").textContent =
        `ASR change ${signed(plan.expected_delta)} at confidence ${confidence}`;
      $("plan-cites").textContent = plan.cites.length
        ? plan.cites.map((id) => `lesson ${id}`).join(", ")
        : "no lessons";
      $("plan-hypothesis").textContent = plan.hypothesis;
    }
    const briefing = $("briefing");
    // Setting the same text again would throw away the reader's scroll place.
    const text = data.briefing ? data.briefing.text : "No briefing stored for this run.";
    if (briefing.textContent !== text) briefing.textContent = text;
    $("briefing-title").textContent = data.briefing
      ? `Briefing the CEO was sent in cycle ${data.briefing.cycle}`
      : "Briefing the CEO was sent";
    list("lesson-list", "lesson-empty", data.lessons || [], (lesson) => {
      const item = el("li");
      item.append(el("div", lesson.text, "agent-text"));
      const meta = el("div", undefined, "meta");
      const status = el("span", lesson.status, "status-word");
      status.dataset.status = lesson.status;
      const evidence = lesson.evidence_cycles.length
        ? `from cycle ${lesson.evidence_cycles.join(", ")}`
        : "no evidence cycle";
      meta.append(
        `Lesson ${lesson.id}, `,
        status,
        `, confidence ${lesson.confidence.toFixed(2)}, ${lesson.tags.join(", ")}, ${evidence}`,
      );
      item.append(meta);
      return item;
    });
    list("backlog-list", "backlog-empty", data.backlog || [], (entry) => {
      const item = el("li");
      item.append(el("div", entry.text, "agent-text"));
      item.append(el("div", `Item ${entry.id}, ${entry.status}`, "meta"));
      return item;
    });
    calibration($("plot-calibration"), data.calibration || []);
  }

  // Controls and alerts --------------------------------------------------------------------------

  let token = null;
  const STATE_WORDS = { running: "Running", paused: "Paused", stopped: "Stopped" };
  const TARGETS = { start: "running", resume: "running", pause: "paused", stop: "stopped" };

  async function write(url, body, errorId) {
    const error = $(errorId);
    error.hidden = true;
    try {
      if (!token) token = (await getJson("/dashboard/token")).token;
      const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Arena-Token": token },
        body: JSON.stringify(body),
      });
      const answer = await response.json();
      if (!response.ok) throw new Error(answer.error || `The server answered ${response.status}.`);
      await pollPanels();
      return answer;
    } catch (failure) {
      error.textContent = failure.message;
      error.hidden = false;
      return null;
    }
  }

  for (const button of document.querySelectorAll(".controls button")) {
    button.addEventListener("click", () =>
      write(`/control/${button.dataset.action}`, {}, "control-error"),
    );
  }

  $("note-add").addEventListener("click", async () => {
    const box = $("note-text");
    if (!box.value.trim()) {
      $("note-error").textContent = "Write the note first.";
      $("note-error").hidden = false;
      return;
    }
    if (await write("/notes", { text: box.value }, "note-error")) box.value = "";
  });

  function showOps(data) {
    showRuns(data.runs || []);
    const state = $("control-state");
    if (data.control) {
      const [who, what] = data.control.reason;
      state.dataset.state = data.control.state;
      const word = STATE_WORDS[data.control.state] || data.control.state;
      state.textContent = `${word}, set by ${who}${what ? ` (${what.replaceAll("_", " ")})` : ""}`;
      for (const button of document.querySelectorAll(".controls button")) {
        button.disabled = data.control.state === TARGETS[button.dataset.action];
      }
    } else {
      state.dataset.state = "";
      state.textContent = "No run database yet. Start a run from the command line first.";
    }
    list("anomaly-list", "anomaly-empty", data.anomalies || [], (anomaly) => {
      const item = el("li");
      item.append(el("strong", anomaly.kind.replaceAll("_", " ")));
      item.append(el("div", `Cycle ${anomaly.cycle}, ${when(anomaly.at)}`, "meta"));
      return item;
    });
    const blocked = Boolean(data.notes_blocked);
    $("note-add").disabled = blocked;
    $("note-add").title = blocked
      ? "A run is mid-cycle and this database holds more than one run."
      : "";
    const notes = $("note-list");
    clear(notes);
    for (const note of data.notes || []) {
      const item = el("li");
      item.append(el("div", note.text, "agent-text"));
      item.append(el("div", `Note ${note.id}, ${when(note.at)}`, "meta"));
      notes.append(item);
    }
    const usage = data.usage || [];
    $("usage-table").hidden = usage.length === 0;
    $("usage-empty").hidden = usage.length > 0;
    const rows = $("usage-rows");
    clear(rows);
    for (const entry of usage) {
      const row = rows.insertRow();
      row.append(
        el("td", entry.role),
        el("td", entry.calls),
        el("td", entry.input_tokens.toLocaleString("en-GB")),
        el("td", entry.output_tokens.toLocaleString("en-GB")),
        el("td", pct(entry.headroom)),
      );
    }
  }

  // Polling --------------------------------------------------------------------------------------

  let polling = false;
  async function pollPanels() {
    if (polling) return;
    polling = true;
    try {
      const [scores, memory, ops] = await Promise.all([
        getJson(`/dashboard/scores${runQuery}`),
        getJson(`/dashboard/memory${runQuery}`),
        getJson(`/dashboard/ops${runQuery}`),
      ]);
      if (scores.points) showScores(scores);
      if (memory.lessons) showMemory(memory);
      showOps(ops);
    } catch {
      // A missed poll is retried on the next tick.
    } finally {
      polling = false;
    }
  }

  pollCycles();
  pollPanels();
  setInterval(() => {
    pollCycles();
    pollPanels();
  }, POLL_MS);
})();
