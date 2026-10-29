// The arena: each finished cycle replays as one sequence. The CEO sends its focus to both agents,
// the Attacker's attacks fly at the Detector, caught ones break on a shield ripple and the rest hit
// the Target, the Defender's patch sweeps the Detector, and the Judge stamps its verdict. The server
// sends codes, flags and counts only (arena/arena_feed.py). Every value is set with textContent or
// setAttribute.
// Motion follows `data-motion` on <html> (set in app.js). With motion off every step lands on its
// end state at once and the captions still tell the story.
// Its own scope: app.js shares the page and declares names of its own.
(() => {
  "use strict";

  // The run the page shows, chosen in the bar (dashboard.js); none means the newest run.
  const RUN = new URLSearchParams(location.search).get("run");
  const runQuery = RUN ? `&run=${encodeURIComponent(RUN)}` : "";
  const $ = (id) => document.getElementById(id);
  const svg = $("arena-svg");
  const NS = svg.namespaceURI;
  const dots = $("arena-dots");
  const fx = $("arena-fx");
  const gate = $("arena-gate");
  const ceo = $("arena-ceo");
  const title = $("arena-title");
  const focusLine = $("arena-focus");
  const badge = $("arena-badge");
  const caption = $("arena-caption");
  const patchLabel = $("arena-patch");
  const target = $("arena-target");
  const stamp = $("arena-stamp");
  const stampText = $("arena-stamp-text");
  const strip = $("arena-strip");
  const score = {
    cycles: $("score-cycles"),
    kept: $("score-kept"),
    rejected: $("score-rejected"),
    rules: $("score-rules"),
    asr: $("score-asr"),
    tpr: $("score-tpr"),
  };

  // Positions in the SVG's own units (viewBox 0 0 960 410).
  const START_X = 140;
  const GATE_X = 472;
  const GATE_MID = 480;
  const FADE_X = 330;
  const TARGET_X = 820;
  const TOP_Y = 116;
  const BOTTOM_Y = 302;
  const CEO_X = 480;
  const CEO_Y = 42;
  const POLL_MS = 10000;
  // More cycles than this waiting to play: skip to the newest, since the strip and scoreboard
  // already hold the rest.
  const MAX_WAITING = 3;

  const REASONS = {
    kept: "kept",
    no_tpr_gain: "no gain on dev",
    failed_fold_two: "did not replicate on the second fold",
    asr_regressed: "attack success rose",
    utility_below_cap: "cost too much normal work",
    category_fpr_over_cap: "too many false alarms in one category",
    regression_reopened: "let an old attack back in",
    missed_fresh_evasions: "missed the held-back evasions",
    target_fpr_unreachable: "could not reach the false-alarm target",
    not_implemented: "no candidate to judge",
  };

  const cycles = new Map();
  const queue = [];
  // Every animation this script starts, kept until the stage resets, so a reset can undo even
  // the ones that finished and still hold their end state. CSS loops are never in here.
  const started = new Set();
  let after = 0;
  let fetching = false;
  // On first load the history goes to the strip and only the latest cycle plays.
  let loaded = false;
  let playing = false;
  let token = 0;
  let totals = { kept: 0, rejected: 0 };

  const motionOn = () => document.documentElement.dataset.motion === "on";

  function node(name, attributes) {
    const element = document.createElementNS(NS, name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
  }

  // One animation, tracked. With motion off it runs in zero time, so it still lands on its end.
  function animate(element, frames, ms, extra = {}) {
    const animation = element.animate(frames, {
      duration: motionOn() ? ms : 0,
      easing: "cubic-bezier(0.3, 0, 0.2, 1)",
      fill: "forwards",
      ...extra,
    });
    started.add(animation);
    return animation.finished.catch(() => undefined);
  }

  function cancelStarted() {
    for (const animation of started) animation.cancel();
    started.clear();
  }

  function wait(ms, mine) {
    return new Promise((resolve) => setTimeout(() => resolve(mine === token), ms));
  }

  function lane(attack) {
    if (attack.refused) return "refused";
    if (!attack.valid) return "none";
    return attack.evaded ? "through" : "caught";
  }

  function words(count, one, many) {
    return `${count} ${count === 1 ? one : many}`;
  }

  function tally(attacks) {
    const counts = { caught: 0, through: 0, none: 0, refused: 0 };
    for (const attack of attacks) counts[lane(attack)] += 1;
    const parts = [`${counts.caught} caught`, `${counts.through} got past`];
    if (counts.none) parts.push(`${counts.none} no effect`);
    if (counts.refused) parts.push(`${counts.refused} refused`);
    return `${words(attacks.length, "attack", "attacks")}: ${parts.join(", ")}.`;
  }

  function patchText(patch) {
    if (!patch) return "no patch";
    if (patch.refused) return "patch refused";
    const groups = new Map();
    const names = { normalisers: "normaliser", rules: "rule", classifier_prompt: "prompt", layers: "layer" };
    for (const op of patch.ops) {
      const sign = op.op === "add" ? "+" : op.op === "remove" ? "-" : "~";
      const key = `${sign}${names[op.field] || "change"}`;
      groups.set(key, (groups.get(key) || 0) + 1);
    }
    return [...groups].map(([key, n]) => `${key[0]}${n} ${key.slice(1)}${n === 1 ? "" : "s"}`).join(", ");
  }

  // [decision, short label for the strip, caption sentence].
  function verdict(judge) {
    if (!judge || judge.decision === "none") {
      return ["none", "No candidate", "The Judge had no patch to judge."];
    }
    const reason = REASONS[judge.reason] || judge.reason.replaceAll("_", " ");
    return judge.decision === "keep"
      ? ["keep", "Kept", "The Judge kept the patch."]
      : ["reject", `Rejected, ${reason}`, `The Judge rejected the patch: ${reason}.`];
  }

  function percent(value) {
    return value == null ? "-" : `${(value * 100).toFixed(1)}%`;
  }

  // Numbers on the scoreboard count up to their new value. The scoreboard is not a live region,
  // so a screen reader hears only the caption, never the counting.
  function countTo(element, value, format = String) {
    const from = Number.parseFloat(element.textContent);
    if (!motionOn() || !Number.isFinite(from) || from === value) {
      element.textContent = format(value);
      return;
    }
    const start = performance.now();
    const step = (now) => {
      const t = Math.min((now - start) / 600, 1);
      const eased = 1 - (1 - t) ** 3;
      element.textContent = format(from + (value - from) * eased);
      if (t < 1) requestAnimationFrame(step);
      else element.textContent = format(value);
    };
    requestAnimationFrame(step);
  }

  function resetStage(cycle) {
    cancelStarted();
    dots.replaceChildren();
    fx.replaceChildren();
    stamp.setAttribute("hidden", "");
    target.removeAttribute("data-hit");
    patchLabel.textContent = "";
    title.textContent = `Cycle ${cycle.cycle}`;
    focusLine.textContent = cycle.focus ? `focus ${cycle.focus}` : "";
    const live = cycle.backend === "live";
    badge.hidden = !cycle.backend || cycle.backend === "none yet";
    badge.textContent = live ? "Live" : "Simulated";
    badge.dataset.kind = live ? "live" : "simulated";
  }

  // 1. The CEO sends the cycle's focus to the Attacker and the Defender.
  async function ceoBeams() {
    const flash = node("circle", { class: "beam", cx: CEO_X, cy: CEO_Y, r: 28 });
    const toAttacker = node("path", { class: "beam", d: `M${CEO_X - 24} ${CEO_Y + 10} Q 300 70 ${START_X} 170` });
    const toDefender = node("path", { class: "beam", d: `M${CEO_X + 24} ${CEO_Y + 10} Q 600 200 ${GATE_MID + 18} 340` });
    fx.append(flash, toAttacker, toDefender);
    const beam = [
      { opacity: 0, strokeDashoffset: 44 },
      { opacity: 1, strokeDashoffset: 22, offset: 0.4 },
      { opacity: 0, strokeDashoffset: 0 },
    ];
    await Promise.all([
      animate(flash, [{ opacity: 0.9, transform: "scale(0.8)" }, { opacity: 0, transform: "scale(1.5)" }], 900, {
        easing: "ease-out",
      }),
      // No held end state here: it would freeze the CEO's breathing loop after the first replay.
      animate(ceo, [{ fillOpacity: 1 }, { fillOpacity: 0.2 }], 900, { fill: "none" }),
      animate(toAttacker, beam, 1100, { easing: "linear" }),
      animate(toDefender, beam, 1100, { easing: "linear" }),
    ]);
  }

  function ring(className, x, y, to) {
    const circle = node("circle", { class: className, cx: x, cy: y, r: 4 });
    fx.append(circle);
    return animate(
      circle,
      [
        { opacity: 1, r: "4px" },
        { opacity: 0, r: `${to}px` },
      ],
      650,
      { easing: "ease-out" },
    );
  }

  // 2 and 3. Each attack flies as a comet; the Detector's shield breaks the caught ones.
  async function playAttacks(attacks, mine, speed) {
    const rows = attacks.length;
    const step = rows > 1 ? (BOTTOM_Y - TOP_Y) / (rows - 1) : 0;
    const runs = attacks.map(async (attack, index) => {
      const y = rows > 1 ? TOP_Y + step * index : (TOP_Y + BOTTOM_Y) / 2;
      const kind = lane(attack);
      dots.append(node("line", { class: "track", x1: START_X, y1: y, x2: TARGET_X, y2: y }));
      const comet = node("g", { "data-lane": kind });
      comet.style.transform = `translate(${START_X}px, ${y}px)`;
      const tail = node("line", { class: "tail", x1: -30, y1: 0, x2: 0, y2: 0, "stroke-opacity": 0 });
      const dot = node("circle", { class: "dot", cx: 0, cy: 0, r: 7, "data-lane": kind });
      const label = node("title", {});
      label.textContent = `${attack.technique}: ${kind === "through" ? "got past" : kind === "none" ? "no effect" : kind}`;
      dot.append(label);
      comet.append(tail, dot);
      if (attack.held_back) comet.append(node("circle", { class: "ring", cx: 0, cy: 0, r: 11 }));
      dots.append(comet);
      if (!(await wait(motionOn() ? (index * 160) / speed : 0, mine))) return;
      const fly = (toX, ms, fade) => {
        const frames = [
          { transform: `translate(${START_X}px, ${y}px)` },
          { transform: `translate(${toX}px, ${y}px)` },
        ];
        if (fade !== undefined) {
          frames[0].opacity = 1;
          frames[1].opacity = fade;
        }
        animate(tail, [{ strokeOpacity: 0.5 }, { strokeOpacity: 0.35, offset: 0.8 }, { strokeOpacity: 0 }], ms / speed);
        return animate(comet, frames, ms / speed);
      };
      if (kind === "refused") {
        comet.style.opacity = "0.6";
        return;
      }
      if (kind === "none") {
        await fly(FADE_X, 900, 0.15);
        return;
      }
      if (kind === "caught") {
        await fly(GATE_X - 10, 1100);
        if (mine !== token) return;
        ring("ripple", GATE_MID, y, 26);
        animate(dot, [{ opacity: 1 }, { opacity: 0.4 }], 300);
        const cross = node("text", { class: "cross", x: GATE_X - 32, y: y + 5, "text-anchor": "middle" });
        cross.textContent = "×";
        dots.append(cross);
        return;
      }
      await fly(TARGET_X - 10, 1700);
      if (mine !== token) return;
      target.setAttribute("data-hit", "");
      ring("impact", TARGET_X, y, 32);
      animate(
        target,
        [
          { transform: "translateX(0)" },
          { transform: "translateX(-5px)" },
          { transform: "translateX(5px)" },
          { transform: "translateX(-3px)" },
          { transform: "translateX(0)" },
        ],
        360,
        { easing: "linear" },
      );
    });
    await Promise.all(runs);
  }

  // 4. The Defender's patch sweeps the Detector, which grows with each rule added.
  async function patchSweep(patch) {
    const scan = node("rect", { class: "scan", x: GATE_X - 8, y: 96, width: 32, height: 5, rx: 2 });
    fx.append(scan);
    await animate(
      scan,
      [
        { transform: "translateY(0)", opacity: 0.9 },
        { transform: "translateY(221px)", opacity: 0.2 },
      ],
      900,
      { easing: "ease-in-out" },
    );
    scan.remove();
    if (!patch || patch.refused) return;
    const added = patch.ops.filter((op) => op.op === "add").length;
    if (added) animate(gate, [{ transform: "scaleX(1)" }, { transform: `scaleX(${1 + Math.min(added, 4) * 0.25})` }], 500);
  }

  function markStrip(cycle) {
    let button = strip.querySelector(`[data-cycle="${cycle.cycle}"]`);
    if (!button) {
      const item = document.createElement("li");
      button = document.createElement("button");
      button.type = "button";
      button.dataset.cycle = String(cycle.cycle);
      button.addEventListener("click", () => replay(cycle.cycle));
      item.append(button);
      strip.append(item);
    }
    const outcome = cycle.unreadable ? "unreadable" : cycle.state === "rolled_back" ? "rolled back" : verdict(cycle.judge)[1];
    button.dataset.outcome = cycle.judge ? cycle.judge.decision : "none";
    button.setAttribute("aria-label", `Cycle ${cycle.cycle}, ${outcome.toLowerCase()}. Replay.`);
    button.title = `Cycle ${cycle.cycle}: ${outcome}`;
  }

  function scoreCycle(cycle) {
    if (cycle.judge && cycle.judge.decision === "keep") totals.kept += 1;
    if (cycle.judge && cycle.judge.decision === "reject") totals.rejected += 1;
    const whole = (n) => String(Math.round(n));
    countTo(score.cycles, cycles.size, whole);
    countTo(score.kept, totals.kept, whole);
    countTo(score.rejected, totals.rejected, whole);
    if (cycle.rules && cycle.rules.after != null) countTo(score.rules, cycle.rules.after, whole);
    if (cycle.judge && cycle.judge.asr != null) countTo(score.asr, cycle.judge.asr * 100, (n) => percent(n / 100));
    if (cycle.judge && cycle.judge.tpr != null) countTo(score.tpr, cycle.judge.tpr * 100, (n) => percent(n / 100));
  }

  async function play(cycle, speed) {
    const mine = token;
    for (const button of strip.querySelectorAll("[data-playing]")) button.removeAttribute("data-playing");
    const current = strip.querySelector(`[data-cycle="${cycle.cycle}"]`);
    if (current) current.setAttribute("data-playing", "");
    resetStage(cycle);
    if (cycle.unreadable) {
      caption.textContent = `Cycle ${cycle.cycle} could not be read.`;
      return;
    }
    if (cycle.state === "rolled_back") {
      caption.textContent = `Cycle ${cycle.cycle} was rolled back, so nothing from it counts.`;
      return;
    }
    caption.textContent = cycle.focus ? `The CEO sends both agents after ${cycle.focus}.` : "A new cycle.";
    await ceoBeams();
    if (!(await wait(200 / speed, mine))) return;
    if (cycle.attacks.length) {
      caption.textContent = `The Attacker sends ${words(cycle.attacks.length, "attack", "attacks")} at the Detector.`;
      await playAttacks(cycle.attacks, mine, speed);
      if (mine !== token) return;
      caption.textContent = tally(cycle.attacks);
    } else {
      caption.textContent = "The Attacker sat this cycle out.";
    }
    if (!(await wait(1200 / speed, mine))) return;
    patchLabel.textContent = patchText(cycle.patch);
    caption.textContent = cycle.patch
      ? `The Defender patches the Detector: ${patchText(cycle.patch)}.`
      : "The Defender sat this cycle out.";
    await patchSweep(cycle.patch);
    if (!(await wait(700 / speed, mine))) return;
    const [decision, , sentence] = verdict(cycle.judge);
    stamp.dataset.verdict = decision;
    // The stamp carries the decision; the caption below carries the reason.
    stampText.textContent = { keep: "KEPT", reject: "REJECTED" }[decision] || "NO CANDIDATE";
    stamp.removeAttribute("hidden");
    caption.textContent = sentence;
    await animate(
      stamp,
      [
        { opacity: 0, transform: "scale(1.8) rotate(-10deg)" },
        { opacity: 1, transform: "scale(0.94) rotate(-3deg)", offset: 0.75 },
        { opacity: 1, transform: "scale(1) rotate(-3deg)" },
      ],
      420,
      { easing: "cubic-bezier(0.2, 0.8, 0.3, 1.2)" },
    );
    await wait(1800 / speed, mine);
  }

  async function drain() {
    if (playing) return;
    playing = true;
    // A replay starts a new generation; this loop then stops and leaves the queue to the new one.
    const mine = token;
    while (queue.length && mine === token) {
      if (queue.length > MAX_WAITING) queue.splice(0, queue.length - 1);
      await play(queue.shift(), 1);
    }
    if (mine === token) playing = false;
  }

  function replay(id) {
    const cycle = cycles.get(id);
    if (!cycle) return;
    token += 1;
    cancelStarted();
    playing = false;
    queue.unshift(cycle);
    drain();
  }

  async function poll() {
    if (fetching) return;
    fetching = true;
    try {
      const response = await fetch(`/arena/cycles?after=${after}${runQuery}`);
      if (!response.ok) return;
      const page = await response.json();
      for (const cycle of page.cycles) {
        if (cycles.has(cycle.cycle)) continue;
        cycles.set(cycle.cycle, cycle);
        markStrip(cycle);
        scoreCycle(cycle);
        queue.push(cycle);
      }
      after = page.next_after;
      if (page.cycles.length >= 50) {
        setTimeout(poll, 0);
        return;
      }
      if (!loaded) {
        loaded = true;
        queue.splice(0, queue.length - 1);
      }
      drain();
    } catch {
      // The feed's own status line reports a lost connection; the next poll tries again.
    } finally {
      fetching = false;
    }
  }

  function resetAll() {
    token += 1;
    cancelStarted();
    playing = false;
    cycles.clear();
    queue.length = 0;
    after = 0;
    loaded = false;
    totals = { kept: 0, rejected: 0 };
    strip.replaceChildren();
    dots.replaceChildren();
    fx.replaceChildren();
    stamp.setAttribute("hidden", "");
    target.removeAttribute("data-hit");
    for (const key of Object.keys(score)) score[key].textContent = key === "rules" || key === "asr" || key === "tpr" ? "-" : "0";
    title.textContent = "Waiting for the first cycle";
    focusLine.textContent = "";
    caption.textContent = "Start a run and each finished cycle plays here.";
  }

  document.addEventListener("feed:event", poll);
  document.addEventListener("feed:status", (event) => {
    // A new run database replaced the old one: start the arena again from its first cycle.
    if (event.detail === "reset") resetAll();
  });
  setInterval(poll, POLL_MS);
  poll();
})();
