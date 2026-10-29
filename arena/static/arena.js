// The arena: each finished cycle replays as dots travelling from the Attacker through the Detector
// to the Target, then the Defender's patch and the Judge's decision. The server sends codes, flags
// and counts only (arena/arena_feed.py). Every value is set with textContent or setAttribute.
// Its own scope: app.js shares the page and declares names of its own.
(() => {
  "use strict";

  // The run the page shows, chosen in the bar (dashboard.js); none means the newest run.
  const RUN = new URLSearchParams(location.search).get("run");
  const runQuery = RUN ? `&run=${encodeURIComponent(RUN)}` : "";
  const svg = document.getElementById("arena-svg");
  const NS = svg.namespaceURI;
  const dots = document.getElementById("arena-dots");
  const title = document.getElementById("arena-title");
  const focusLine = document.getElementById("arena-focus");
  const badge = document.getElementById("arena-badge");
  const caption = document.getElementById("arena-caption");
  const patchLabel = document.getElementById("arena-patch");
  const target = document.getElementById("arena-target");
  const stamp = document.getElementById("arena-stamp");
  const stampText = document.getElementById("arena-stamp-text");
  const strip = document.getElementById("arena-strip");
  const score = {
    cycles: document.getElementById("score-cycles"),
    kept: document.getElementById("score-kept"),
    rejected: document.getElementById("score-rejected"),
    rules: document.getElementById("score-rules"),
    asr: document.getElementById("score-asr"),
    tpr: document.getElementById("score-tpr"),
  };

  // Positions in the SVG's own units (viewBox 0 0 960 330).
  const START_X = 140;
  const GATE_X = 462;
  const FADE_X = 330;
  const TARGET_X = 822;
  const TOP_Y = 50;
  const BOTTOM_Y = 250;
  const POLL_MS = 10000;

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

  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)");
  const cycles = new Map();
  const queue = [];
  let after = 0;
  let fetching = false;
  // On first load the history goes to the strip and only the latest cycle plays.
  let loaded = false;
  let playing = false;
  let token = 0;
  let totals = { kept: 0, rejected: 0 };

  function node(name, attributes) {
    const element = document.createElementNS(NS, name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
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
    for (const op of patch.ops) {
      const sign = op.op === "add" ? "+" : op.op === "remove" ? "-" : "~";
      const names = { normalisers: "normaliser", rules: "rule", classifier_prompt: "prompt", layers: "layer" };
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

  function wait(ms, mine) {
    return new Promise((resolve) => setTimeout(() => resolve(mine === token), ms));
  }

  function move(element, dx, ms, fade) {
    if (reduced.matches) {
      element.style.transform = `translateX(${dx}px)`;
      if (fade) element.style.opacity = String(fade);
      return Promise.resolve();
    }
    const frames = [{ transform: "translateX(0)" }, { transform: `translateX(${dx}px)` }];
    if (fade) {
      frames[0].opacity = 1;
      frames[1].opacity = fade;
    }
    return element.animate(frames, { duration: ms, easing: "cubic-bezier(0.3, 0, 0.2, 1)", fill: "forwards" })
      .finished.catch(() => undefined);
  }

  function resetStage(cycle) {
    dots.replaceChildren();
    stamp.setAttribute("hidden", "");
    target.removeAttribute("data-hit");
    patchLabel.textContent = "";
    title.textContent = `Cycle ${cycle.cycle}`;
    focusLine.textContent = cycle.focus ? `focus: ${cycle.focus}` : "";
    const live = cycle.backend === "live";
    badge.hidden = !cycle.backend || cycle.backend === "none yet";
    badge.textContent = live ? "Live" : "Simulated";
    badge.dataset.kind = live ? "live" : "simulated";
  }

  async function playAttacks(attacks, mine, speed) {
    const rows = attacks.length;
    const step = rows > 1 ? (BOTTOM_Y - TOP_Y) / (rows - 1) : 0;
    const runs = attacks.map(async (attack, index) => {
      const y = rows > 1 ? TOP_Y + step * index : (TOP_Y + BOTTOM_Y) / 2;
      const kind = lane(attack);
      const group = node("g", { "data-lane": kind });
      const track = node("line", { class: "track", x1: START_X, y1: y, x2: TARGET_X, y2: y });
      const dot = node("circle", { class: "dot", cx: START_X, cy: y, r: 7, "data-lane": kind });
      const label = node("title", {});
      label.textContent = `${attack.technique}: ${kind === "through" ? "got past" : kind === "none" ? "no effect" : kind}`;
      dot.append(label);
      group.append(track, dot);
      if (attack.held_back) group.append(node("circle", { class: "ring", cx: START_X, cy: y, r: 11 }));
      dots.append(group);
      if (!(await wait(reduced.matches ? 0 : (index * 140) / speed, mine))) return;
      const moving = [...group.querySelectorAll("circle")];
      if (kind === "refused") {
        dot.style.opacity = "0.6";
        return;
      }
      if (kind === "none") {
        await Promise.all(moving.map((c) => move(c, FADE_X - START_X, 900 / speed, 0.12)));
        return;
      }
      if (kind === "caught") {
        await Promise.all(moving.map((c) => move(c, GATE_X - START_X - 8, 1100 / speed)));
        if (mine !== token) return;
        const cross = node("text", { class: "cross", x: GATE_X - 30, y: y + 5, "text-anchor": "middle" });
        cross.textContent = "×";
        group.append(cross);
          return;
      }
      await Promise.all(moving.map((c) => move(c, TARGET_X - START_X - 10, 1700 / speed)));
      if (mine === token) target.setAttribute("data-hit", "");
    });
    await Promise.all(runs);
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
    score.cycles.textContent = String(cycles.size);
    score.kept.textContent = String(totals.kept);
    score.rejected.textContent = String(totals.rejected);
    if (cycle.rules && cycle.rules.after != null) score.rules.textContent = String(cycle.rules.after);
    if (cycle.judge && cycle.judge.asr != null) score.asr.textContent = percent(cycle.judge.asr);
    if (cycle.judge && cycle.judge.tpr != null) score.tpr.textContent = percent(cycle.judge.tpr);
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
    caption.textContent = cycle.focus ? `The CEO sends the Attacker after ${cycle.focus}.` : "A new cycle.";
    if (!(await wait(700 / speed, mine))) return;
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
    if (!(await wait(1400 / speed, mine))) return;
    const [decision, , sentence] = verdict(cycle.judge);
    stamp.dataset.verdict = decision;
    // The stamp carries the decision; the caption below carries the reason.
    stampText.textContent = { keep: "Kept", reject: "Rejected" }[decision] || "No candidate";
    stamp.removeAttribute("hidden");
    caption.textContent = sentence;
    await wait(1800 / speed, mine);
  }

  async function drain() {
    if (playing) return;
    playing = true;
    // A replay starts a new generation; this loop then stops and leaves the queue to the new one.
    const mine = token;
    while (queue.length && mine === token) {
      const cycle = queue.shift();
      // When cycles arrive faster than they play, catch up at triple speed.
      await play(cycle, queue.length > 2 ? 3 : 1);
    }
    if (mine === token) playing = false;
  }

  function replay(id) {
    const cycle = cycles.get(id);
    if (!cycle) return;
    token += 1;
    for (const animation of svg.getAnimations({ subtree: true })) animation.cancel();
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
    for (const animation of svg.getAnimations({ subtree: true })) animation.cancel();
    playing = false;
    cycles.clear();
    queue.length = 0;
    after = 0;
    loaded = false;
    totals = { kept: 0, rejected: 0 };
    strip.replaceChildren();
    dots.replaceChildren();
    stamp.setAttribute("hidden", "");
    for (const key of Object.keys(score)) score[key].textContent = key === "rules" || key === "asr" || key === "tpr" ? "-" : "0";
    title.textContent = "Waiting for the first cycle";
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
