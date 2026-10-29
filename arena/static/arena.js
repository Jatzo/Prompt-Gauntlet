// The siege arena: each finished cycle replays on a ring. The detector is the blue shield, its
// rules the lit slots; the Attacker's attacks fly from the red launch node at the ring, one slice
// per technique, so a mark's angle names its technique. Caught attacks stop on the shield, the
// ones that get past reach the target in the centre, and the Judge's verdict lands last. The server
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
  const view = {
    core: $("arena-core"),
    slots: $("ring-slots"),
    notches: $("ring-notches"),
    marks: $("arena-marks"),
    fx: $("arena-fx"),
    orbits: { a: $("orbit-a"), b: $("orbit-b"), c: $("orbit-c") },
    redSub: $("ring-red-sub"),
    blueSub: $("ring-blue-sub"),
    title: $("arena-title"),
    badge: $("arena-badge"),
    focus: $("arena-focus"),
    caption: $("arena-caption"),
    strip: $("arena-strip"),
    redTally: $("red-tally"),
    redList: $("red-list"),
    redNote: $("red-note"),
    blueTally: $("blue-tally"),
    blueNote: $("blue-note"),
    tprValue: $("tpr-value"),
    tprFill: $("tpr-fill"),
    asrValue: $("asr-value"),
    asrFill: $("asr-fill"),
    purpleTally: $("purple-tally"),
    verdict: $("verdict"),
    verdictTitle: $("verdict-title"),
    verdictDetail: $("verdict-detail"),
  };

  // Positions in the SVG's own units (viewBox 0 0 900 800), around the ring's centre.
  const C = 450;
  const R_CORE = 90;
  const R_SHIELD = 230;
  const R_MARK = 266;
  const ORBIT = { a: 320, b: 350, c: 380 };
  const LAUNCH = [202, 697];
  const POLL_MS = 10000;
  // More cycles than this waiting to play: skip to the newest, since the strip and cards already
  // hold the rest.
  const MAX_WAITING = 3;
  // Slices on the ring and rows in the red card; a bigger batch is summed up in a line.
  const MAX_SLICES = 12;
  const MAX_ROWS = 8;
  // The whole volley lands within this, however large the batch.
  const VOLLEY_MS = 3100;
  // Slots drawn before the first cycle arrives: the default rule cap (config.max_rules).
  const DEFAULT_SLOTS = 40;

  // Worst first: a technique's row takes the colour of its worst outcome.
  const KINDS = ["through", "held", "caught", "none", "refused"];
  const KIND_WORDS = { through: "got past", held: "got past, held back", caught: "caught", none: "no effect", refused: "refused" };
  const ORBIT_OF = { through: "a", caught: "a", held: "b", none: "c", refused: "c" };

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
  let kept = 0;
  let slotCount = 0;

  const motionOn = () => document.documentElement.dataset.motion === "on";

  function node(name, attributes) {
    const element = document.createElementNS(NS, name);
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
  }

  function html(name, text, attributes = {}) {
    const element = document.createElement(name);
    if (text !== undefined) element.textContent = text;
    for (const [key, value] of Object.entries(attributes)) element.setAttribute(key, String(value));
    return element;
  }

  // A point on the ring, `degrees` clockwise from the top.
  function polar(radius, degrees) {
    const rad = (degrees * Math.PI) / 180;
    return [C + radius * Math.sin(rad), C - radius * Math.cos(rad)];
  }

  function fixed(n) {
    return Math.round(n * 10) / 10;
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
    return new Promise((resolve) => setTimeout(() => resolve(mine === token), motionOn() ? ms : 0));
  }

  function words(count, one, many) {
    return `${count} ${count === 1 ? one : many}`;
  }

  function percent(value) {
    return value == null ? "-" : `${(value * 100).toFixed(1)}%`;
  }

  function kindOf(attack) {
    if (attack.refused) return "refused";
    if (attack.held_back) return "held";
    if (!attack.valid) return "none";
    return attack.evaded ? "through" : "caught";
  }

  // The batch per technique: counts per outcome, worst outcome first, busiest techniques first.
  function techniques(attacks) {
    const byName = new Map();
    for (const attack of attacks) {
      const counts = byName.get(attack.technique) || Object.fromEntries(KINDS.map((kind) => [kind, 0]));
      counts[kindOf(attack)] += 1;
      byName.set(attack.technique, counts);
    }
    return [...byName]
      .map(([name, counts]) => ({
        name,
        counts,
        total: KINDS.reduce((sum, kind) => sum + counts[kind], 0),
        worst: KINDS.find((kind) => counts[kind] > 0),
      }))
      .sort((x, y) => KINDS.indexOf(x.worst) - KINDS.indexOf(y.worst) || y.total - x.total || x.name.localeCompare(y.name));
  }

  // One mark per technique and outcome, at the technique's slice of the ring.
  function placements(list) {
    const shown = list.slice(0, MAX_SLICES).sort((x, y) => x.name.localeCompare(y.name));
    const slice = 360 / Math.max(shown.length, 1);
    const marks = [];
    shown.forEach((technique, index) => {
      const kinds = KINDS.filter((kind) => technique.counts[kind] > 0);
      const step = Math.min(9, slice / (kinds.length + 1));
      kinds.forEach((kind, j) => {
        marks.push({
          technique: technique.name,
          kind,
          count: technique.counts[kind],
          angle: (index + 0.5) * slice + (j - (kinds.length - 1) / 2) * step,
        });
      });
    });
    return marks;
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
    if (!groups.size) return "no change";
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

  // Numbers count up to their new value. The cards are not live regions, so a screen reader hears
  // only the caption, never the counting.
  function countTo(element, value, format) {
    const from = Number.parseFloat(element.textContent);
    if (!motionOn() || !Number.isFinite(from) || from === value) {
      element.textContent = format(value);
      return;
    }
    const start = performance.now();
    const step = (now) => {
      const t = Math.min((now - start) / 600, 1);
      element.textContent = format(from + (value - from) * (1 - (1 - t) ** 3));
      if (t < 1) requestAnimationFrame(step);
      else element.textContent = format(value);
    };
    requestAnimationFrame(step);
  }

  // The radar sweep: three slices, brightest at the leading edge.
  function buildSweep() {
    const sweep = $("ring-sweep");
    for (const [from, to, opacity] of [
      [0, 48, 0.05],
      [48, 76, 0.12],
      [76, 96, 0.26],
    ]) {
      const [x1, y1] = polar(223, from);
      const [x2, y2] = polar(223, to);
      sweep.append(
        node("path", {
          class: "sweep",
          d: `M${C} ${C} L${fixed(x1)} ${fixed(y1)} A223 223 0 0 1 ${fixed(x2)} ${fixed(y2)} Z`,
          "fill-opacity": opacity,
        }),
      );
    }
  }

  function buildSlots(cap) {
    if (cap === slotCount) return;
    slotCount = cap;
    view.slots.replaceChildren();
    const size = cap > 24 ? 13 : 18;
    for (let i = 0; i < cap; i += 1) {
      const angle = ((i + 0.5) * 360) / cap;
      const [x, y] = polar(R_SHIELD, angle);
      view.slots.append(
        node("rect", {
          class: "slot",
          x: fixed(x - size / 2),
          y: fixed(y - size / 2),
          width: size,
          height: size,
          rx: 4,
          transform: `rotate(${fixed(angle)} ${fixed(x)} ${fixed(y)})`,
        }),
      );
    }
  }

  function lightSlots(count) {
    [...view.slots.children].forEach((slot, i) => slot.toggleAttribute("data-lit", i < count));
  }

  // New slots light one by one, as the kept patch's rules go in.
  async function growSlots(from, to, mine) {
    const slots = [...view.slots.children];
    for (let i = from; i < to && i < slots.length; i += 1) {
      if (!(await wait(140, mine))) return;
      slots[i].setAttribute("data-lit", "");
      animate(slots[i], [{ opacity: 0 }, { opacity: 1 }], 300);
    }
    lightSlots(to);
  }

  function orbitDots(marks) {
    for (const orbit of Object.values(view.orbits)) orbit.replaceChildren();
    for (const mark of marks) {
      const radius = ORBIT[ORBIT_OF[mark.kind]];
      const [cx, cy] = polar(radius, mark.angle);
      const dot = node("circle", { class: "orbit-dot", "data-kind": mark.kind, cx: fixed(cx), cy: fixed(cy), r: mark.kind === "through" ? 9 : 7 });
      dot.append(title(`${mark.technique}: ${mark.count} ${KIND_WORDS[mark.kind]}`));
      view.orbits[ORBIT_OF[mark.kind]].append(dot);
    }
  }

  function title(text) {
    const element = node("title", {});
    element.textContent = text;
    return element;
  }

  // The end state of one mark on the ring.
  function placeMark(mark) {
    const [x, y] = polar(R_MARK, mark.angle);
    const group = node("g", { "data-kind": mark.kind });
    group.append(title(`${mark.technique}: ${mark.count} ${KIND_WORDS[mark.kind]}`));
    if (mark.kind === "caught") {
      const cross = node("text", { class: "mark-caught", x: fixed(x), y: fixed(y + 6), "text-anchor": "middle" });
      cross.textContent = "✕";
      group.append(cross);
    } else if (mark.kind === "through") {
      group.append(node("circle", { class: "mark-through pulse", cx: fixed(x), cy: fixed(y), r: 10 }));
      const [x1, y1] = polar(R_SHIELD, mark.angle - 4);
      const [x2, y2] = polar(R_SHIELD, mark.angle + 4);
      view.notches.append(
        node("path", {
          class: "notch",
          d: `M${fixed(x1)} ${fixed(y1)} A${R_SHIELD} ${R_SHIELD} 0 0 1 ${fixed(x2)} ${fixed(y2)}`,
        }),
      );
    } else if (mark.kind === "held") {
      group.append(node("circle", { class: "mark-held", cx: fixed(x), cy: fixed(y), r: 8.5 }));
    } else if (mark.kind === "none") {
      group.append(node("circle", { class: "mark-none", cx: fixed(x), cy: fixed(y), r: 8 }));
    } else {
      const [ax, ay] = polar(R_MARK, mark.angle - 1.6);
      const [bx, by] = polar(R_MARK, mark.angle + 1.6);
      group.append(node("line", { class: "mark-refused", x1: fixed(ax), y1: fixed(ay), x2: fixed(bx), y2: fixed(by) }));
    }
    if (mark.count > 1) {
      const [cx, cy] = polar(R_MARK + 22, mark.angle);
      const count = node("text", { class: "mark-count", x: fixed(cx), y: fixed(cy + 4), "text-anchor": "middle" });
      count.textContent = String(mark.count);
      group.append(count);
    }
    view.marks.append(group);
    return group;
  }

  function ring(className, x, y, scale) {
    const circle = node("circle", { class: className, cx: fixed(x), cy: fixed(y), r: 8 });
    view.fx.append(circle);
    return animate(
      circle,
      [
        { opacity: 1, transform: "scale(1)" },
        { opacity: 0, transform: `scale(${scale})` },
      ],
      700,
      { easing: "ease-out" },
    );
  }

  // One comet per mark, staggered so the whole volley lands within VOLLEY_MS.
  async function volley(marks, mine) {
    const gap = marks.length > 1 ? Math.min(260, (VOLLEY_MS - 900) / (marks.length - 1)) : 0;
    const flights = marks.map(async (mark, index) => {
      if (!(await wait(index * gap, mine))) return;
      if (mark.kind === "refused") {
        animate(placeMark(mark), [{ opacity: 0 }, { opacity: 1 }], 400);
        return;
      }
      const [mx, my] = polar(R_MARK + 8, mark.angle);
      const [cx, cy] = polar(R_CORE + 8, mark.angle);
      const start = `translate(${LAUNCH[0]}px, ${LAUNCH[1]}px)`;
      const comet = node("circle", { class: "comet", cx: 0, cy: 0, r: 7 });
      comet.style.transform = start;
      view.fx.append(comet);
      let frames;
      if (mark.kind === "through") {
        frames = [{ transform: start }, { transform: `translate(${mx}px, ${my}px)`, offset: 0.65 }, { transform: `translate(${cx}px, ${cy}px)` }];
      } else if (mark.kind === "none") {
        const [hx, hy] = [(LAUNCH[0] + mx) / 2, (LAUNCH[1] + my) / 2];
        frames = [{ transform: start, opacity: 1 }, { transform: `translate(${hx}px, ${hy}px)`, opacity: 0 }];
      } else {
        frames = [{ transform: start }, { transform: `translate(${mx}px, ${my}px)` }];
      }
      await animate(comet, frames, mark.kind === "through" ? 1300 : 900);
      comet.remove();
      if (mine !== token) return;
      if (mark.kind === "caught") {
        ring("ripple", ...polar(R_SHIELD + 10, mark.angle), 4);
      } else if (mark.kind === "through") {
        view.core.setAttribute("data-hit", "");
        ring("impact", C, C, 12);
      }
      animate(placeMark(mark), [{ opacity: 0 }, { opacity: 1 }], 300);
    });
    await Promise.all(flights);
  }

  function renderRed(list, attacks) {
    view.redList.replaceChildren();
    if (!attacks.length) {
      view.redTally.textContent = "-";
      view.redNote.textContent = "No attacks this cycle.";
      view.redNote.hidden = false;
      view.redSub.textContent = "";
      return;
    }
    // The Judge holds back only attacks that got past (arena/judge/attacks.py), so both count.
    const through = attacks.filter((attack) => ["through", "held"].includes(kindOf(attack))).length;
    view.redTally.textContent = `${through}/${attacks.length}`;
    for (const technique of list.slice(0, MAX_ROWS)) {
      const parts = KINDS.filter((kind) => technique.counts[kind]).map((kind) => `${technique.counts[kind]} ${KIND_WORDS[kind]}`);
      const row = html("li", undefined, { "data-kind": technique.worst });
      row.append(html("span", undefined, { class: "pip", "aria-hidden": "true" }), html("span", technique.name, { class: "technique" }), html("span", parts.join(", "), { class: "outcome" }));
      view.redList.append(row);
    }
    const more = list.length - MAX_ROWS;
    view.redNote.hidden = more <= 0;
    view.redNote.textContent = more > 0 ? `and ${words(more, "more technique", "more techniques")}.` : "";
    view.redSub.textContent = `${words(attacks.length, "attack", "attacks")} over ${words(list.length, "technique", "techniques")}`;
  }

  function setBlue(cycle, lit) {
    const rules = cycle.rules || {};
    const cap = rules.cap || slotCount;
    view.blueTally.textContent = lit == null ? `0/${cap}` : `${lit}/${cap}`;
    view.blueSub.textContent = lit == null ? "no detector yet" : `${lit} of ${cap} rule slots in use`;
  }

  function renderBlue(cycle) {
    const rules = cycle.rules || {};
    setBlue(cycle, rules.after);
    view.blueNote.textContent =
      rules.after == null
        ? "No detector yet: every slot is empty."
        : `${words(rules.after, "rule", "rules")} in the detector after this cycle. The Defender's patch: ${patchText(cycle.patch)}.`;
    const judge = cycle.judge || {};
    view.tprValue.textContent = percent(judge.tpr);
    view.asrValue.textContent = percent(judge.asr);
    view.tprFill.style.width = `${(judge.tpr || 0) * 100}%`;
    view.asrFill.style.width = `${(judge.asr || 0) * 100}%`;
  }

  function renderPurple(cycle) {
    const decision = verdict(cycle.judge)[0];
    view.verdict.dataset.decision = decision;
    view.verdictTitle.textContent = { keep: "Patch kept", reject: "Patch rejected" }[decision] || "No candidate";
    const reason = decision === "reject" ? REASONS[cycle.judge.reason] || cycle.judge.reason.replaceAll("_", " ") : "";
    view.verdictDetail.textContent = decision === "none" ? "Nothing to measure this cycle" : [patchText(cycle.patch), reason].filter(Boolean).join(", ");
    const whole = (n) => String(Math.round(n));
    view.purpleTally.textContent = `${whole(kept)}/${cycles.size}`;
  }

  function resetStage(cycle) {
    cancelStarted();
    view.marks.replaceChildren();
    view.notches.replaceChildren();
    view.fx.replaceChildren();
    for (const orbit of Object.values(view.orbits)) orbit.replaceChildren();
    view.core.removeAttribute("data-hit");
    view.title.textContent = `Cycle ${cycle.cycle}`;
    view.focus.textContent = cycle.focus ? `focus ${cycle.focus}` : "";
    const live = cycle.backend === "live";
    view.badge.hidden = !cycle.backend || cycle.backend === "none yet";
    view.badge.textContent = live ? "Live" : "Simulated";
    view.badge.title = live ? "" : "Stand-in models ran this cycle to test the machinery cheaply. Its numbers are not real results.";
    view.badge.dataset.kind = live ? "live" : "simulated";
    view.redList.replaceChildren();
    view.redTally.textContent = "-";
    view.redNote.hidden = false;
    view.redNote.textContent = "Attacks in flight.";
    view.blueNote.textContent = "Waiting for the Defender's patch.";
    view.verdict.dataset.decision = "none";
    view.verdictTitle.textContent = "Waiting for the Judge";
    view.verdictDetail.textContent = "";
  }

  function markStrip(cycle) {
    let button = view.strip.querySelector(`[data-cycle="${cycle.cycle}"]`);
    if (!button) {
      const item = document.createElement("li");
      button = document.createElement("button");
      button.type = "button";
      button.dataset.cycle = String(cycle.cycle);
      button.addEventListener("click", () => replay(cycle.cycle));
      item.append(button);
      view.strip.append(item);
    }
    const outcome = cycle.unreadable ? "unreadable" : cycle.state === "rolled_back" ? "rolled back" : verdict(cycle.judge)[1];
    button.dataset.outcome = cycle.judge ? cycle.judge.decision : "none";
    button.setAttribute("aria-label", `Cycle ${cycle.cycle}, ${outcome.toLowerCase()}. Replay.`);
    button.title = `Cycle ${cycle.cycle}: ${outcome}`;
  }

  async function play(cycle) {
    const mine = token;
    for (const button of view.strip.querySelectorAll("[data-playing]")) button.removeAttribute("data-playing");
    const current = view.strip.querySelector(`[data-cycle="${cycle.cycle}"]`);
    if (current) current.setAttribute("data-playing", "");
    resetStage(cycle);
    if (cycle.unreadable || cycle.state === "rolled_back") {
      view.caption.textContent = cycle.unreadable
        ? `Cycle ${cycle.cycle} could not be read.`
        : `Cycle ${cycle.cycle} was rolled back, so nothing from it counts.`;
      view.verdictTitle.textContent = cycle.unreadable ? "Unreadable" : "Rolled back";
      return;
    }
    const rules = cycle.rules || {};
    buildSlots(rules.cap || slotCount);
    const before = rules.before ?? rules.after;
    lightSlots(before || 0);
    setBlue(cycle, before);
    const list = techniques(cycle.attacks);
    const marks = placements(list);
    orbitDots(marks);
    view.caption.textContent = cycle.focus ? `The CEO sends the Attacker after ${cycle.focus}.` : "A new cycle.";
    if (!(await wait(900, mine))) return;
    if (marks.length) {
      view.caption.textContent = `The Attacker sends ${words(cycle.attacks.length, "attack", "attacks")} at the detector.`;
      await volley(marks, mine);
      if (mine !== token) return;
    } else {
      view.caption.textContent = "The Attacker sat this cycle out.";
    }
    renderRed(list, cycle.attacks);
    if (!(await wait(1200, mine))) return;
    view.caption.textContent = cycle.patch ? `The Defender patches the detector: ${patchText(cycle.patch)}.` : "The Defender sat this cycle out.";
    if (rules.after != null && before != null && rules.after > before) await growSlots(before, rules.after, mine);
    else lightSlots(rules.after || 0);
    if (mine !== token) return;
    renderBlue(cycle);
    if (!(await wait(800, mine))) return;
    const [decision, , sentence] = verdict(cycle.judge);
    view.caption.textContent = sentence;
    renderPurple(cycle);
    if (decision !== "none") ring("verdict-ring", C, C, 14);
    await animate(
      view.verdict,
      [
        { opacity: 0, transform: "scale(1.06)" },
        { opacity: 1, transform: "scale(1)" },
      ],
      420,
    );
    await wait(1800, mine);
  }

  async function drain() {
    if (playing) return;
    playing = true;
    // A replay starts a new generation; this loop then stops and leaves the queue to the new one.
    const mine = token;
    while (queue.length && mine === token) {
      if (queue.length > MAX_WAITING) queue.splice(0, queue.length - 1);
      await play(queue.shift());
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
        if (cycle.judge && cycle.judge.decision === "keep") kept += 1;
        markStrip(cycle);
        queue.push(cycle);
      }
      countTo(view.purpleTally, kept, (n) => `${Math.round(n)}/${cycles.size}`);
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
    kept = 0;
    view.strip.replaceChildren();
    for (const group of [view.marks, view.notches, view.fx, ...Object.values(view.orbits), view.redList]) group.replaceChildren();
    view.core.removeAttribute("data-hit");
    lightSlots(0);
    for (const element of [view.redTally, view.blueTally, view.purpleTally, view.tprValue, view.asrValue]) element.textContent = "-";
    view.tprFill.style.width = "0";
    view.asrFill.style.width = "0";
    view.redNote.textContent = "No attacks yet.";
    view.blueNote.textContent = "No detector yet.";
    view.redNote.hidden = false;
    view.title.textContent = "Waiting for the first cycle";
    view.focus.textContent = "";
    view.caption.textContent = "Start a run and each finished cycle plays here.";
  }

  buildSweep();
  buildSlots(DEFAULT_SLOTS);
  document.addEventListener("feed:event", poll);
  document.addEventListener("feed:status", (event) => {
    // A new run database replaced the old one: start the arena again from its first cycle.
    if (event.detail === "reset") resetAll();
  });
  setInterval(poll, POLL_MS);
  poll();
})();
