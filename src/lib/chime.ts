let audioCtx: AudioContext | null = null;

/**
 * Lazily create the audio context and make sure it is running.
 *
 * A context created before any user gesture starts suspended, which is exactly
 * the situation for the unlock chime (fired on mount). Previously `resume()` was
 * never called, so the first chime silently did nothing and the failure was
 * swallowed by an empty catch.
 */
function ctx(): AudioContext | null {
  try {
    if (!audioCtx) {
      const Ctor =
        window.AudioContext ??
        (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (!Ctor) return null;
      audioCtx = new Ctor();
    }
    if (audioCtx.state === "suspended") void audioCtx.resume();
    return audioCtx;
  } catch {
    return null;
  }
}

export function playUnlockChime() {
  const c = ctx();
  if (!c) return;
  try {
    const now = c.currentTime;

    const gain = c.createGain();
    gain.connect(c.destination);
    gain.gain.setValueAtTime(0, now);
    gain.gain.linearRampToValueAtTime(0.14, now + 0.02);
    gain.gain.exponentialRampToValueAtTime(0.0001, now + 1.6);

    // Warm "ding" — medium pitch with slight detune for width
    const notes = [520, 524];
    notes.forEach((freq, index) => {
      const osc = c.createOscillator();
      osc.type = "sine";
      osc.frequency.value = freq;
      osc.connect(gain);
      osc.start(now);
      osc.stop(now + 1.7);
      if (index === notes.length - 1) {
        osc.onended = () => gain.disconnect();
      }
    });
  } catch {
    // Audio is a nicety; never let it break the lock/unlock flow.
  }
}

export function playLockChime() {
  const c = ctx();
  if (!c) return;
  try {
    const now = c.currentTime;

    // Low thud — sub hit for weight
    const thud = c.createGain();
    thud.connect(c.destination);
    thud.gain.setValueAtTime(0, now);
    thud.gain.linearRampToValueAtTime(0.15, now + 0.01);
    thud.gain.exponentialRampToValueAtTime(0.0001, now + 0.35);

    const sub = c.createOscillator();
    sub.type = "sine";
    sub.frequency.setValueAtTime(120, now);
    sub.frequency.linearRampToValueAtTime(55, now + 0.25);
    sub.connect(thud);
    sub.start(now);
    sub.stop(now + 0.4);
    sub.onended = () => thud.disconnect();

    // High click for the "lock engaging" feel
    const click = c.createGain();
    click.connect(c.destination);
    click.gain.setValueAtTime(0, now + 0.05);
    click.gain.linearRampToValueAtTime(0.06, now + 0.06);
    click.gain.exponentialRampToValueAtTime(0.0001, now + 0.25);

    const clicks = [1800, 2400];
    clicks.forEach((freq, index) => {
      const osc = c.createOscillator();
      osc.type = "sine";
      osc.frequency.value = freq;
      osc.connect(click);
      osc.start(now + 0.05);
      osc.stop(now + 0.3);
      if (index === clicks.length - 1) {
        osc.onended = () => click.disconnect();
      }
    });
  } catch {
    // Audio is a nicety; never let it break the lock/unlock flow.
  }
}
