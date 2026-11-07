import { getCurrentWindow, LogicalSize } from "@tauri-apps/api/window";

const LOCKED_SIZE = { width: 700, height: 720 };
const WORKSPACE_SIZE = { width: 1180, height: 760 };
const ANIMATION_STEPS = 16;

let activeAnimation = 0;

const nextFrame = () => new Promise<void>((resolve) => requestAnimationFrame(() => resolve()));

function isTauriRuntime() {
  return Object.prototype.hasOwnProperty.call(globalThis, "__TAURI_INTERNALS__");
}

function prefersReducedMotion() {
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Animate the native window between the fixed lock size and the workspace size.
 *
 * `resizable` is tied to the mode: the lock screen is a fixed panel, while the
 * workspace is a normal window. Previously the window was pinned non-resizable
 * and nothing ever restored it, so after the first unlock the user could never
 * resize Encra again.
 */
export async function animateWindowMode(unlocked: boolean, animated = true) {
  if (!isTauriRuntime()) return;

  const animationId = ++activeAnimation;
  const target = unlocked ? WORKSPACE_SIZE : LOCKED_SIZE;
  const appWindow = getCurrentWindow();

  try {
    if (!animated || prefersReducedMotion()) {
      await appWindow.setSize(new LogicalSize(target.width, target.height));
      await appWindow.center();
      await appWindow.setResizable(unlocked);
      return;
    }

    await appWindow.setResizable(false);

    const scaleFactor = await appWindow.scaleFactor();
    const current = (await appWindow.innerSize()).toLogical(scaleFactor);

    for (let step = 1; step <= ANIMATION_STEPS; step += 1) {
      if (animationId !== activeAnimation) return;

      const progress = step / ANIMATION_STEPS;
      const eased = 1 - Math.pow(1 - progress, 3);
      const width = Math.round(current.width + (target.width - current.width) * eased);
      const height = Math.round(current.height + (target.height - current.height) * eased);

      await appWindow.setSize(new LogicalSize(width, height));
      await appWindow.center();
      await nextFrame();
    }

    if (animationId === activeAnimation) {
      await appWindow.setSize(new LogicalSize(target.width, target.height));
      await appWindow.center();
      await appWindow.setResizable(unlocked);
    }
  } catch (error) {
    console.error("Unable to update the Encra window geometry", error);
  }
}
