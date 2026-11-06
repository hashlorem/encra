import { forwardRef, useEffect, useImperativeHandle, useRef } from "react";

interface SnakeEyeProps {
  className?: string;
  closed?: boolean;
  interactive?: boolean;
  label?: string;
}

export const SnakeEye = forwardRef<HTMLSpanElement, SnakeEyeProps>(
  ({ className = "", closed = false, interactive = false, label }, ref) => {
    const eyeRef = useRef<HTMLSpanElement>(null);
    const frameRef = useRef<number | null>(null);
    const targetRef = useRef({ x: 0, y: 0 });
    const positionRef = useRef({ x: 0, y: 0 });
    const velocityRef = useRef({ x: 0, y: 0 });
    const reducedMotionRef = useRef(false);

    // No dependency array previously meant the handle was rebuilt on every
    // render; an empty one publishes it once, after the DOM ref is attached.
    useImperativeHandle(ref, () => eyeRef.current as HTMLSpanElement, []);

    useEffect(() => {
      if (!interactive) return;

      const applyTransform = () => {
        const focus = eyeRef.current?.querySelector<SVGGElement>(".snake-eye-focus");
        const position = positionRef.current;
        focus?.style.setProperty(
          "transform",
          `translate(${position.x.toFixed(3)}px, ${position.y.toFixed(3)}px)`,
        );
      };

      const render = () => {
        const position = positionRef.current;
        const target = targetRef.current;
        const velocity = velocityRef.current;

        if (reducedMotionRef.current) {
          position.x = target.x;
          position.y = target.y;
        } else {
          velocity.x = (velocity.x + (target.x - position.x) * 0.15) * 0.7;
          velocity.y = (velocity.y + (target.y - position.y) * 0.15) * 0.7;
          position.x += velocity.x;
          position.y += velocity.y;
        }

        applyTransform();

        const settled =
          Math.abs(target.x - position.x) < 0.01 &&
          Math.abs(target.y - position.y) < 0.01 &&
          Math.abs(velocity.x) < 0.01 &&
          Math.abs(velocity.y) < 0.01;

        if (settled || reducedMotionRef.current) {
          velocity.x = 0;
          velocity.y = 0;
          frameRef.current = null;
          return;
        }

        frameRef.current = requestAnimationFrame(render);
      };

      const start = () => {
        if (frameRef.current === null) frameRef.current = requestAnimationFrame(render);
      };

      const track = (event: PointerEvent) => {
        const bounds = eyeRef.current?.getBoundingClientRect();
        if (!bounds) return;
        const deltaX = event.clientX - (bounds.left + bounds.width / 2);
        const deltaY = event.clientY - (bounds.top + bounds.height / 2);
        const distance = Math.max(1, Math.hypot(deltaX, deltaY));
        const travel = Math.min(7.5, distance / 45);
        targetRef.current.x = (deltaX / distance) * travel;
        targetRef.current.y = (deltaY / distance) * travel;

        // Under reduced motion there is nothing to animate, so move the iris
        // straight to the target instead of scheduling a frame per event.
        if (reducedMotionRef.current) {
          positionRef.current.x = targetRef.current.x;
          positionRef.current.y = targetRef.current.y;
          applyTransform();
          return;
        }
        start();
      };

      const center = () => {
        targetRef.current.x = 0;
        targetRef.current.y = 0;
        if (reducedMotionRef.current) {
          positionRef.current.x = 0;
          positionRef.current.y = 0;
          applyTransform();
          return;
        }
        start();
      };

      // Re-read the OS preference on change instead of only at mount.
      const motionQuery = window.matchMedia("(prefers-reduced-motion: reduce)");
      reducedMotionRef.current = motionQuery.matches;
      const handleMotionChange = () => {
        reducedMotionRef.current = motionQuery.matches;
        if (reducedMotionRef.current) {
          positionRef.current.x = targetRef.current.x;
          positionRef.current.y = targetRef.current.y;
          velocityRef.current.x = 0;
          velocityRef.current.y = 0;
          applyTransform();
        }
      };
      motionQuery.addEventListener("change", handleMotionChange);

      window.addEventListener("pointermove", track, { passive: true });
      window.addEventListener("blur", center);
      return () => {
        motionQuery.removeEventListener("change", handleMotionChange);
        window.removeEventListener("pointermove", track);
        window.removeEventListener("blur", center);
        if (frameRef.current !== null) cancelAnimationFrame(frameRef.current);
        frameRef.current = null;
      };
    }, [interactive]);

    return (
      <span
        ref={eyeRef}
        className={`snake-eye${closed ? " snake-eye-closed" : ""}${interactive ? " snake-eye-interactive" : ""}${className ? ` ${className}` : ""}`}
        aria-hidden={label ? undefined : true}
        aria-label={label}
        role={label ? "img" : undefined}
      >
        <svg viewBox="0 0 120 120" fill="none">
          <path className="snake-eye-shadow" d="M8 60C27 24 45 15 60 15s33 9 52 45c-19 36-37 45-52 45S27 96 8 60Z" />
          <path className="snake-eye-lid" d="M8 60C29 34 43 27 60 27s31 7 52 33c-21 26-35 33-52 33S29 86 8 60Z" />
          <path className="snake-eye-rim snake-eye-rim-top" d="M8 60C29 25 46 18 60 18s31 7 52 42" />
          <path className="snake-eye-rim snake-eye-rim-bottom" d="M8 60c21 35 38 42 52 42s31-7 52-42" />
          <g className="snake-eye-focus">
            <circle className="snake-eye-iris-ring" cx="60" cy="60" r="28" />
            <circle className="snake-eye-iris" cx="60" cy="60" r="22" />
            <path className="snake-eye-iris-detail" d="M60 38 55 51l-12-5 9 11-12 3 12 3-9 11 12-5 5 13 5-13 12 5-9-11 12-3-12-3 9-11-12 5Z" />
            <ellipse className="snake-eye-pupil" cx="60" cy="60" rx="5.2" ry="19" />
            <ellipse className="snake-eye-glint" cx="54" cy="49" rx="3" ry="5" />
          </g>
          <g className="snake-eye-blink" aria-hidden="true">
            <path className="snake-eye-blink-upper" d="M8 60C29 25 46 18 60 18s31 7 52 42" />
            <path className="snake-eye-blink-lower" d="M8 60c21 35 38 42 52 42s31-7 52-42" />
            <path className="snake-eye-blink-seam" d="M10 60c25 10 75 10 100 0" />
          </g>
        </svg>
      </span>
    );
  }
);

SnakeEye.displayName = "SnakeEye";
