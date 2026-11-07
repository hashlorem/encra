import type { Ref } from "react";
import { SnakeEye } from "./SnakeEye";

interface CobryptWordmarkProps {
  className?: string;
  closed?: boolean;
  eyeRef?: Ref<HTMLSpanElement>;
  interactive?: boolean;
  variant?: "sidebar" | "lock";
}

export function CobryptWordmark({
  className = "",
  closed = false,
  eyeRef,
  interactive = false,
  variant = "sidebar",
}: CobryptWordmarkProps) {
  return (
    <span
      className={`cobrypt-wordmark cobrypt-wordmark-${variant}${className ? ` ${className}` : ""}`}
      role="img"
      aria-label="Encra"
    >
      <SnakeEye
        ref={eyeRef}
        className="cobrypt-wordmark-eye"
        closed={closed}
        interactive={interactive}
      />
      <span className="cobrypt-wordmark-text" aria-hidden="true">Encra</span>
    </span>
  );
}
