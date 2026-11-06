import type { Ref } from "react";
import { CobryptWordmark } from "./CobryptWordmark";

interface BrandProps {
  interactive?: boolean;
  eyeRef?: Ref<HTMLSpanElement>;
}

export function Brand({ interactive = false, eyeRef }: BrandProps) {
  return (
    <div className="brand">
      <CobryptWordmark eyeRef={eyeRef} interactive={interactive} />
    </div>
  );
}
