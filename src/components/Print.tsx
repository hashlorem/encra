interface PrintProps {
  kind: "whorl" | "loop" | "arch";
  className?: string;
}

/**
 * A synthetic fingerprint, drawn as a mask over the ink colour so it follows
 * the theme. Decorative: the meaning ("sealed") is always also said in text.
 */
export function Print({ kind, className = "" }: PrintProps) {
  return <span className={`print print-${kind} ${className}`} aria-hidden="true" />;
}
