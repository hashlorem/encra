import type { ReactNode, SVGProps } from "react";

export type IconName =
  | "activity"
  | "arrow-left"
  | "book"
  | "check"
  | "chevron-right"
  | "clipboard"
  | "command"
  | "copy"
  | "download"
  | "eye"
  | "eye-off"
  | "file"
  | "fingerprint"
  | "folder"
  | "globe"
  | "key"
  | "lock"
  | "moon"
  | "more"
  | "network"
  | "plus"
  | "refresh"
  | "search"
  | "settings"
  | "shield"
  | "sparkles"
  | "sun"
  | "terminal"
  | "trash"
  | "upload"
  | "user"
  | "wand"
  | "x";

const paths: Record<IconName, ReactNode> = {
  activity: <><path d="M3 12h4l2.2-6 4.2 12 2.2-6H21" /></>,
  "arrow-left": <><path d="m15 18-6-6 6-6" /></>,
  book: <><path d="M4 19.5A2.5 2.5 0 0 1 6.5 17H20" /><path d="M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2Z" /></>,
  check: <path d="m5 12 4 4L19 6" />,
  "chevron-right": <path d="m9 18 6-6-6-6" />,
  clipboard: <><rect width="14" height="18" x="5" y="3" rx="2" /><path d="M9 3V1.8h6V3M9 8h6M9 12h6M9 16h4" /></>,
  command: <><path d="M18 9a3 3 0 1 0-3-3v12a3 3 0 1 0 3-3H6a3 3 0 1 0 3 3V6a3 3 0 1 0-3 3Z" /></>,
  copy: <><rect width="13" height="13" x="9" y="9" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" /></>,
  download: <><path d="M12 3v12m0 0 4-4m-4 4-4-4" /><path d="M5 21h14" /></>,
  eye: <><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z" /><circle cx="12" cy="12" r="2.5" /></>,
  "eye-off": <><path d="m3 3 18 18" /><path d="M10.6 6.2A10.7 10.7 0 0 1 12 6c6.5 0 10 6 10 6a17 17 0 0 1-2.1 2.8M6.6 6.6C3.6 8.3 2 12 2 12s3.5 6 10 6a10 10 0 0 0 4.1-.8" /></>,
  file: <><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z" /><path d="M14 2v6h6M8 13h8M8 17h5" /></>,
  fingerprint: <><path d="M12 11a2 2 0 0 1 2 2c0 3-.6 5.6-1.5 7.5" /><path d="M8.2 21A18 18 0 0 0 10 13a2 2 0 0 1 4 0c0 2.2.4 4.3 1.2 6.2" /><path d="M5 18a21 21 0 0 0 1-5 6 6 0 0 1 12 0c0 1 .1 2 .3 3" /><path d="M4 10a8.2 8.2 0 0 1 16 3" /><path d="M7 4.8A10 10 0 0 1 22 13" /></>,
  folder: <><path d="M3 5h6l2 2h10v12H3Z" /></>,
  globe: <><circle cx="12" cy="12" r="9" /><path d="M3 12h18M12 3c2.5 2.7 3.6 5.7 3.6 9S14.5 18.3 12 21c-2.5-2.7-3.6-5.7-3.6-9S9.5 5.7 12 3Z" /></>,
  key: <><circle cx="7.5" cy="15.5" r="4.5" /><path d="m11 12 9-9m-3 3 3 3m-6 0 3 3" /></>,
  lock: <><rect width="16" height="12" x="4" y="10" rx="3" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v4" /></>,
  moon: <path d="M20.6 15.8A9 9 0 0 1 8.2 3.4a9 9 0 1 0 12.4 12.4Z" />,
  more: <><circle cx="5" cy="12" r="1" fill="currentColor" stroke="none" /><circle cx="12" cy="12" r="1" fill="currentColor" stroke="none" /><circle cx="19" cy="12" r="1" fill="currentColor" stroke="none" /></>,
  network: <><rect width="6" height="6" x="9" y="3" rx="1" /><rect width="6" height="6" x="3" y="15" rx="1" /><rect width="6" height="6" x="15" y="15" rx="1" /><path d="M12 9v3m0 0H6v3m6-3h6v3" /></>,
  plus: <path d="M12 5v14M5 12h14" />,
  refresh: <><path d="M20 7v5h-5" /><path d="M4 17v-5h5" /><path d="M6.1 8A7 7 0 0 1 18.8 6L20 8M4 16l1.2 2A7 7 0 0 0 18 16" /></>,
  search: <><circle cx="11" cy="11" r="7" /><path d="m20 20-4-4" /></>,
  settings: <><circle cx="12" cy="12" r="3" /><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1-2.8 2.8-.1-.1a1.7 1.7 0 0 0-1.9-.3 1.7 1.7 0 0 0-1 1.6v.2h-4V21a1.7 1.7 0 0 0-1-1.6 1.7 1.7 0 0 0-1.9.3l-.1.1L4.2 17l.1-.1a1.7 1.7 0 0 0 .3-1.9A1.7 1.7 0 0 0 3 14H2.8v-4H3a1.7 1.7 0 0 0 1.6-1 1.7 1.7 0 0 0-.3-1.9L4.2 7 7 4.2l.1.1A1.7 1.7 0 0 0 9 4.6 1.7 1.7 0 0 0 10 3v-.2h4V3a1.7 1.7 0 0 0 1 1.6 1.7 1.7 0 0 0 1.9-.3l.1-.1L19.8 7l-.1.1a1.7 1.7 0 0 0-.3 1.9 1.7 1.7 0 0 0 1.6 1h.2v4H21a1.7 1.7 0 0 0-1.6 1Z" /></>,
  shield: <><path d="M12 2 4.5 5v6.5c0 4.5 3 8.5 7.5 10.5 4.5-2 7.5-6 7.5-10.5V5Z" /><path d="m8.5 12 2.2 2.2 4.8-5" /></>,
  sparkles: <><path d="m12 3-1.2 3.2L7.5 7.5l3.3 1.3L12 12l1.2-3.2 3.3-1.3-3.3-1.3Z" /><path d="m5 14-.8 2.2L2 17l2.2.8L5 20l.8-2.2L8 17l-2.2-.8ZM19 13l-.6 1.4L17 15l1.4.6L19 17l.6-1.4L21 15l-1.4-.6Z" /></>,
  sun: <><circle cx="12" cy="12" r="4" /><path d="M12 2v2m0 16v2M4.9 4.9l1.4 1.4m11.4 11.4 1.4 1.4M2 12h2m16 0h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>,
  terminal: <><rect width="20" height="16" x="2" y="4" rx="3" /><path d="m6 9 3 3-3 3m6 0h5" /></>,
  trash: <><path d="M4 7h16M9 7V4h6v3m3 0-1 14H7L6 7m4 4v6m4-6v6" /></>,
  upload: <><path d="M12 16V4m0 0L8 8m4-4 4 4" /><path d="M5 20h14" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21a8 8 0 0 1 16 0" /></>,
  wand: <><path d="m15 4 5 5L8 21l-5-5Z" /><path d="m6 14 5 5M6 3v3M4.5 4.5h3M18 15v4m-2-2h4" /></>,
  x: <path d="M6 6l12 12M18 6 6 18" />,
};

interface IconProps extends Omit<SVGProps<SVGSVGElement>, "children"> {
  name: IconName;
  size?: number;
  /** Accessible name. Required when the icon is the only content of a control. */
  label?: string;
}

export function Icon({ name, size = 18, label, ...props }: IconProps) {
  const labelled = label !== undefined;
  return (
    <svg
      {...props}
      aria-hidden={labelled ? undefined : true}
      aria-label={label}
      role={labelled ? "img" : undefined}
      fill="none"
      height={size}
      viewBox="0 0 24 24"
      width={size}
      stroke="currentColor"
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth="1.8"
    >
      {paths[name]}
    </svg>
  );
}
