import { cn } from "@/lib/utils";
import * as React from "react";

interface AsyncStatusProps extends React.HTMLAttributes<HTMLParagraphElement> {
  tone?: "muted" | "error";
}

const AsyncStatus = React.forwardRef<HTMLParagraphElement, AsyncStatusProps>(
  ({ className, tone = "muted", ...props }, ref) => (
    <p
      ref={ref}
      role={tone === "error" ? "alert" : "status"}
      aria-live={tone === "error" ? "assertive" : "polite"}
      tabIndex={tone === "error" ? -1 : undefined}
      className={cn(
        tone === "error"
          ? "rounded-md border border-destructive/50 bg-destructive/10 px-3 py-2 text-sm text-destructive focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          : "text-sm text-muted-foreground",
        className,
      )}
      {...props}
    />
  ),
);
AsyncStatus.displayName = "AsyncStatus";

export { AsyncStatus };
