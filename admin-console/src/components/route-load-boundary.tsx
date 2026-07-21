import { Component, Suspense, type ErrorInfo, type ReactNode } from "react";
import { RotateCw } from "lucide-react";
import { Button } from "@/components/ui/button";

export function RouteLoading() {
  return (
    <div
      role="status"
      aria-live="polite"
      aria-busy="true"
      className="flex min-h-48 items-center justify-center text-sm text-muted-foreground"
    >
      Loading page…
    </div>
  );
}

interface RouteLoadErrorBoundaryProps {
  children: ReactNode;
  onReload?: () => void;
}

interface RouteLoadErrorBoundaryState {
  error: Error | null;
}

export class RouteLoadErrorBoundary extends Component<
  RouteLoadErrorBoundaryProps,
  RouteLoadErrorBoundaryState
> {
  state: RouteLoadErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): RouteLoadErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("Route module failed to load", error, info.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div className="flex min-h-48 flex-col items-start justify-center gap-3">
        <h1 className="text-lg font-semibold">Page failed to load</h1>
        <p role="alert" className="text-sm text-destructive">
          The page module could not be downloaded. Check the connection and reload.
        </p>
        <Button
          type="button"
          onClick={this.props.onReload ?? (() => window.location.reload())}
        >
          <RotateCw className="size-4" aria-hidden="true" />
          Reload page
        </Button>
      </div>
    );
  }
}

export function RouteLoadBoundary({ children }: { children: ReactNode }) {
  return (
    <RouteLoadErrorBoundary>
      <Suspense fallback={<RouteLoading />}>{children}</Suspense>
    </RouteLoadErrorBoundary>
  );
}
