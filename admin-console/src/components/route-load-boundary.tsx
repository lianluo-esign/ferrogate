import { Button } from "@/components/ui/button";
import { useI18n } from "@/i18n";
import { RotateCw } from "lucide-react";
import { Component, type ErrorInfo, type ReactNode, Suspense } from "react";

export function RouteLoading() {
  const { t } = useI18n();
  return (
    <div
      // biome-ignore lint/a11y/useSemanticElements: ARIA live region for route-loading; the min-height/flex centering classes assume a div, which <output>'s inline default would break
      role="status"
      aria-live="polite"
      aria-busy="true"
      className="flex min-h-48 items-center justify-center text-sm text-muted-foreground"
    >
      {t("component.routeBoundary.loading")}
    </div>
  );
}

/**
 * Localized error fallback. Extracted from the class boundary below so it can
 * read the catalog through `useI18n()` — a class component cannot call hooks,
 * and the provider always sits above the boundary (see `App.tsx`).
 */
function RouteLoadErrorFallback({ onReload }: { onReload: () => void }) {
  const { t } = useI18n();
  return (
    <div className="flex min-h-48 flex-col items-start justify-center gap-3">
      <h1 className="text-lg font-semibold">{t("component.routeBoundary.errorTitle")}</h1>
      <p role="alert" className="text-sm text-destructive">
        {t("component.routeBoundary.errorBody")}
      </p>
      <Button type="button" onClick={onReload}>
        <RotateCw className="size-4" aria-hidden="true" />
        {t("component.routeBoundary.reload")}
      </Button>
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
      <RouteLoadErrorFallback onReload={this.props.onReload ?? (() => window.location.reload())} />
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
