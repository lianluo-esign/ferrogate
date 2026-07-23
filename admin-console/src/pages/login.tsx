import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { LanguageSwitcher } from "@/i18n";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
} from "@/components/ui/card";
import { AsyncStatus } from "@/components/ui/async-status";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import { ApiError } from "@/types/auth";

export default function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const errorRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  const from = (location.state as { from?: string } | null)?.from ?? "/";

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login({ email, password });
      navigate(from, { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative min-h-svh bg-background">
      <div className="absolute right-4 top-4 z-10 flex items-center gap-1">
        <LanguageSwitcher />
        <ThemeSwitcher />
      </div>
      <main className="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
        <div className="w-full max-w-sm">
        <Card>
          <CardHeader className="text-center">
            <h1 className="text-xl font-semibold leading-none">FerroGate Admin Console</h1>
            <CardDescription>Sign in to manage your workspace</CardDescription>
          </CardHeader>
          <form onSubmit={onSubmit} aria-describedby={error ? "login-error" : undefined}>
            <CardContent className="flex flex-col gap-4">
              <div className="grid gap-2">
                <Label htmlFor="email">Email</Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  inputMode="email"
                  spellCheck={false}
                  placeholder="you@example.com"
                  autoComplete="email"
                  required
                  value={email}
                  onChange={(event) => setEmail(event.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="password">Password</Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              {error ? (
                <AsyncStatus id="login-error" ref={errorRef} tone="error">
                  {error}
                </AsyncStatus>
              ) : null}
            </CardContent>
            <CardFooter className="flex flex-col gap-4">
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Signing in…" : "Sign in"}
              </Button>
              <p className="text-center text-sm text-muted-foreground">
                Don&apos;t have an organization yet?{" "}
                <Link to="/register" className="underline underline-offset-4">
                  Register
                </Link>
              </p>
            </CardFooter>
          </form>
        </Card>
        </div>
      </main>
    </div>
  );
}
