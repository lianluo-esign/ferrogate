import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { ThemeSwitcher } from "@/components/theme-switcher";
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

export default function RegisterPage() {
  const { register } = useAuth();
  const navigate = useNavigate();
  const [organizationName, setOrganizationName] = useState("");
  const [displayName, setDisplayName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const errorRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  async function onSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await register({
        organization_name: organizationName,
        email,
        password,
        display_name: displayName || undefined,
      });
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Registration failed");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="relative min-h-svh bg-background">
      <div className="absolute right-4 top-4 z-10">
        <ThemeSwitcher />
      </div>
      <main className="flex min-h-svh flex-col items-center justify-center gap-6 p-6">
        <div className="w-full max-w-sm">
        <Card>
          <CardHeader className="text-center">
            <h1 className="text-xl font-semibold leading-none">Create your organization</h1>
            <CardDescription>
              Sets up a new tenant with you as the owner
            </CardDescription>
          </CardHeader>
          <form onSubmit={onSubmit} aria-describedby={error ? "register-error" : undefined}>
            <CardContent className="flex flex-col gap-4">
              <div className="grid gap-2">
                <Label htmlFor="organization_name">Organization name</Label>
                <Input
                  id="organization_name"
                  name="organization_name"
                  autoComplete="organization"
                  spellCheck={false}
                  placeholder="Acme Inc."
                  required
                  value={organizationName}
                  onChange={(event) => setOrganizationName(event.target.value)}
                />
              </div>
              <div className="grid gap-2">
                <Label htmlFor="display_name">Your name (optional)</Label>
                <Input
                  id="display_name"
                  name="display_name"
                  autoComplete="name"
                  placeholder="Jane Doe"
                  value={displayName}
                  onChange={(event) => setDisplayName(event.target.value)}
                />
              </div>
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
                  autoComplete="new-password"
                  required
                  minLength={8}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
              </div>
              {error ? (
                <AsyncStatus id="register-error" ref={errorRef} tone="error">
                  {error}
                </AsyncStatus>
              ) : null}
            </CardContent>
            <CardFooter className="flex flex-col gap-4">
              <Button type="submit" className="w-full" disabled={submitting}>
                {submitting ? "Creating…" : "Create organization"}
              </Button>
              <p className="text-center text-sm text-muted-foreground">
                Already have an account?{" "}
                <Link to="/login" className="underline underline-offset-4">
                  Sign in
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
