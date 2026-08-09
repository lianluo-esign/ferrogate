import { ThemeSwitcher } from "@/components/theme-switcher";
import { AsyncStatus } from "@/components/ui/async-status";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useAuth } from "@/hooks/use-auth";
import { LanguageSwitcher } from "@/i18n";
import { useI18n } from "@/i18n";
import { ApiError } from "@/types/auth";
import { useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate } from "react-router-dom";

export default function LoginPage() {
  const { t } = useI18n();
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
      setError(err instanceof ApiError ? err.message : t("auth.login.error"));
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
              <h1 className="text-xl font-semibold leading-none">{t("common.appName")}</h1>
              <CardDescription>{t("auth.login.subtitle")}</CardDescription>
            </CardHeader>
            <form onSubmit={onSubmit} aria-describedby={error ? "login-error" : undefined}>
              <CardContent className="flex flex-col gap-4">
                <div className="grid gap-2">
                  <Label htmlFor="email">{t("auth.field.email")}</Label>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    inputMode="email"
                    spellCheck={false}
                    // eslint-disable-next-line ferrogate/no-untranslated-literal -- illustrative email format, not translated copy (#380)
                    placeholder="you@example.com"
                    autoComplete="email"
                    required
                    value={email}
                    onChange={(event) => setEmail(event.target.value)}
                  />
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="password">{t("auth.field.password")}</Label>
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
                  {submitting ? t("auth.login.submitting") : t("auth.login.submit")}
                </Button>
                <p className="text-center text-sm text-muted-foreground">
                  {t("auth.login.registerPrompt")}{" "}
                  <Link to="/register" className="underline underline-offset-4">
                    {t("auth.login.registerLink")}
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
