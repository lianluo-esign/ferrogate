import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { NAV_GROUPS } from "@/components/layout/nav-config";
import { useAuth } from "@/hooks/use-auth";

export default function DashboardPage() {
  const { session } = useAuth();

  return (
    <div className="flex flex-col gap-6">
      <div>
        <h1 className="text-2xl font-semibold">
          Welcome{session ? `, ${session.user.display_name || session.user.email}` : ""}
        </h1>
        <p className="text-muted-foreground">
          Managing <span className="font-medium">{session?.tenant.name}</span>{" "}
          as <span className="font-medium">{session?.tenant.role}</span>
        </p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {NAV_GROUPS.flatMap((group) => group.items).map((item) => (
          <Card key={item.url}>
            <CardHeader>
              <CardTitle className="text-base">{item.title}</CardTitle>
              <CardDescription>Manage {item.title.toLowerCase()}</CardDescription>
            </CardHeader>
            <CardContent>
              <a href={item.url} className="text-sm text-primary underline-offset-4 hover:underline">
                Open
              </a>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
