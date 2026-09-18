import { AcceptInvitationForm } from "./accept-invitation-form";

export default async function AcceptInvitationPage({
  searchParams,
}: {
  searchParams: Promise<{ token?: string }>;
}) {
  const token = (await searchParams).token ?? "";
  return <AcceptInvitationForm token={token} />;
}
