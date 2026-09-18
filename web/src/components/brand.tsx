import { ShieldCheck } from "lucide-react";
import Link from "next/link";

export function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link href="/dashboard" className="inline-flex items-center gap-3" aria-label="AgentTrust home">
      <span className="grid size-10 place-items-center rounded-xl bg-[#3157d5] text-white shadow-sm">
        <ShieldCheck size={22} strokeWidth={2.2} />
      </span>
      {!compact && (
        <span className="text-[19px] font-semibold tracking-[-0.02em] text-white">AgentTrust</span>
      )}
    </Link>
  );
}
