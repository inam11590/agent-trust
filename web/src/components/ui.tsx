import { AlertCircle, Inbox, LoaderCircle } from "lucide-react";
import Link from "next/link";

export function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-[-0.025em] text-slate-950">{title}</h1>
        {description && <p className="mt-1 text-sm leading-6 text-slate-500">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function PrimaryLink({ href, children }: { href: string; children: React.ReactNode }) {
  return (
    <Link href={href} className="inline-flex h-10 items-center justify-center rounded-lg bg-[#3157d5] px-4 text-sm font-semibold text-white shadow-sm transition hover:bg-[#2949b7]">
      {children}
    </Link>
  );
}

export function LoadingState({ label = "Loading" }: { label?: string }) {
  return (
    <div className="flex min-h-48 items-center justify-center gap-3 rounded-xl border border-slate-200 bg-white text-sm text-slate-500">
      <LoaderCircle className="animate-spin" size={18} /> {label}…
    </div>
  );
}

export function ErrorState({ message, retry }: { message: string; retry?: () => void }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-xl border border-red-100 bg-red-50/60 px-6 text-center">
      <AlertCircle className="mb-3 text-red-500" size={24} />
      <p className="text-sm font-medium text-red-800">{message}</p>
      {retry && <button onClick={retry} className="mt-4 text-sm font-semibold text-red-700 underline">Try again</button>}
    </div>
  );
}

export function EmptyState({ title, description }: { title: string; description: string }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-xl border border-dashed border-slate-300 bg-white px-6 text-center">
      <Inbox className="mb-3 text-slate-400" size={25} />
      <p className="font-semibold text-slate-800">{title}</p>
      <p className="mt-1 max-w-md text-sm text-slate-500">{description}</p>
    </div>
  );
}

export function StatusBadge({ value }: { value: string }) {
  const normalized = value.toUpperCase();
  const positive = normalized === "ACTIVE" || normalized === "APPROVED";
  const negative = normalized === "REJECTED" || normalized === "REVOKED";
  const classes = positive
    ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20"
    : negative
      ? "bg-red-50 text-red-700 ring-red-600/20"
      : "bg-amber-50 text-amber-700 ring-amber-600/20";
  return <span className={`inline-flex rounded-full px-2.5 py-1 text-[11px] font-bold tracking-wide ring-1 ring-inset ${classes}`}>{normalized}</span>;
}

export function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="block text-sm font-medium text-slate-700">
      {label}
      <span className="mt-1.5 block">{children}</span>
      {hint && <span className="mt-1.5 block text-xs font-normal text-slate-500">{hint}</span>}
    </label>
  );
}

export const inputClass = "h-11 w-full rounded-lg border border-slate-300 bg-white px-3.5 text-sm text-slate-950 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-[#3157d5] focus:ring-4 focus:ring-blue-100";
export const textareaClass = `${inputClass} h-28 resize-y py-3`;
export const buttonClass = "inline-flex h-11 items-center justify-center rounded-lg bg-[#3157d5] px-5 text-sm font-semibold text-white shadow-sm transition hover:bg-[#2949b7] disabled:cursor-not-allowed disabled:opacity-60";
export const secondaryButtonClass = "inline-flex h-10 items-center justify-center rounded-lg border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 shadow-sm transition hover:bg-slate-50 disabled:opacity-60";
