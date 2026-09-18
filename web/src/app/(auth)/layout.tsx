import { Brand } from "@/components/brand";

export default function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <main className="grid min-h-screen lg:grid-cols-[1.05fr_0.95fr]">
      <section className="hidden bg-[#101b35] p-12 text-white lg:flex lg:flex-col lg:justify-between">
        <Brand />
        <div className="max-w-xl pb-12">
          <p className="mb-5 text-sm font-semibold uppercase tracking-[0.18em] text-blue-300">Permission infrastructure</p>
          <h1 className="text-5xl font-semibold leading-[1.08] tracking-[-0.04em]">Put every AI agent action inside clear boundaries.</h1>
          <p className="mt-6 max-w-lg text-lg leading-8 text-slate-300">Register agents, define limited permissions, and keep a permanent record of every authorization decision.</p>
        </div>
        <p className="text-xs text-slate-500">Secure by design · Owner-scoped data · Complete audit history</p>
      </section>
      <section className="flex min-h-screen items-center justify-center bg-white px-6 py-12 sm:px-10">
        <div className="w-full max-w-md">
          <div className="mb-10 lg:hidden"><Brand /></div>
          {children}
        </div>
      </section>
    </main>
  );
}
