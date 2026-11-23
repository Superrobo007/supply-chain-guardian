import * as Dialog from "@radix-ui/react-dialog";
import * as TabsP from "@radix-ui/react-tabs";
import * as TooltipP from "@radix-ui/react-tooltip";
import { cva, type VariantProps } from "class-variance-authority";
import { X } from "lucide-react";
import type { ButtonHTMLAttributes, HTMLAttributes, InputHTMLAttributes, ReactNode } from "react";
import type { Priority } from "../lib/api";
import { cn, prioClass } from "../lib/utils";

export function Card({ className, ...p }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn("rounded-xl border border-line bg-panel shadow-[0_1px_2px_rgba(16,24,40,.04)]", className)} {...p} />;
}
export function CardHeader({ title, sub, right }: { title: ReactNode; sub?: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-line px-5 py-3.5">
      <div className="min-w-0">
        <h3 className="text-[15px] font-semibold tracking-tight">{title}</h3>
        {sub && <p className="mt-0.5 text-[13px] text-ink-3">{sub}</p>}
      </div>
      {right}
    </div>
  );
}

const button = cva(
  "inline-flex items-center justify-center gap-1.5 whitespace-nowrap rounded-lg text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand/40 disabled:pointer-events-none disabled:opacity-50",
  {
    variants: {
      variant: {
        primary: "bg-brand text-white hover:bg-indigo-700 shadow-sm",
        secondary: "border border-line bg-white text-ink hover:bg-slate-50",
        ghost: "text-ink-2 hover:bg-slate-100",
        human: "bg-human text-white hover:bg-amber-700 shadow-sm",
        danger: "bg-crit text-white hover:bg-rose-700",
      },
      size: { sm: "h-8 px-3", md: "h-9 px-4", lg: "h-10 px-5" },
    },
    defaultVariants: { variant: "secondary", size: "md" },
  },
);
export function Button({ className, variant, size, ...p }: ButtonHTMLAttributes<HTMLButtonElement> & VariantProps<typeof button>) {
  return <button className={cn(button({ variant, size }), className)} {...p} />;
}

export function Input({ className, ...p }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn("h-9 w-full rounded-lg border border-line bg-white px-3 text-sm outline-none placeholder:text-ink-3 focus:border-brand focus:ring-2 focus:ring-brand/15", className)} {...p} />;
}

export function Badge({ className, children }: { className?: string; children: ReactNode }) {
  return <span className={cn("inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-[11.5px] font-medium ring-1 ring-inset whitespace-nowrap", className)}>{children}</span>;
}
export function PriorityBadge({ p }: { p: Priority }) {
  return <Badge className={prioClass[p]}><span className="size-1.5 rounded-full" style={{ background: "currentColor" }} />{p}</Badge>;
}

export function Sheet({ open, onOpenChange, title, sub, children, wide }: {
  open: boolean; onOpenChange: (o: boolean) => void; title: ReactNode; sub?: ReactNode; children: ReactNode; wide?: boolean;
}) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-slate-900/20 backdrop-blur-[1px]" />
        <Dialog.Content className={cn("fixed inset-y-0 right-0 z-50 flex w-full flex-col border-l border-line bg-ground shadow-2xl outline-none", wide ? "max-w-[880px]" : "max-w-[720px]")}>
          <div className="flex items-start justify-between gap-4 border-b border-line bg-white px-6 py-4">
            <div className="min-w-0">
              <Dialog.Title className="text-lg font-semibold tracking-tight">{title}</Dialog.Title>
              {sub ? <Dialog.Description asChild><div className="mt-1 text-sm text-ink-3">{sub}</div></Dialog.Description>
                : <Dialog.Description className="sr-only">Details</Dialog.Description>}
            </div>
            <Dialog.Close className="rounded-md p-1.5 text-ink-3 hover:bg-slate-100 hover:text-ink" aria-label="Close"><X className="size-5" /></Dialog.Close>
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto px-6 py-5">{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export const Tabs = TabsP.Root;
export function TabsList({ children }: { children: ReactNode }) {
  return <TabsP.List className="inline-flex gap-1 rounded-lg bg-slate-100 p-1">{children}</TabsP.List>;
}
export function TabsTrigger({ value, children }: { value: string; children: ReactNode }) {
  return <TabsP.Trigger value={value} className="rounded-md px-3 py-1.5 text-sm font-medium text-ink-2 data-[state=active]:bg-white data-[state=active]:text-ink data-[state=active]:shadow-sm">{children}</TabsP.Trigger>;
}
export const TabsContent = ({ value, children }: { value: string; children: ReactNode }) =>
  <TabsP.Content value={value} className="mt-4 outline-none">{children}</TabsP.Content>;

export function Tip({ label, children }: { label: ReactNode; children: ReactNode }) {
  return (
    <TooltipP.Root delayDuration={150}>
      <TooltipP.Trigger asChild>{children}</TooltipP.Trigger>
      <TooltipP.Portal>
        <TooltipP.Content sideOffset={6} className="z-50 max-w-xs rounded-md bg-ink px-2.5 py-1.5 text-xs text-white shadow-lg">{label}</TooltipP.Content>
      </TooltipP.Portal>
    </TooltipP.Root>
  );
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 px-6 py-14 text-center">
      <div className="rounded-full bg-brand-soft p-3 text-brand">{icon}</div>
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-md text-sm text-ink-3">{children}</div>}
    </div>
  );
}

export function Mono({ children, className }: { children: ReactNode; className?: string }) {
  return <code className={cn("rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[12px] text-ink", className)}>{children}</code>;
}
