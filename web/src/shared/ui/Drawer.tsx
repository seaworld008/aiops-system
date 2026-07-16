import { Dialog } from "radix-ui";
import type { PropsWithChildren } from "react";

type DrawerProps = PropsWithChildren<{
  open: boolean;
  title: string;
  onOpenChange: (open: boolean) => void;
}>;

export function Drawer({
  open,
  title,
  onOpenChange,
  children,
}: DrawerProps) {
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="drawer-overlay" />
        <Dialog.Content className="drawer-content">
          <div className="drawer-header">
            <Dialog.Title>{title}</Dialog.Title>
            <Dialog.Close asChild>
              <button type="button" aria-label={`关闭${title}`}>
                关闭
              </button>
            </Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
