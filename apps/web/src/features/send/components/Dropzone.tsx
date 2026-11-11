import { FolderOpen, UploadCloud } from 'lucide-react';
import { useId, useRef, useState, type DragEvent, type ReactNode } from 'react';
import { toast } from 'sonner';
import { Button } from '../../../components/ui';
import { cn } from '../../../lib/cn';

export interface DropzoneProps {
  onFiles: (files: File[]) => void;
  disabled?: boolean;
  /** Limits shown under the call to action (count and size). */
  hint?: ReactNode;
  /** Compact variant once files are selected. */
  compact?: boolean;
  className?: string;
}

/** Drag and drop or browse; multiple files. Folders are not supported (only files are taken). */
export function Dropzone({
  onFiles,
  disabled = false,
  hint,
  compact = false,
  className,
}: DropzoneProps) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const depth = useRef(0);
  const hintId = useId();

  const take = (list: ArrayLike<File> | null) => {
    if (!list || disabled) return;
    const files = Array.from(list).filter((f) => f instanceof File);
    if (files.length > 0) onFiles(files);
  };

  const onDragEnter = (e: DragEvent) => {
    if (disabled || !e.dataTransfer.types.includes('Files')) return;
    e.preventDefault();
    depth.current += 1;
    setOver(true);
  };
  const onDragLeave = () => {
    depth.current = Math.max(0, depth.current - 1);
    if (depth.current === 0) setOver(false);
  };
  const onDragOver = (e: DragEvent) => {
    if (disabled) return;
    e.preventDefault();
    e.dataTransfer.dropEffect = 'copy';
  };
  const onDrop = (e: DragEvent) => {
    e.preventDefault();
    depth.current = 0;
    setOver(false);
    const { items, files } = e.dataTransfer;
    // A dropped folder shows up as an unreadable File: spot it through its entry and say why it is skipped.
    if (items && items.length > 0 && typeof items[0]?.webkitGetAsEntry === 'function') {
      const taken: File[] = [];
      let folders = 0;
      for (const item of Array.from(items)) {
        if (item.kind !== 'file') continue;
        if (item.webkitGetAsEntry()?.isDirectory) folders += 1;
        else {
          const file = item.getAsFile();
          if (file) taken.push(file);
        }
      }
      if (folders > 0) {
        toast.error('Folders are not supported', {
          description: 'Zip the folder first, then add the zip file.',
        });
      }
      take(taken);
      return;
    }
    take(files);
  };

  return (
    <div
      onDragEnter={onDragEnter}
      onDragLeave={onDragLeave}
      onDragOver={onDragOver}
      onDrop={onDrop}
      data-dragging={over || undefined}
      className={cn(
        'relative flex flex-col items-center justify-center rounded-xl border-2 border-dashed text-center transition-colors',
        compact ? 'gap-2 px-4 py-5 sm:flex-row sm:gap-4' : 'gap-3 px-6 py-10 sm:py-12',
        over ? 'border-primary bg-primary/5' : 'border-border-strong/60 bg-surface-2/40',
        disabled && 'pointer-events-none opacity-60',
        className,
      )}
    >
      <span
        className={cn(
          'flex items-center justify-center rounded-full bg-primary/10 text-primary-ink',
          compact ? 'size-9' : 'size-12',
        )}
        aria-hidden="true"
      >
        <UploadCloud className={compact ? 'size-5' : 'size-6'} />
      </span>
      <div className={cn('flex flex-col gap-1', compact && 'sm:items-start sm:text-left')}>
        <p className="text-sm font-medium text-foreground">
          {over ? 'Drop to add files' : compact ? 'Add more files' : 'Drag files here, or browse'}
        </p>
        {hint ? (
          <p id={hintId} className="text-xs text-muted">
            {hint}
          </p>
        ) : null}
      </div>
      <Button
        variant={compact ? 'outline' : 'primary'}
        size={compact ? 'sm' : 'md'}
        icon={FolderOpen}
        onClick={() => inputRef.current?.click()}
        disabled={disabled}
        aria-describedby={hint ? hintId : undefined}
        className={compact ? 'sm:ml-auto' : undefined}
      >
        Browse files
      </Button>
      <input
        ref={inputRef}
        type="file"
        multiple
        className="sr-only"
        tabIndex={-1}
        aria-hidden="true"
        data-testid="file-input"
        onChange={(e) => {
          take(e.currentTarget.files);
          e.currentTarget.value = '';
        }}
      />
    </div>
  );
}
