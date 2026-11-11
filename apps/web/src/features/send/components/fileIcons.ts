import {
  File as FileIcon,
  FileArchive,
  FileAudio,
  FileCode,
  FileImage,
  FileText,
  FileVideo,
  type LucideIcon,
} from 'lucide-react';

/** A lucide icon for a MIME type (and a file name fallback). */
export function fileIconFor(type: string, name = ''): LucideIcon {
  const t = type.toLowerCase();
  const ext = name.toLowerCase().split('.').pop() ?? '';
  if (t.startsWith('image/')) return FileImage;
  if (t.startsWith('video/')) return FileVideo;
  if (t.startsWith('audio/')) return FileAudio;
  if (
    /zip|compressed|tar|gzip|7z|rar/.test(t) ||
    ['zip', 'gz', 'tgz', '7z', 'rar', 'tar'].includes(ext)
  )
    return FileArchive;
  if (/json|javascript|typescript|xml|x-sh|x-python/.test(t)) return FileCode;
  if (
    t.startsWith('text/') ||
    t === 'application/pdf' ||
    ['md', 'txt', 'pdf', 'doc', 'docx'].includes(ext)
  )
    return FileText;
  return FileIcon;
}
