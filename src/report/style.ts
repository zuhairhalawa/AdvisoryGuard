export interface Style {
  bold(s: string): string;
  dim(s: string): string;
  red(s: string): string;
  yellow(s: string): string;
  green(s: string): string;
  cyan(s: string): string;
}

const ESC = String.fromCharCode(27);

function wrap(open: number, close: number, enabled: boolean): (s: string) => string {
  return enabled ? (s) => `${ESC}[${open}m${s}${ESC}[${close}m` : (s) => s;
}

export function createStyle(enabled: boolean): Style {
  return {
    bold: wrap(1, 22, enabled),
    dim: wrap(2, 22, enabled),
    red: wrap(31, 39, enabled),
    yellow: wrap(33, 39, enabled),
    green: wrap(32, 39, enabled),
    cyan: wrap(36, 39, enabled),
  };
}
