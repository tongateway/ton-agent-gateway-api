export function toSafeNumber(input: string | number): number {
  if (typeof input === 'number') {
    if (!Number.isSafeInteger(input) || input < 0) {
      throw new Error(`Invalid numeric value: ${input}`);
    }
    return input;
  }

  const parsed = Number(input);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`Invalid numeric value: ${input}`);
  }
  return parsed;
}
