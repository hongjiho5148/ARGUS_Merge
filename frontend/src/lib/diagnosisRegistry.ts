/** Guideline sections that open an options dialog before run. */
export const DIAGNOSIS_SECTIONS_WITH_DIALOG = new Set([
  "1-2",
  "1-5",
  "2-2",
  "3-2",
  "3-5",
  "3-6",
  "4-1",
  "5-2",
  "6-1",
  "6-2",
  "7-1",
  "7-2",
  "7-3",
  "7-4",
]);

export function sectionHasStartDialog(sectionId: string): boolean {
  return DIAGNOSIS_SECTIONS_WITH_DIALOG.has(sectionId);
}
