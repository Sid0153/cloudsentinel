/** Scans often start within the same minute, so their times can include seconds. */
export function formatDateTime(value: string | null | undefined, withSeconds = false): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: withSeconds ? "medium" : "short",
  });
}

/** "DATA_PROTECTION" -> "Data protection", "COMPLETED_WITH_ERRORS" -> "Completed with errors". */
export function humanize(value: string): string {
  const text = value.replace(/_/g, " ").toLowerCase();
  return text.charAt(0).toUpperCase() + text.slice(1);
}

/** "AWS::EC2::SecurityGroup" -> "EC2 SecurityGroup". */
export function shortType(resourceType: string): string {
  return resourceType.replace(/^AWS::/, "").replace(/::/g, " ");
}

/** Resource IDs can be long ARNs; the last path segment is usually the recognizable part. */
export function shortResourceId(resourceId: string): string {
  if (!resourceId.startsWith("arn:")) return resourceId;
  const tail = resourceId.split(":").pop() ?? resourceId;
  return tail.includes("/") ? tail.slice(tail.indexOf("/") + 1) : tail;
}
