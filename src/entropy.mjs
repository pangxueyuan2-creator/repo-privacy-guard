export function shannonEntropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const character of value) {
    counts.set(character, (counts.get(character) ?? 0) + 1);
  }

  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

const ASSIGNMENT_PATTERN = /\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd)\b\s*[:=]\s*["']?([A-Za-z0-9_./+=\-!@#$%^&*]{20,})/gi;

export function findHighEntropyAssignments(text, minimumEntropy = 4.1) {
  const matches = [];
  const pattern = new RegExp(ASSIGNMENT_PATTERN.source, ASSIGNMENT_PATTERN.flags);
  for (const match of text.matchAll(pattern)) {
    const value = match[2];
    if (shannonEntropy(value) >= minimumEntropy) {
      matches.push({
        index: match.index ?? 0,
        length: match[0].length,
        id: "high-entropy-secret",
        severity: "high",
        message: `High-entropy value assigned to ${match[1]}`,
      });
    }
  }
  return matches;
}
