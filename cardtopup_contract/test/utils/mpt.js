// merkle-patricia trie utils

const getNibbles = (bytes) => {
  const res = [];
  for (const byte of bytes) {
    res.push([(byte >> 4) & 0x0f, byte & 0x0f]);
  }
  return res;
};

const zip = (a, b) =>
  Array(Math.min(b.length, a.length))
    .fill(0)
    .map((_, i) => [a[i], b[i]]);

const getCommonPrefixLength = (
  leftKey,
  rightKey
) => {
  const zippedVals = zip(leftKey, rightKey);
  for (let i = 0; i < zippedVals.length; i++) {
    if (zippedVals[i][0] != zippedVals[i][1]) {
      return i;
    }
  }
  return Math.min(leftKey.length, rightKey.length);
};

const consumeCommonPrefix = (
  leftKey,
  rightKey
) => {
  const commonPrefixLength = getCommonPrefixLength(leftKey, rightKey);
  return {
    commonPrefix: leftKey.slice(0, commonPrefixLength),
    leftReminder: leftKey.slice(commonPrefixLength),
    rightReminder: rightKey.slice(commonPrefixLength)
  };
};

module.exports = { getNibbles, getCommonPrefixLength, consumeCommonPrefix };
