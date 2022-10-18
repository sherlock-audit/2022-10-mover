// tiny hex manipulation handlers

const zeroToHexZero = (v) => {
    if (v === '0') {
      return `0x0`;
    }
    return v;
  };
  
const parseAsInt = (v) => {
    if (v === '0x') {
      return 0;
    }
    if (v.startsWith('0x')) {
      return parseInt(v, 16);
    }
    return parseInt(v, 10);
  };
  
const parseHexAsBigInt = (v) => {
    if (typeof v === 'string') {
      if (v === '0x') {
        return BigInt(0);
      }
      if (!v.startsWith('0x')) {
        return BigInt(`0x${v}`);
      }
      return BigInt(v);
    } else {
      return BigInt(v);
    }
  };
  
const bigIntToHexString = (v) => {
    return `0x${v.toString(16)}`;
  };
  
const bigIntToDecimalString = (v) => {
    return `0x${v.toString(16)}`;
  };
  
const byteToHex = [];
  
for (let n = 0; n <= 0xff; ++n) {
  const hexOctet = n.toString(16).padStart(2, '0');
  byteToHex.push(hexOctet);
}
  
const uintBufferToHex = (buff) => {
    const hexOctets = []; // new Array(buff.length) is even faster (preallocates necessary array size), then use hexOctets[i] instead of .push()
    for (let i = 0; i < buff.length; ++i) hexOctets.push(byteToHex[buff[i]]);
    return hexOctets.join('');
  };

module.exports = { bigIntToDecimalString, bigIntToHexString, uintBufferToHex };
