export function decodeHex(hex) {
  return hex
    .match(/.{1,2}/g)
    .map((b) => String.fromCharCode(parseInt(b, 16)))
    .join("");
}

export function greeting(name) {
  return `hello ${name}`;
}
