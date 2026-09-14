'use strict';

rpc.exports = {
  snapshot() {
    const main = Process.mainModule;
    const base = main.base;
    if (base.readU32() !== 0xfeedfacf) throw new Error('Expected a 64-bit Mach-O image');
    const count = base.add(16).readU32();
    let command = base.add(32);
    let slide = ptr(0);
    const sections = [];
    for (let i = 0; i < count; i++) {
      const type = command.readU32();
      const size = command.add(4).readU32();
      if (type === 0x19) {
        const segment = command.add(8).readCString();
        if (segment === '__TEXT') slide = base.sub(ptr(command.add(24).readU64().toString()));
        const n = command.add(64).readU32();
        for (let j = 0; j < n; j++) {
          const section = command.add(72 + j * 80);
          const name = section.readCString();
          if (name !== '__cstring' && name !== '__swift5_reflstr') continue;
          const address = ptr(section.add(32).readU64().toString()).add(slide);
          const length = section.add(40).readU64().toNumber();
          const bytes = new Uint8Array(address.readByteArray(length));
          const matches = [];
          let start = 0;
          for (let k = 0; k < bytes.length; k++) {
            if (bytes[k] !== 0) continue;
            let value = '';
            for (let a = start; a < k; a++) value += String.fromCharCode(bytes[a]);
            if (/airshield|hmac_derive|datax|hkdf|l2cap|secure.?link|ecdh|p256|uniband|handshake|emg|gesture|session.?key|key.?deriv|aead/i.test(value)) {
              matches.push({offset: address.add(start).sub(base).toString(), value});
            }
            start = k + 1;
          }
          sections.push({name, length, matches});
        }
      }
      if (size < 8) throw new Error('Invalid Mach-O load-command size');
      command = command.add(size);
    }
    const relevant = symbol => /l2cap|secure.?link|handshake|hkdf|ecdh|noise|sessionkey|keyexchange|crypto|aes|gcm|chacha|hmac/i.test(symbol.name);
    return {
      main: {name: main.name, base: base.toString(), size: main.size},
      imports: main.enumerateImports().filter(relevant),
      symbols: main.enumerateSymbols().filter(relevant),
      sections,
    };
  },
};
