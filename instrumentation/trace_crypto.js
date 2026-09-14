// Capture call sites, not keys or plaintext, for the app's imported primitives.
'use strict';

setImmediate(function () {
  const hooked = new Set();
  const counts = new Map();
  let epoch;
  const modules = new ModuleMap();
  const emit = (event, details) => console.log(JSON.stringify({event, timestamp: new Date().toISOString(), ...details}));

  function location(address) {
    const module = modules.find(address);
    return module === null ? {address: address.toString()} : {
      module: module.name, offset: address.sub(module.base).toString(),
    };
  }

  const imports = Process.mainModule.enumerateImports().filter(symbol => symbol.type === 'function' &&
    (/CryptoKit.*P256.*KeyAgreement|CryptoKit.*SharedSecret|CryptoKit.*AES.*GCM.*(seal|open)|^CCHmac$|^CCCryptor(CreateWithMode|Update)$|^SecKeyCopyKeyExchangeResult$/.test(symbol.name)));
  for (const symbol of imports) {
    if (symbol.address === undefined || hooked.has(symbol.address.toString())) continue;
    hooked.add(symbol.address.toString());
    Interceptor.attach(symbol.address, {
      onEnter(args) {
        if (epoch !== globalThis.neuralBandChannelEpoch) {
          epoch = globalThis.neuralBandChannelEpoch;
          counts.clear();
        }
        const count = (counts.get(symbol.name) || 0) + 1;
        counts.set(symbol.name, count);
        if (count > 50) return;
        const parameters = symbol.name === 'CCCryptorCreateWithMode' ? {
          operation: args[0].toInt32(), mode: args[1].toInt32(),
          algorithm: args[2].toInt32(), padding: args[3].toInt32(),
          keyLength: args[6].toUInt32(),
        } : {};
        emit('crypto_call', {
          function: symbol.name, count, thread: this.threadId,
          channelEpoch: epoch === undefined ? null : epoch,
          ...parameters,
          caller: location(this.returnAddress),
          stack: Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 12).map(location),
        });
      },
    });
  }
  emit('crypto_observer_ready', {pid: Process.id, functions: imports.map(symbol => symbol.name), maxEventsPerFunction: 50});
});
