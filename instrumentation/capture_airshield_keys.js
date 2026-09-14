// Build-specific probe: Meta AI 269.1.0 / 948093709, Frida 17.5.1.
// Records this AirShield KDF's session material; keep output in local captures/.
'use strict';

setImmediate(function () {
  const main = Process.mainModule;
  const stacks = new Map();
  let nextId = 0;
  const hex = (address, length) => Array.from(new Uint8Array(address.readByteArray(length)),
    byte => byte.toString(16).padStart(2, '0')).join('');
  const emit = (event, details) => console.log(JSON.stringify({event, timestamp: new Date().toISOString(), ...details}));

  // Refuse unrelated builds before interpreting native stack/object offsets.
  if (main.name !== 'MetaAI' ||
      !Instruction.parse(main.base.add(0x45e45ec)).toString().startsWith('stp x29, x30,') ||
      Instruction.parse(main.base.add(0x45e4810)).toString() !== 'ldrb w8, [x20, #0xb]' ||
      main.base.add(0x896e075).readCString() !== 'hmac_derive') {
    throw new Error('AirShield KDF anchors do not match the inspected build');
  }

  Interceptor.attach(main.base.add(0x45e45ec), {
    onEnter(args) {
      this.sample = ++nextId <= 16;
      if (!this.sample) return;
      this.id = nextId;
      this.cache = args[3];
      const stack = stacks.get(this.threadId) || [];
      stack.push(this.id);
      stacks.set(this.threadId, stack);
      try {
        emit('airshield_kdf_enter', {
          id: this.id, thread: this.threadId, directionFlag: args[1].toUInt32(),
          builder: args[0].toString(), challenge: hex(args[0].add(0x10), 16),
          seed: hex(args[0].add(0x48), 32), iv: hex(args[0].add(0x68), 16),
          parameters: hex(args[2], 12),
        });
      } catch (error) {
        emit('airshield_probe_error', {id: this.id, message: String(error)});
      }
    },
    onLeave() {
      if (!this.sample) return;
      try {
        const valid = this.cache.add(32).readU8();
        if (valid !== 1) throw new Error('Shared-secret cache is not valid');
        emit('airshield_shared_secret', {id: this.id, valid, hex: hex(this.cache, 32)});
      } catch (error) {
        emit('airshield_probe_error', {id: this.id, message: String(error)});
      } finally {
        const stack = stacks.get(this.threadId);
        stack.pop();
        if (!stack.length) stacks.delete(this.threadId);
      }
    },
  });

  // At this point both directional keys have been derived, before cipher setup.
  Interceptor.attach(main.base.add(0x45e4810), {
    onEnter() {
      const stack = stacks.get(this.threadId);
      if (!stack || !stack.length) return;
      try {
        emit('airshield_derived_keys', {
          id: stack[stack.length - 1],
          encryption: hex(this.context.fp.sub(0xd0), 32),
          mac: hex(this.context.fp.sub(0xf0), 32),
        });
      } catch (error) {
        emit('airshield_probe_error', {message: String(error)});
      }
    },
  });
  emit('airshield_probe_ready', {pid: Process.id, maxDerivations: 16});
});
