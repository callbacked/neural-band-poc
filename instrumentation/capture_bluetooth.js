// Observe existing app operations; run through the Frida CLI for its ObjC bridge.
'use strict';

const streams = new Map();
const hooked = new Set();
let sequence = 0;

function emit(event, details) {
  console.log(JSON.stringify({event, timestamp: new Date().toISOString(), sequence: sequence++, ...details}));
}

function peerInfo(peripheral) {
  const nameObject = peripheral.name();
  const name = nameObject === null ? '' : nameObject.toString();
  if (!/^Meta Band|^Meta RB Display|^Ray.Ban/i.test(name)) return null;
  return {name, identifier: peripheral.identifier().UUIDString().toString()};
}

function payload(buffer, length) {
  return Array.from(new Uint8Array(buffer.readByteArray(length)), byte => byte.toString(16).padStart(2, '0')).join('');
}

function observeStream(stream, direction, channel) {
  if (stream === null) return;
  const streamId = stream.handle.toString();
  streams.set(streamId, {...channel, stream: streamId, direction});
  const selector = direction === 'rx' ? '- read:maxLength:' : '- write:maxLength:';
  const method = stream[selector];
  if (!method) {
    emit('hook_error', {stream: streamId, selector, message: 'Stream method unavailable'});
    return;
  }
  const address = method.implementation.toString();
  if (hooked.has(address)) return;
  hooked.add(address);
  Interceptor.attach(method.implementation, {
    onEnter(args) {
      this.channel = streams.get(args[0].toString());
      if (!this.channel) return;
      this.buffer = args[2];
      this.capacity = args[3].toUInt32();
      this.saved = null;
      // Copy writes before the call; only the returned byte count is recorded.
      if (this.channel.direction === 'tx' && this.capacity <= 1048576) {
        try { this.saved = payload(this.buffer, this.capacity); }
        catch (error) { emit('capture_error', {message: String(error), ...this.channel}); }
      }
    },
    onLeave(retval) {
      if (!this.channel) return;
      const count = retval.toInt32();
      try {
        if (count <= 0) {
          emit('stream_result', {...this.channel, count, requested: this.capacity});
        } else if (count > this.capacity || count > 1048576) {
          emit('capture_error', {...this.channel, count, requested: this.capacity, message: 'Unexpected byte count; payload omitted'});
        } else {
          const hex = this.channel.direction === 'rx' ? payload(this.buffer, count) : this.saved === null ? null : this.saved.slice(0, count * 2);
          emit('stream_bytes', {...this.channel, count, requested: this.capacity, hex});
        }
      } catch (error) {
        emit('capture_error', {message: String(error), ...this.channel});
      }
    },
  });
  const close = stream['- close'];
  if (close && !hooked.has(close.implementation.toString())) {
    hooked.add(close.implementation.toString());
    Interceptor.attach(close.implementation, {
      onEnter(args) {
        const id = args[0].toString();
        const info = streams.get(id);
        if (info) {
          emit('stream_closed', info);
          streams.delete(id);
        }
      },
    });
  }
  emit('stream_hook', {class: stream.$className, selector, address});
}

let installAttempts = 0;
function installRecorder() {
  installAttempts++;
  const transport = ObjC.available && ObjC.classes['L2CapTransport.L2CapTransport'];
  const channelMethod = transport && transport['- peripheral:didOpenL2CAPChannel:error:'];
  const characteristicMethod = transport && transport['- peripheral:didUpdateValueForCharacteristic:error:'];
  // Swift's Objective-C delegate methods may appear after the image's class name.
  if (!channelMethod || !characteristicMethod) {
    if (installAttempts < 50) return setTimeout(installRecorder, 100);
    emit('hook_error', {message: 'Expected L2CapTransport delegate methods unavailable after 5 seconds; inspect this build'});
    return;
  }
  emit('recorder_initializing', {pid: Process.id});
  emit('transport_resolved', {});

  Interceptor.attach(channelMethod.implementation, {
    onEnter(args) {
      try {
        const peer = peerInfo(new ObjC.Object(args[2]));
        if (!peer) return;
        if (args[3].isNull() || !args[4].isNull()) {
          emit('channel_error', {peer, message: args[4].isNull() ? 'No channel' : new ObjC.Object(args[4]).toString()});
          return;
        }
        const channel = new ObjC.Object(args[3]);
        const info = {peer, channel: channel.handle.toString(), psm: Number(channel.PSM())};
        // Refresh the companion crypto observer's sample budget at each connection.
        globalThis.neuralBandChannelEpoch = sequence;
        emit('channel_open', info);
        observeStream(channel.inputStream(), 'rx', info);
        observeStream(channel.outputStream(), 'tx', info);
      } catch (error) {
        emit('capture_error', {message: String(error), source: 'channel_open'});
      }
    },
  });

  emit('channel_callback_hooked', {});
  Interceptor.attach(characteristicMethod.implementation, {
    onEnter(args) {
      try {
        const peer = peerInfo(new ObjC.Object(args[2]));
        if (!peer) return;
        const characteristic = new ObjC.Object(args[3]);
        const value = characteristic.value();
        const count = value === null ? 0 : Number(value.length());
        emit('characteristic_value', {
          peer, uuid: characteristic.UUID().UUIDString().toString(), count,
          error: args[4].isNull() ? null : new ObjC.Object(args[4]).toString(),
          hex: count === 0 ? '' : payload(value.bytes(), count),
        });
      } catch (error) {
        emit('capture_error', {message: String(error), source: 'characteristic_value'});
      }
    },
  });

  emit('recorder_ready', {pid: Process.id, note: 'Waiting for app to open target L2CAP channels; no connections initiated by recorder'});
}

setImmediate(installRecorder);
