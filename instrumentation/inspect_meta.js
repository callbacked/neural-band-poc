// Run with the Frida CLI, which supplies the Objective-C bridge.
'use strict';

function emit(event, details) {
  console.log(JSON.stringify({event, timestamp: new Date().toISOString(), ...details}));
}

if (!ObjC.available) {
  throw new Error('Objective-C runtime is unavailable');
}

setImmediate(function () {
  const info = ObjC.classes.NSBundle.mainBundle().infoDictionary();
  const app = {};
  for (const key of ['CFBundleIdentifier', 'CFBundleShortVersionString', 'CFBundleVersion', 'MinimumOSVersion']) {
    const value = info.objectForKey_(key);
    app[key] = value === null ? null : value.toString();
  }
  emit('app', app);

  const modules = Process.enumerateModules();
  emit('modules', {modules: modules.filter(m => m.path.includes('.app/') || /crypto|bluetooth|boring|ssl/i.test(m.name))
    .map(m => ({name: m.name, base: m.base.toString(), size: m.size}))});

  const copyNames = new NativeFunction(Module.getGlobalExportByName('objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer']);
  const free = new NativeFunction(Module.getGlobalExportByName('free'), 'void', ['pointer']);
  const names = [];
  for (const module of modules.filter(m => m.name === 'MetaAI' || m.name === 'CoreBluetooth')) {
    const count = Memory.alloc(4);
    const array = copyNames(Memory.allocUtf8String(module.path), count);
    try {
      const total = count.readU32();
      emit('class_count', {module: module.name, count: total});
      for (let index = 0; index < total; index++) {
        const name = array.add(index * Process.pointerSize).readPointer().readUtf8String();
        if (/band|l2cap|handshake|noise|keyagreement|bluetooth|gatt|securechannel/i.test(name)) names.push(name);
      }
    } finally {
      if (!array.isNull()) free(array);
    }
  }
  emit('classes', {names});
  for (const name of names) {
    if (/band|l2cap|handshake|noise|keyagreement|securechannel/i.test(name)) {
      try {
        emit('methods', {class: name, methods: ObjC.classes[name].$ownMethods});
      } catch (error) {
        emit('inspection_error', {class: name, message: String(error)});
      }
    }
  }

  emit('inspection_complete', {});
});
