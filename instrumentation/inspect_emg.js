// Read-only class/method inventory for raw-input and identity-authentication leads.
// Use the Frida CLI for its Objective-C bridge; no heap scans or method calls.
'use strict';

setImmediate(function () {
  const main = Process.mainModule;
  const copyNames = new NativeFunction(Module.getGlobalExportByName('objc_copyClassNamesForImage'), 'pointer', ['pointer', 'pointer']);
  const free = new NativeFunction(Module.getGlobalExportByName('free'), 'void', ['pointer']);
  const count = Memory.alloc(4);
  const array = copyNames(Memory.allocUtf8String(main.path), count);
  try {
    for (let index = 0; index < count.readU32(); index++) {
      const name = array.add(index * Process.pointerSize).readPointer().readUtf8String();
      if (!/IdentityClient|IdentityService|LSV3|WearableInput|EmgSdkDatax|RawEmg|EmgDeviceControl|Uniband|DeviceIdentity/i.test(name)) continue;
      const cls = ObjC.classes[name];
      console.log(JSON.stringify({event: 'target_class', name, methods: cls.$ownMethods.map(method => ({
        name: method, offset: cls[method].implementation.sub(main.base).toString(),
      }))}));
    }
    console.log(JSON.stringify({event: 'inspection_complete'}));
  } finally {
    if (!array.isNull()) free(array);
  }
});
