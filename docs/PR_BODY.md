while getting enrollment working on the mac side for kinesis i ended up mapping out basically the whole enrollment protocol, so im dropping it here

the main piece is the full enrollment flow: what happens on the ble side step by step (identity read, challenge, start/finish change owner), how pair_request and pair work on the server side, the receipt formats, and the trust handshake the band wants after a reboot before it opens input again. also an error map for the identity service and a fuzzer for the identity service in case anyone wants to keep pulling on that thread. threw in firmware package format notes too, the ota layout, how the records and partitions fit together, what's readable and what's encrypted, and a parser for it. bring your own package, im not hosting one

heads up that my extraction path was a jailbroken iphone (the meta ai app caches the ota url and keeps enrollment state on device), so if you're coming from a rooted android expect the storage locations and app internals to differ. the protocol and flow docs should hold either way, that part lives on the band

no keys or captures in here, just protocol and tools