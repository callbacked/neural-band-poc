"""Offline extraction of the observed OTBH/QcomPart band update format.

Inferred from a checksum-verified production package. This tool only parses a
package file; it does not flash hardware and does not verify the final
signature record. Partitions are reconstructed by their flash offsets;
declared lengths exclude transport padding. Treat the output directory as
private: keystore partitions land there verbatim.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import struct

HEADER = struct.Struct('<4sHIII32s')


def decode(data):
    chunks = []
    position = 0
    while position < len(data):
        if len(data) - position < HEADER.size:
            raise ValueError('Truncated OTBH header')
        magic, flags, offset, address, length, digest = HEADER.unpack_from(data, position)
        end = position + HEADER.size + length
        if magic != b'OTBH' or offset != position or end > len(data):
            raise ValueError('Invalid OTBH framing')
        payload = data[position + HEADER.size:end]
        if flags == 0:
            if hashlib.sha256(data[position:position + 18] + payload).digest() != digest:
                raise ValueError('OTBH data checksum mismatch')
        elif flags != 1 or end != len(data) or length != 132:
            raise ValueError('Unexpected OTBH terminal record')
        chunks.append({'offset': position, 'flags': flags, 'address': address,
                       'payload': payload})
        position = end
    if not chunks or chunks[-1]['flags'] != 1 or chunks[0]['address'] != 0:
        raise ValueError('Missing table or terminal record')
    table = chunks[0]['payload']
    if len(table) < 32 or table[:8] != b'QcomPart':
        raise ValueError('Missing QcomPart table')
    version, count = struct.unpack_from('<II', table, 8)
    if version != 1 or len(table) != 32 + count * 64:
        raise ValueError('Unexpected partition table shape')
    partitions = []
    used_chunks = {0, len(chunks) - 1}
    for index in range(count):
        row = table[32 + 64 * index:32 + 64 * (index + 1)]
        address, kind = struct.unpack_from('<II', row)
        capacity, length, flags = struct.unpack_from('<III', row, 20)
        name = row[8:20].decode('ascii').strip(' \0')
        if not name or any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_' for c in name):
            raise ValueError('Unsafe partition filename')
        if length > capacity or capacity > 32 * 1024 * 1024:
            raise ValueError('Invalid partition size')
        if any(address < p['address'] + p['capacity'] and p['address'] < address + capacity for p in partitions):
            raise ValueError('Overlapping partitions')
        pieces = []
        cursor = address
        for chunk_index, chunk in enumerate(chunks[1:-1], 1):
            if address <= chunk['address'] < address + capacity:
                if chunk['address'] != cursor or chunk_index in used_chunks:
                    raise ValueError('Noncontiguous or duplicate partition chunk')
                pieces.append(chunk['payload'])
                cursor += len(chunk['payload'])
                used_chunks.add(chunk_index)
        payload = b''.join(pieces)
        if len(payload) < length or len(payload) > capacity or len(payload) - length > 31:
            raise ValueError('Partition data disagrees with declared length/padding')
        partitions.append({'name': name, 'kind': kind, 'address': address,
                           'capacity': capacity, 'length': length, 'flags': flags,
                           'transport_padding_bytes': len(payload) - length,
                           'payload': payload[:length], 'iv': row[32:48].hex()})
    if len(used_chunks) != len(chunks):
        raise ValueError('Unmapped data chunk')
    return partitions, len(chunks) - 1


def elf32_headers(data):
    output = []
    cursor = 0
    while True:
        start = data.find(b'\x7fELF', cursor)
        if start < 0:
            return output
        cursor = start + 4
        if start + 52 > len(data) or data[start + 4:start + 6] != b'\x01\x01':
            continue
        machine = struct.unpack_from('<H', data, start + 18)[0]
        entry, phoff = struct.unpack_from('<II', data, start + 24)
        phsize, phnum = struct.unpack_from('<HH', data, start + 42)
        if phsize != 32 or phnum > 64 or start + phoff + phsize * phnum > len(data):
            continue
        segments = []
        for index in range(phnum):
            kind, offset, virtual, physical, size, memory, flags, alignment = struct.unpack_from('<8I', data, start + phoff + index * phsize)
            segments.append({'type': kind, 'offset': offset, 'vaddr': virtual,
                             'paddr': physical, 'file_size': size, 'memory_size': memory,
                             'flags': flags, 'alignment': alignment,
                             'file_range_in_partition': start + offset + size <= len(data)})
        output.append({'offset': start, 'machine': machine, 'entry': entry, 'segments': segments})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('blob', type=Path, help='band OTA package file')
    parser.add_argument('output', type=Path, help='new output directory (created private)')
    args = parser.parse_args()
    data = args.blob.read_bytes()
    partitions, verified = decode(data)
    args.output.mkdir(mode=0o700)
    report = {'source_sha256': hashlib.sha256(data).hexdigest(),
              'verified_data_records': verified, 'terminal_signature_verified': False,
              'format_status': 'inferred from observed package', 'partitions': []}
    for partition in partitions:
        payload = partition['payload']
        filename = partition['name'] + '.bin'
        fd = os.open(args.output / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(payload)
        report['partitions'].append({k: v for k, v in partition.items() if k != 'payload'} |
                                    {'sha256': hashlib.sha256(payload).hexdigest(),
                                     'elf32_headers': elf32_headers(payload)})
    (args.output / 'partition-report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'output': str(args.output), 'verified_data_records': verified,
                      'partitions': [{k: p[k] for k in ('name', 'length', 'flags')} for p in partitions]}, indent=2))


if __name__ == '__main__':
    main()
