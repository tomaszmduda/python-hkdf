from __future__ import print_function

import argparse
import hashlib
import struct
import sys

from hkdf import hkdf_expand


def main():
    parser = argparse.ArgumentParser(
        description='Generates pseudorandom key usin HKDF method described in '
        'RFC 5869. Hash function used for HMAC is SHA256.'
    )
    parser.add_argument('-i', '--info', default='',
        help='optional context and application specific information, defaults '
        'to empty string')
    parser.add_argument('-k', '--key', default='-',
        help='path to pseudorandom key, use "-" for reading from standard'
        ' input')
    parser.add_argument('-l', '--length', default=32, type=int,
        help='desired length of output material, defaults to 32')
    parser.add_argument('-L', '--append-length', default=False,
        action='store_true',
        help='if set, to info requested length is appended, encoded as '
        'big-endian binary; using this flag prevents shorter keys being '
        'prefixes to longer keys')
    args = parser.parse_args()

    info = args.info

    if args.append_length:
        # Binding length to info is described in RFC 5869 in section
        # "3.2.  The 'info' Input to HKDF". Thanks to that, shorter derived
        # keys wont be prefixes of longer derived keys.
        info = info + struct.pack('>I', args.length)

    key_file = sys.stdin
    if args.key != '-':
        key_file = open(args.key, 'r')



    key_data = key_file.read()
    output = hkdf_expand(
        pseudo_random_key=key_data,
        info=info,
        length=args.length,
        hash_object=hashlib.sha256
    )

    sys.stdout.write(output)

    if args.key != '-':
        key_file.close()



if __name__ == '__main__':
    main()
