"""
Utility functions for mii_helper.
Despite using the "__name__ == __main__" nomenclature,
seedminer_launcher3 relies heavily on sys.argv in several of it's functions.
Importing seedminer_launcher3 thus won't work,
so this file includes shorter re-written versions of the seedminer functions
which only use function-argument data, and do not rely on argv.
"""

import os
import subprocess
import sys
import struct
import time

from binascii import hexlify, unhexlify
from Cryptodome.Cipher import AES

lfcs = []
ftune = []
lfcs_new = []
ftune_new = []
err_correct = 0


def validate_id0(id0):
    "Is an ID0 valid? Required for generate_part1"
    try:
        print(id0, end="")
        sys.stdout.flush()
        int(id0, 16)
        if len(id0) == 32:
            print(" -- valid ID0")
            return True
        else:
            print(" -- improper ID0 length")
            sys.stdout.flush()
            return False
    except:
        print(" -- not an ID0")
        return False


def generate_part1(id0: str):
    """
    Generate movable_part1.sed from ID0.
    Overridden from seedminer_launcher 3 to simplify.
    """
    buf = b""

    try:
        with open("movable_part1.sed", "rb") as f:
            file = f.read()
    except IOError:
        print("movable_part1.sed not found, generating a new one")
        print("don't forget to add an lfcs to it!\n")
        with open("movable_part1.sed", "wb") as f:
            file = b"\x00" * 0x1000
            f.write(file)

    buf += str(id0).encode("ascii")
    hashcount = 1

    print(id0)

    if hashcount == 1:
        print("Hash added!")
    else:
        # should be unreachable
        print("No hashes added!")
        sys.exit(0)

    with open("movable_part1.sed.backup", "wb") as f:
        f.write(file)

    file = file[:0x10]
    pad_len = 0x1000 - len(file + buf)
    pad = b"\x00" * pad_len
    with open("movable_part1.sed", "wb") as f:
        f.write(file + buf + pad)

    calculated_hashcount = len(file + buf) // 0x20
    print(f"There are now {calculated_hashcount} ID0 hashes in your movable_part1.sed!")
    print("Done!")


def getmax(lfcs: int) -> int:
    "Get the maximum offset for a given movable_part1.sed."
    # Taken from the BFM autolauncher by @eip618
    # thanks, eip!
    lfcs_list = []
    isnew = lfcs >> 32
    lfcs &= 0xFFFFFFF0
    lfcs |= 0x8
    c = 0
    if isnew == 2:
        print("new3ds detected")
        max_offsets = [16, 16, 20]
        distance = [0x00000, 0x00100, 0x00200]
        with open("saves/new-v2.dat", "rb") as f:
            buf = f.read()
    elif isnew == 0:
        print("old3ds detected")
        max_offsets = [18, 18, 20]
        distance = [0x00000, 0x00100, 0x00200]
        with open("saves/old-v2.dat", "rb") as f:
            buf = f.read()
    else:
        print("Error: lfcs high u32 isn't 0 or 2")
        sys.exit(1)

    buflen = len(buf)
    listlen = buflen // 8

    for i in range(0, listlen):
        lfcs_list.append(struct.unpack("<I", buf[i * 8 : i * 8 + 4])[0])

    dist = lfcs - lfcs_list[listlen - 1]
    for i in range(1, listlen - 1):
        if lfcs < lfcs_list[i]:
            dist = min(lfcs - lfcs_list[i - 1], lfcs_list[i + 1] - lfcs)
            break
    print(f"Distance: {dist:08X}")
    for i in distance:
        if dist < i:
            return max_offsets[c - 1] + 10
        c += 1
    return max_offsets[len(distance) - 1] + 10


def byteswap4(n):
    "Reverse a bytes object and return it"
    # using a slice to reverse is better, and easier for bytes
    return n[::-1]


def int16bytes(n: int) -> bytes:
    "Convert an int to two bytes, big-endian"
    return n.to_bytes(16, "big")


def bytes2int(s):
    "Mystery bytes-to-integer function"
    n = 0
    for i in range(4):
        n += ord(s[i : i + 1]) << (i * 8)
    return n


def int2bytes(n):
    "Magic integer-to-bytes function"
    s = bytearray(4)
    for i in range(4):
        s[i] = n & 0xFF
        n = n >> 8
    return s


def endian4(n):
    "Fancy-looking endianness function"
    return (
        (n & 0xFF000000) >> 24
        | (n & 0x00FF0000) >> 8
        | (n & 0x0000FF00) << 8
        | (n & 0x000000FF) << 24
    )


def mii_gpu(year=0, model=None, force_reduced_work_size=False):
    "Bruteforce movable.sed from Mii data using the GPU"
    nk31 = 0x59FC817E6446EA6190347B20E9BDCE52
    offset_override = 0
    with open("input.bin", "rb") as f:
        enc = f.read()
    if len(enc) != 0x70:
        print(
            "Error: input.bin is invalid size (likely QR -> input.bin conversion issue)"
        )
        sys.exit(1)
    nonce = enc[:8] + b"\x00" * 4
    cipher = AES.new(int16bytes(nk31), AES.MODE_CCM, nonce)
    dec = cipher.decrypt(enc[8:0x60])
    nonce = nonce[:8]
    final = dec[:12] + nonce + dec[12:]

    with open("output.bin", "wb") as f:
        f.write(final)

    model_str = b""
    start_lfcs_old = 0x0B000000 // 2
    start_lfcs_new = 0x05000000 // 2
    start_lfcs = 0

    if model == "old":
        model_str = b"\x00\x00"
        if year == 2011:
            start_lfcs_old = 0x01000000
        elif year == 2012:
            start_lfcs_old = 0x04000000
        elif year == 2013:
            start_lfcs_old = 0x07000000
        elif year == 2014:
            start_lfcs_old = 0x09000000
        elif year == 2015:
            start_lfcs_old = 0x09800000
        elif year == 2016:
            start_lfcs_old = 0x0A000000
        elif year == 2017:
            start_lfcs_old = 0x0A800000
        else:
            print(
                "Year 2011-2017 not entered so beginning at lfcs midpoint "
                + hex(start_lfcs_old)
            )
        start_lfcs = start_lfcs_old

    elif model == "new":
        model_str = b"\x02\x00"
        if year == 2014:
            start_lfcs_new = 0x00800000
        elif year == 2015:
            start_lfcs_new = 0x01800000
        elif year == 2016:
            start_lfcs_new = 0x03000000
        elif year == 2017:
            start_lfcs_new = 0x04000000
        else:
            print(
                "Year 2014-2017 not entered so beginning at lfcs midpoint "
                + hex(start_lfcs_new)
            )
        start_lfcs = start_lfcs_new
    start_lfcs = endian4(start_lfcs)
    if os.name == "nt":
        init_command = "bfcl lfcs {:08X} {} {} {:08X}".format(
            start_lfcs,
            hexlify(model_str).decode("ascii"),
            hexlify(final[4 : 4 + 8]).decode("ascii"),
            endian4(offset_override),
        )
    else:
        init_command = "./bfcl lfcs {:08X} {} {} {:08X}".format(
            start_lfcs,
            hexlify(model_str).decode("ascii"),
            hexlify(final[4 : 4 + 8]).decode("ascii"),
            endian4(offset_override),
        )
    print(init_command)
    if force_reduced_work_size is True:
        command = "{} rws".format(init_command)
        subprocess.call(command.split())
    else:
        command = "{} sws".format(init_command)
        proc = subprocess.call(command.split())
        if (
            proc == 251 or proc == 4294967291
        ):  # Help wanted for a better way of catching an exit code of '-5'
            time.sleep(
                3
            )  # Just wait a few seconds so we don't burn out our graphics card
            subprocess.call("{} rws".format(init_command).split())


def generate_part2():
    "Generate movable_part2.sed"
    global err_correct
    with open("saves/old-v2.dat", "rb") as f:
        buf = f.read()

    lfcs_len = len(buf) // 8
    err_correct = 0

    for i in range(lfcs_len):
        lfcs.append(struct.unpack("<i", buf[i * 8 : i * 8 + 4])[0])

    for i in range(lfcs_len):
        ftune.append(struct.unpack("<i", buf[i * 8 + 4 : i * 8 + 8])[0])

    with open("saves/new-v2.dat", "rb") as f:
        buf = f.read()

    lfcs_new_len = len(buf) // 8

    for i in range(lfcs_new_len):
        lfcs_new.append(struct.unpack("<i", buf[i * 8 : i * 8 + 4])[0])

    for i in range(lfcs_new_len):
        ftune_new.append(struct.unpack("<i", buf[i * 8 + 4 : i * 8 + 8])[0])

    noobtest = b"\x00" * 0x20
    with open("movable_part1.sed", "rb") as f:
        seed = f.read()
    if noobtest in seed[0x10:0x30]:
        print("Error: ID0 has been left blank, please add an ID0")
        print("Ex: python {} id0 abcdef012345EXAMPLEdef0123456789".format(sys.argv[0]))
        sys.exit(1)
    if noobtest[:4] in seed[:4]:
        print(
            "Error: LFCS has been left blank, did you do a complete two-way friend code exchange before dumping friendlist?"
        )
        sys.exit(1)
    if len(seed) != 0x1000:
        print("Error: movable_part1.sed is not 4KB")
        sys.exit(1)

    if seed[4:5] == b"\x02":
        print("New3DS msed")
        isnew = True
    elif seed[4:5] == b"\x00":
        print("Old3DS msed - this can happen on a New3DS")
        isnew = False
    else:
        print("Error: can't read u8 msed[4]")
        sys.exit(1)

    # expand()
    print("LFCS      : " + hex(bytes2int(seed[0:4])))
    print("msed3 est : " + hex(getmsed3estimate(bytes2int(seed[0:4]), isnew)))
    print("Error est : " + str(err_correct))
    msed3 = getmsed3estimate(bytes2int(seed[0:4]), isnew)

    offset = 0x10
    hash_final = b""
    i = None
    for i in range(64):
        try:
            hash_init = unhexlify(seed[offset : offset + 0x20])
        except:
            break
        hash_single = (
            byteswap4(hash_init[0:4])
            + byteswap4(hash_init[4:8])
            + byteswap4(hash_init[8:12])
            + byteswap4(hash_init[12:16])
        )
        print("ID0 hash " + str(i) + ": " + hexlify(hash_single).decode("ascii"))
        hash_final += hash_single
        offset += 0x20
    print("Hash total: " + str(i))

    part2 = seed[0:12] + int2bytes(msed3) + hash_final

    pad = 0x1000 - len(part2)
    part2 += b"\x00" * pad

    with open("movable_part2.sed", "wb") as f:
        f.write(part2)
    print("movable_part2.sed generation success")


def getmsed3estimate(n, isnew):
    "Get estimate for MSED3"
    global err_correct
    newbit = 0x0
    if isnew:
        fc = lfcs_new
        ft = ftune_new
        newbit = 0x80000000
    else:
        fc = lfcs
        ft = ftune

    fc_size = len(fc)
    ft_size = len(ft)

    if fc_size != ft_size:
        return -1

    for i in range(fc_size):
        if n < fc[i]:
            xs = n - fc[i - 1]
            xl = fc[i] - fc[i - 1]
            y = ft[i - 1]
            yl = ft[i] - ft[i - 1]
            ys = ((xs * yl) // xl) + y
            err_correct = ys
            return ((n // 5) - ys) | newbit

    return ((n // 5) - ft[ft_size - 1]) | newbit


def do_gpu(force_reduced_work_size: bool = False, max_msky_offset=16384) -> int:
    "Start GPU mining!"
    offset_override = 0
    with open("movable_part2.sed", "rb") as f:
        buf = f.read()
    keyy = hexlify(buf[:16]).decode("ascii")
    id0 = hexlify(buf[16:32]).decode("ascii")
    if os.name == "nt":
        init_command = "bfcl msky {} {} {:08X} {:08X}".format(
            keyy, id0, endian4(offset_override), endian4(max_msky_offset)
        )
    else:
        init_command = "./bfcl msky {} {} {:08X} {:08X}".format(
            keyy, id0, endian4(offset_override), endian4(max_msky_offset)
        )
    print(init_command)
    if force_reduced_work_size is True:
        command = "{} rws".format(init_command)
        proc = subprocess.call(command.split())
    else:
        command = "{} sws sm".format(init_command)
        proc = subprocess.call(command.split())
        if (
            proc == 251 or proc == 4294967291
        ):  # Help wanted for a better way of catching an exit code of '-5'
            time.sleep(
                3
            )  # Just wait a few seconds so we don't burn out our graphics card
            command = "{} rws sm".format(init_command)
            proc = subprocess.call(command.split())
    return proc
