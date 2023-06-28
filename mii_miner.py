"""
Manual Mii mining utility script.
Streamlines going from ID0, QR, model, and year to a movable.sed
"""
import argparse
import datetime
import sys
import cv2
import os
import shutil
import glob

import seedminer_utils


def get_mii_data(filename: str) -> bytes | str:
    "Get Mii data from a QR code."
    qr_decoder = cv2.QRCodeDetector()
    try:
        data, _, _ = qr_decoder.detectAndDecode(cv2.imread(filename))
    except UnicodeDecodeError as exc:
        # Nintendo's QR codes make CV2 unhappy
        # It thinks they're text, so it assumes UTF-8
        # however a lot of the time, mii data is not UTF-8
        # causing CV2 to throw an exception
        # there is no way to override the encoding
        # thankfully, we can pull the Mii data from the exception

        data = exc.object
    except FileNotFoundError:
        print(f"File {filename} does not exist! Please check this and try again.")
        sys.exit(1)

    return data


def gen_timestamp() -> str:
    "Generate an ISO-like timestamp."
    return datetime.datetime.now().strftime("%Y-%m-%d %H%M")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Bruteforce a movable.sed using locally-obtained console info."
    )

    parser.add_argument("filename", help="Filename for the Mii QR code")
    parser.add_argument("id0", help="The ID0 for this console")
    parser.add_argument(
        "console_type",
        choices=["old", "new"],
        help="Console type (New3DS or Old3DS)",
    )

    parser.add_argument(
        "--year",
        "-y",
        required=False,
        type=int,
        help="Year of console manufacture (optional)",
    )
    parser.add_argument(
        "--out",
        "-o",
        dest="output_folder",
        required=False,
        default=gen_timestamp(),
        help="Output folder name (defaults to current date and time if not specified)",
    )

    args = parser.parse_args()

    # Double-check ID0
    if seedminer_utils.validate_id0(args.id0) == False:
        sys.exit(1)

    # Generate part1, get max_offset
    seedminer_utils.generate_part1(args.id0)
    with open("movable_part1.sed", "rb") as movable_file:
        movable_lfcs = int.from_bytes(movable_file.read(8), byteorder="little")
        max_offset = seedminer_utils.getmax(movable_lfcs)

    print(f"Max offset for this ID0 is {max_offset}")

    # Generate input.bin
    mii = get_mii_data(args.filename)
    with open("input.bin", "wb") as mii_bin:
        mii_bin.write(mii)

    # GENTLEMEN, START YOUR ENGINES
    seedminer_utils.mii_gpu(
        year=(0 if args.year is None else args.year), model=args.console_type
    )
    seedminer_utils.generate_part2()
    bfcl_return = seedminer_utils.do_gpu(max_msky_offset=max_offset)

    # Clean up after ourselves
    movables = glob.glob("movable*")
    msed_data = glob.glob("msed_data*")

    console_uniques = ["input.bin", "output.bin", args.filename, *movables, *msed_data]

    print("Cleaning up...")

    if not os.path.exists(args.output_folder):
        os.makedirs(args.output_folder)

    if len(os.listdir(args.output_folder)) > 0:
        print("Output folder is not empty!")
        print("To avoid clobbering someone else's movable, we won't clean up.")
        print("Please fix this manually.")
    else:
        for file in console_uniques:
            shutil.move(file, args.output_folder)

    sys.exit(bfcl_return)
