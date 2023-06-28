# mii-miner
Stripped and modified Seedminer (by Zoogie), for Mii mining

## What is this script?
This script (`mii_miner.py`) is a tidy front-end for "Mii mining". It uses a heavily stripped-out version of Zoogie's `seedminer_launcher3.py` - provided here as `seedminer_utils.py` - containing only the bare minimum functions required to mine a `movable.sed` using a Mii QR code, an ID0, the console type, and the manufacturing year.

## Requirements
Requires `opencv-python` (for decoding the Mii QR code) and `pycryptodomex` (for Movable cryptography) - see `requirements.txt`.

## Usage
```
usage: mii_miner.py [-h] [--year YEAR] [--out OUTPUT_FOLDER] filename id0 {old,new}

Bruteforce a movable.sed using locally-obtained console info.

positional arguments:
  filename              Filename for the Mii QR code
  id0                   The ID0 for this console
  {old,new}             Console type (New3DS or Old3DS)

options:
  -h, --help            show this help message and exit
  --year YEAR, -y YEAR  Year of console manufacture (optional)
  --out OUTPUT_FOLDER, -o OUTPUT_FOLDER
                        Output folder name (defaults to current date and time if not specified)
```

### Example 1:
```
python mii_miner.py HNI_0001.JPG 2ee505276c21582ed6e858d2d44e1aeb old --year 2011 --out nicl
```
Mine a movable.sed using the following parameters:
- the QR code is stored in `HNI_0001.JPG`
- this is from an Old 3DS
- it was manufactured in 2011

When the seed is mined, it will be moved to the folder `nicl`.

### Example 2:
```
python mii_miner.py HNI_0002.JPG edb5276c2156e82ee508258d2d44e1ae new
```
Mine a movable.sed using the following parameters:
- the QR code is stored in `HNI_0002.JPG`
- this is from a New 3DS
- the manufacturing year is unknown (script will guess)

When the seed is mined, it will be moved to a folder named after the current timestamp (e.g `2023-06-28 1601`)

## Credits
A massive thanks to Zoogie, who is responsible for the vast majority of the code in `seedminer_utils.py`.