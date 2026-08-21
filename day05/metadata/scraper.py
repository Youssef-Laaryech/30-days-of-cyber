import os
import hashlib
import time as time_module
from PIL import Image
from PIL.ExifTags import TAGS
from PyPDF2 import PdfReader

print()
print("METADATA SCRAPER")
print()


file_path = input("Enter file path: ")


def show_file_info(file_path):
    file_size = os.path.getsize(file_path)
    created = os.path.getctime(file_path)
    modified = os.path.getmtime(file_path)

    print(f"\n--- Basic File Info ---")
    print(f"  File name: {os.path.basename(file_path)}")
    print(f"  File size: {file_size} bytes ({file_size / 1024:.1f} KB)")
    print(f"  Created:   {time_module.ctime(created)}")
    print(f"  Modified:  {time_module.ctime(modified)}")

    with open(file_path, 'rb') as f:
        data = f.read()
        md5 = hashlib.md5(data).hexdigest()
        sha256 = hashlib.sha256(data).hexdigest()

    print(f"\n--- File Hashes ---")
    print(f"  MD5:    {md5}")
    print(f"  SHA256: {sha256}")


def extract_image_metadata(file_path):
    image = Image.open(file_path)
    exif_data = image._getexif()

    if exif_data is None:
        print("\n  No EXIF metadata found")
        return
    print(f"\n--- EXIF Metadata ---")
    for tag_id, value in exif_data.items():
        tag_name = TAGS.get(tag_id, tag_id)
        print(f"  {tag_name}: {value}")

    coords = get_gps_coordinates(exif_data)
    if coords:
        print(f"\n--- GPS Location ---")
        print(f"  Latitude:  {coords[0]}")
        print(f"  Longitude: {coords[1]}")
        print(f"  Google Maps: https://maps.google.com/?q={coords[0]},{coords[1]}")


def get_gps_coordinates(exif_data):
    gps_info = exif_data.get(34853)
    if not gps_info:
        return None

    def convert_to_decimal(coords, ref):
        degrees = coords[0]
        minutes = coords[1]
        seconds = coords[2]
        decimal = degrees + minutes / 60 + seconds / 3600
        if ref in ['S', 'W']:
            decimal = -decimal
        return decimal

    try:
        lat = convert_to_decimal(gps_info[2], gps_info[1])
        lon = convert_to_decimal(gps_info[4], gps_info[3])
        return lat, lon
    except:
        return None


def extract_pdf_metadata(file_path):
    reader = PdfReader(file_path)
    metadata = reader.metadata

    if metadata is None:
        print("\n  No metadata found")
        return
    print(f"\n--- PDF Metadata ---")
    for key, value in metadata.items():
        print(f"  {key}: {value}")


if not os.path.exists(file_path):
    print("File not found!")
else:
    with open(file_path, 'rb') as f:
        header = f.read(8)
    if header[:3] == b'\xff\xd8\xff':
        file_type = "jpeg"
    elif header[:4] == b'\x89PNG':
        file_type = "png"
    elif header[:4] == b'%PDF':
        file_type = "pdf"
    else:
        file_type = "unknown"

    print(f"Detected file type: {file_type}")

    show_file_info(file_path)

    if file_type in ["jpeg", "png"]:
        extract_image_metadata(file_path)
    elif file_type == "pdf":
        extract_pdf_metadata(file_path)
    else:
        print("Unsupported file type")
