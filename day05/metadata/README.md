# Day 05 — Metadata Scraper

## What I Built

A file metadata extraction tool that identifies file types using magic bytes, extracts EXIF data from images, pulls metadata from PDFs, computes file hashes, and extracts GPS coordinates from photos.

---

## How It Works

```
python scraper.py
```

Give it any file — it detects the type, shows basic info, hashes, and extracts all embedded metadata.

Example output (JPEG):
```
Detected file type: jpeg

--- Basic File Info ---
  File name: photo.jpg
  File size: 7958 bytes (7.8 KB)
  Created:   Fri Aug 21 23:45:46 2026
  Modified:  Fri Aug 21 23:45:46 2026

--- File Hashes ---
  MD5:    406958840ad1665ffcd1be9c29d515b9
  SHA256: 6bfdabd4fc33d112283c147acccc574e...

--- EXIF Metadata ---
  Make: Canon
  Model: Canon EOS 40D
  DateTime: 2008:07:31 10:38:11
  Software: GIMP 2.4.5
  ISOSpeedRatings: 100
  FocalLength: 135.0
```

---

## Features

### Magic Bytes Detection
Identifies file type by reading the first bytes of the file — not the extension. A JPEG renamed to `.txt` is still detected as JPEG. This is the forensically correct way to identify files.

| File Type | Magic Bytes |
|-----------|-------------|
| JPEG | `FF D8 FF` |
| PNG | `89 50 4E 47` |
| PDF | `25 50 44 46` (%PDF) |

### Basic File Info
Shows file name, size, creation date, and last modified date from the operating system.

### File Hashes (MD5 + SHA256)
Computes cryptographic hashes of the file. Used to verify file integrity — if even one bit changes, the hash changes completely. Useful for:
- Verifying downloads weren't tampered with
- Forensic evidence chain of custody
- Identifying known malware by hash

### Image EXIF Extraction
Extracts all embedded metadata from JPEG/PNG: camera model, date taken, software used, aperture, ISO, focal length, and more.

### GPS Coordinate Extraction
If a photo has GPS data (common in phone photos), converts it to decimal format and provides a direct Google Maps link.

### PDF Metadata Extraction
Extracts author, creator software, creation/modification dates, keywords, and title from PDF documents.

---

## What I Learned

- **Magic bytes:** Every file has a signature in its first bytes that identifies the real type, regardless of extension
- **EXIF data:** Images store hidden info about the camera, settings, location, and timestamps
- **File hashing:** A cryptographic fingerprint that changes if even one bit of the file changes
- **OSINT applications:** Metadata from public documents reveals author names, software, GPS locations, and timestamps
- **Privacy implications:** People unknowingly leak personal info (GPS in selfies, full names in PDFs)
- **Pillow library:** Python's image handling library with EXIF access
- **PyPDF2:** Library for reading PDF metadata and content

---

## Why Metadata Matters in Cybersecurity

- **Reconnaissance:** Extract employee names, internal tools, and infrastructure from public documents
- **Phishing analysis:** Check PDF metadata to identify who created a suspicious document
- **Forensics:** Prove when/where a file was created, on what device
- **Privacy auditing:** Find files that accidentally expose personal data

---

## Requirements

```
pip install Pillow PyPDF2
```

---

## Project Structure

```
metadata/
├── scraper.py    # The metadata extraction tool
└── README.md     # This file
```

---

**#30DaysOfCyber**
