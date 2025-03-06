from pdf2docx import Converter
import os

# Ask user for PDF input path
pdf_path = input("Enter the path of the PDF file to convert: ").strip()
if not os.path.isabs(pdf_path):
    pdf_path = os.path.abspath(pdf_path)  # Convert relative path to absolute

# Ask user for output DOCX path
docx_path = input("Enter the output path for the DOCX file: ").strip()
if not os.path.isabs(docx_path):
    docx_path = os.path.abspath(docx_path)  # Convert relative path to absolute

# Ensure the output file has the correct extension
if not docx_path.lower().endswith(".docx"):
    docx_path += ".docx"

try:
    cv = Converter(pdf_path)
    cv.convert(docx_path, start=0, end=None)
    cv.close()
    print(f"Conversion successful! DOCX saved at: {docx_path}")
except Exception as e:
    print(f"Error: {e}")
