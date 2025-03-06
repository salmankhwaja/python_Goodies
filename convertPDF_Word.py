from pdf2docx import Converter

pdf_path = "PCI-Secure-Software-Program-Guide-v1_2.pdf"
docx_path = "PCI_SSF.docx"

cv = Converter(pdf_path)
cv.convert(docx_path, start=0, end=None)
cv.close()