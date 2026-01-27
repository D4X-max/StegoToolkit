from PyPDF2 import PdfReader, PdfWriter

def hide_in_pdf(input_pdf, secret_data, output_pdf):
    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    
    for page in reader.pages:
        writer.add_page(page)
        
    writer.add_metadata({
        '/SecretKey': secret_data
    })
    
    with open(output_pdf, "wb") as f:
        writer.write(f)

def extract_from_pdf(pdf_path):
    reader = PdfReader(pdf_path)
    metadata = reader.metadata
    return metadata.get('/SecretKey', "No secret found.")