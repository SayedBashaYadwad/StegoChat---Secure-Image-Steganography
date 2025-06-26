 StegoChat - Secure Image Steganography

StegoChat is a user-friendly application that allows you to hide secret messages inside images using steganography and secure encryption. The application provides a modern graphical interface and ensures your messages remain private.

 Features

- Message Hiding: Hide text messages within PNG images
- Password Protection: Secure your hidden messages with password-based encryption
- Modern Interface: Clean and intuitive graphical user interface
- Image Preview: See image previews before hiding or extracting messages
- Progress Indicators: Visual feedback during operations
- Error Handling: Comprehensive error checking and user feedback
- Cross-platform: Works on Windows, macOS, and Linux

 Requirements

- Python 3.8 or higher
- Required Python packages:
  - tkinter (usually comes with Python)
  - Pillow (PIL)
  - numpy
  - cryptography

 Installation

1. Clone or download this repository
2. Install the required packages:
```bash
pip install pillow numpy cryptography
```

 Usage

Run the application:
```bash
python main_app.py
```

 Hiding a Message

1. Click on the "Hide Message" tab
2. Click "Browse" to select a PNG image
3. Enter your password (minimum 8 characters)
4. Confirm your password
5. Type your secret message
6. Click "Hide Message"
7. Choose a filename to save the stego image
8. Share the stego image and password securely with the recipient

 Extracting a Message

1. Click on the "Extract Message" tab
2. Click "Browse" to select the stego image
3. Enter the password that was used to hide the message
4. Click "Extract Message"
5. The hidden message will appear in the text box

 Security Features

- Password-Based Key Derivation: Uses PBKDF2 with SHA256
- Strong Encryption: Fernet symmetric encryption (AES-128 in CBC mode)
- Message Integrity: Encryption includes authentication to detect tampering
- Minimum Password Length: 8 characters required for better security

 Technical Details

 Steganography Method
- Uses Least Significant Bit (LSB) steganography
- Modifies only the least significant bit of image pixels
- Minimal visual impact on the image
- Supports large messages (size depends on image dimensions)

 Encryption Process
1. Password is processed through PBKDF2 to generate a secure key
2. Message is encrypted using Fernet (symmetric encryption)
3. Encrypted data is hidden in the image using LSB

 File Structure

- `main_app.py`: Main application with GUI and steganography functions
- `encryption.py`: Encryption and decryption functions
- `README.md`: This documentation file

 Best Practices

1. Image Selection:
   - Use PNG images for best results
   - Larger images can store longer messages
   - Avoid using the same image multiple times

2. Password Security:
   - Use strong, unique passwords
   - Combine letters, numbers, and special characters
   - Never reuse passwords
   - Share passwords securely (not through the same channel as the image)

3. Message Security:
   - Keep messages concise
   - Don't hide multiple messages in the same image
   - Always use a new password for each message

 Troubleshooting

Common issues and solutions:

1. "Message too long": 
   - Use a larger image
   - Reduce message length

2. "Failed to extract message": 
   - Verify the correct password is being used
   - Ensure the image hasn't been modified
   - Check if the image is in PNG format

3. "Not responding":
   - Wait for large images to process
   - Progress bars indicate ongoing operations

 Limitations

- Only supports PNG image format
- Image must not be modified after hiding message
- Message size limited by image dimensions
- No support for hiding files (text messages only)


 Acknowledgments

- Built using Python and modern cryptographic libraries
- Uses industry-standard encryption methods
- Designed with security and usability in mind

 Contact

For questions, issues, or suggestions:
- Create an issue in the repository
- Contact the maintainers

 Version History

- 1.0.0: Initial release
  - Basic steganography functionality
  - Password-based encryption
  - GUI interface 