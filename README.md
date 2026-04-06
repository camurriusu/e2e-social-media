This is, “**SecureShare**”, a secure social media application developed using Flask.

The platform allows users to publish encrypted posts to a “wall” that are readable only by members of their group. Those outside of a user’s group only see ciphertext in place of the post’s content. The application uses a public key infrastructure system for encrypting and decrypting user’s posts, ensuring high and efficient security and privacy.

Python’s cryptography library is used to run algorithms such as RSA, PBKDF2, and AES-GCM. Key management is completely invisible to the user and automatically performed by the backend. Note also that most data is persistent and securely stored in a SQLite database.
