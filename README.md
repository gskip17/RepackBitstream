# Repackage Bitstream

### Decrypt Bitstream
Decrypt any encrypted Xilinx 7-series bitstream. Must provide the encryption key file (.nky) produced by Vivado.

`$ python3 Repackage.py <bitstream.bit> -d -k <key.nky>`

This will produce `decrypted_bitstream.bin` which will only contain the plaintext decrypted from the original bitstream. If a full decrypted bitstream is desirable then the repack (-r) command should be used, which is explained below.

### Repackage Bitstream
This script is used to repackage an encrypted Xilinx 7-series bitstream with the provided plaintext file. Again the encryption key file (.nky) must be provided.

The plaintext file should have the structure of shown below. The decrypted header/footer configuration commands must be included alongside the modified fabric. They can be copied from the original encrypted bitstream.
```
Decrypted Header Configuration Commands
Modified Fabric
Decrypted Footer Configuration Commands
```

`$ python3 Repackage.py <bitstream.bit> -r <plaintext_file> -k <key.nky> -o <output_file>`

This will produce three intermediate files (`ciphertext.bin`, `new_ciphertext.bin`, `plaintext.bin`) which can be found in the `run` directory after the script is finished. `ciphertext.bin` will include all of the ciphertext from the original encrypted bitstream provided. `new_ciphertext.bin` will include the newly calculated ciphertext from the re-encryption process. Then `plaintext.bin` will include the HMAC header/footer plaintext plus the users provided modified plaintext. The `-o` output file can be designated by the user or is defaulted to `full_encrypted.bit`. This file contains the full new encrypted bitstream with all of the unencrypted sections glued on. `full_decrypted.bit` will contain the same new bitstream but is decrypted. 
