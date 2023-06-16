# NStash
CLI tool for file encryption/decryption.

The encryption method is AES-256, and the password for decryption is hashed using SHA-256 for the encryption process.

## Features

```
Description:
  This program will encrypt/decrypt files.

Usage:
  nstash [<targets>...] [options]

Arguments:
  <targets>  Specifies the path of the file or directory of interest. You can specify multiple targets by separating
             them with commas.

Options:
  -e, --encrypt                        Encrypt the target file.
  -d, --decrypt                        Decrypt the target file.
  -D, --delete                         Delete the original file after encryption/decryption.
  -c, --compress                       Compress the target file before encryption.
  -p, --process-count <process-count>  Specifies the number of processes to use for encryption/decryption. The default
                                       is the number of logical processors in the system. [default: 8]
  --dry-run                            Practice the encryption/decryption process. No actual processing is performed.
  --version                            Show version information
  -?, -h, --help                       Show help and usage information
```

### Encryption and Decryption
Encrypts the file specified by the command line argument.

The `--compress` option performs the Deflate compression process.
You can also specify `--delete` to delete the original file after encryption or decryption.

Encrypted files will be given the extension `.nstash`. The file name before encryption is retained in the encrypted file, so it will be the file name at the time of encryption, regardless of the file name at the time of decryption.


# Author
[@zwei_222](https://twitter.com/zwei_222)

# License
This software is released under the MIT License, see LICENSE.
