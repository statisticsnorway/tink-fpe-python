# Tink FPE Python

[![PyPI](https://img.shields.io/pypi/v/tink-fpe.svg)][pypi_]
[![Status](https://img.shields.io/pypi/status/tink-fpe.svg)][status]
[![Python Version](https://img.shields.io/pypi/pyversions/tink-fpe)][python version]
[![License](https://img.shields.io/pypi/l/tink-fpe)][license]

[![Tests](https://github.com/statisticsnorway/tink-fpe-python/workflows/Tests/badge.svg)][tests]
[![Codecov](https://codecov.io/gh/statisticsnorway/tink-fpe-python/branch/main/graph/badge.svg)][codecov]

[![pre-commit](https://img.shields.io/badge/pre--commit-enabled-brightgreen?logo=pre-commit&logoColor=white)][pre-commit]
[![Black](https://img.shields.io/badge/code%20style-black-000000.svg)][black]

[pypi_]: https://pypi.org/project/tink-fpe/
[status]: https://pypi.org/project/tink-fpe-python/
[python version]: https://pypi.org/project/tink-fpe-python
[tests]: https://github.com/statisticsnorway/tink-fpe-python/actions?workflow=Tests
[codecov]: https://app.codecov.io/gh/statisticsnorway/tink-fpe-python
[pre-commit]: https://github.com/pre-commit/pre-commit
[black]: https://github.com/psf/black

Format-Preserving Encryption (FPE) is a type of encryption that encrypts data in a way that preserves the format of the original plaintext. This means that after encryption, the encrypted data retains the same format as the original plaintext, such as a specific length or character set.

## Features

- _Tink FPE_ implements a [Primitive](https://developers.google.com/tink/glossary) that extends the Google Tink framework with support for Format-Preserving Encryption (FPE).
- The following [NIST compliant](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38Gr1-draft.pdf) algorithms are currently supported: `FF3-1`.
- The implementation of the underlying algorithm is built on top of the excellent [Mysto FPE](https://github.com/mysto/python-fpe) library.
- Tink FPE is currently available for Python and Java.
- Regarding sensitivity for alphabet, FPE is designed to work with a specific alphabet, which is typically defined in the encryption algorithm. If the plaintext data contains characters that are not part of the defined alphabet, Tink FPE supports different _strategies_ for dealing with the data or substitute the characters with ones that are part of the alphabet.

## Requirements

- Google Tink for Python - the bleeding edge version (until [this issue](https://github.com/google/tink/issues/623) is resolved)

## Installation

You can install _Tink FPE_ via [pip] from [PyPI]:

```console
$ pip install tink-fpe
```

## Usage

```python
import tink
import tink_fpe

# Register Tink FPE with the Tink runtime
tink_fpe.register()

# Specify the key template to use. In this example we want a 256 bits FF3-1 key that can handle
# alphanumeric characters (ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789)
key_template = tink_fpe.fpe_key_templates.FPE_FF31_256_ALPHANUMERIC

# Create a keyset
keyset_handle = tink.new_keyset_handle(key_template)

# Get the FPE primitive
fpe = keyset_handle.primitive(tink_fpe.Fpe)

# Encrypt
ciphertext = fpe.encrypt(b'Secret123')
print(ciphertext.decode('utf-8')) #-> sN3gt6q0V

# Decrypt
decrypted = fpe.decrypt(ciphertext)
print(decrypted.decode('utf-8')) #-> Secret123
```

### Handling non-alphabet characters

A characteristic of Format-Preserving Encryption is that plaintext can only be composed of letters or symbols
from a predefined set of characters called the "alphabet". Tink FPE supports different ways of coping with
texts that contain non-alphabet characters. The approach to use can be expressed via the `UnknownCharacterStrategy` enum.

The following _stragies_ are supported:

- `FAIL` - Raise an error and bail out if encountering a non-alphabet character. **(this is the default)**
- `SKIP` - Ignore non-alphabet characters, leaving them unencrypted (nested into the ciphertext).
- `DELETE` - Remove all characters that are not part of the alphabet prior to processing. \_Warning: Using this strategy implies that the length of the plaintext and ciphertext may differ.
- `REDACT` - Replace non-alphabet characters with an alphabet-compliant character prior to processing. _Warning: Using this strategy means that decryption may not result in the exact same plaintext being restored._

```python
from tink_fpe import FpeParams, UnknownCharacterStrategy

# The following will raise an Error
ciphertext = fpe.encrypt(b'Ken sent me...', FpeParams(strategy=UnknownCharacterStrategy.FAIL))

# Skipping non-supported characters might reveal too much of the plaintext, but it is currently the only
# approach that will handle any plaintext without either failing or irreversibly transforming the plaintext.
params = FpeParams(strategy=UnknownCharacterStrategy.SKIP)
fpe.encrypt(b'Ken sent me...', params) #-> UEj l1Ns sj...
fpe.decrypt(ciphertext, params) #-> Ken sent me...

# Notice that using the DELETE strategy implies that the length of the plaintext and ciphertext may differ.
# Furthermore, it might be impossible to go back to the original plaintext.
params = FpeParams(strategy=UnknownCharacterStrategy.DELETE)
ciphertext = fpe.encrypt(b'Ken sent me...', params) #-> EsQPgkE9Y
decrypted = fpe.decrypt(ciphertext, params) #-> Kensentme

# Notice that using the REDACT strategy it might be impossible to go back to the original plaintext.
# If not specified, the redaction character will be deduced automatically from the alphabet.
# For alphanumeric alphabets the 'X' character is used.
params = FpeParams(strategy=UnknownCharacterStrategy.REDACT)
ciphertext = fpe.encrypt(b'Ken sent me...', params) #-> MMY2HXvLwzIDoY
decrypted = fpe.decrypt(ciphertext, params) #-> KenXsentXmeXXX

# It is also possible to specify the redaction character explicitly, like so:
params = FpeParams(strategy=UnknownCharacterStrategy.REDACT, redaction_char='Q')
ciphertext = fpe.encrypt(b'Ken sent me...', params) #-> 9fVDzAODt2vvdz
decrypted = fpe.decrypt(ciphertext, params) #-> KenQsentQmeQQQ
```

### Loading predefined key material

It is easy to initialize key material from a predefined JSON. The following uses a cleartext keyset,
but it will be similar for a wrapped/encrypted key as well.

```python
import json
from tink import JsonKeysetReader
from tink import cleartext_keyset_handle
import tink_fpe

tink_fpe.register()

keyset_json = json.dumps({
    "primaryKeyId": 1382079328,
    "key": [
        {
            "keyData": {
                "typeUrl": "type.googleapis.com/ssb.crypto.tink.FpeFfxKey",
                "value": "EhD4978shQNRpBNaBjbF4KO4GkIQAho+QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=",
                "keyMaterialType": "SYMMETRIC"
            },
            "status": "ENABLED",
            "keyId": 1382079328,
            "outputPrefixType": "RAW"
        }
    ]
})

keyset_handle = cleartext_keyset_handle.read(JsonKeysetReader(keyset_json))
fpe = keyset_handle.primitive(tink_fpe.Fpe)
```

### Using key material protected by Google Cloud KMS

```python
import json

from tink import JsonKeysetReader
from tink import read_keyset_handle
from tink.integration import gcpkms

import tink_fpe


# Define uri to key encryption key and path to GCP credentials
gcp_credentials = "path/to/sa-key.json"

# Register Tink FPE with the Tink runtime
tink_fpe.register()

# Get hold of a wrapped data encryption key (WDEK)
keyset_json = {
    "kekUri": "gcp-kms://projects/<project-id>/locations/<region>/keyRings/my-keyring/cryptoKeys/my-kek",
    "encryptedKeyset": "CiQAp91NBsClBYjw4AS9sOdB65peMwlzY4AiOzyMe+b+dFjSBuIS2QEAZ30rtRcDkuvtUgeENQCt29Vsalf+FtaNZc8wpOXKb3sD2c8hTXKaf34iq2QRMaQUBXxG+YSJPV4PvJZMGydZpjowM9K2eAJFZs5JaVxb3BMfUt0miNaORZmczqZhKlXXHbMoQ71GLwfSnf4jJnIRJK4s38ThnxS2ebm4b5T0qno6PWg84TtUw9eIIieqlUFhIqBjCcMugGTsE+xfWIOct22RDEUI3cAboCew5ppjOREAxzbaH8LaUBct5eLN8wtakY3Vv8KxBoT3Hq6fnNSSGOKmkqMVrK0p",
    "keysetInfo":
        {
            "primaryKeyId": 593699223,
            "keyInfo":
                [
                    {
                        "typeUrl": "type.googleapis.com/ssb.crypto.tink.FpeFfxKey",
                        "status": "ENABLED",
                        "keyId": 593699223,
                        "outputPrefixType": "RAW"
                    }
                ]
        }
}

# Extract the kek uri from the keyset json
kek_uri = keyset_json.pop('kekUri')

# Unwrap key using Google Cloud KMS
kms_client = gcpkms.GcpKmsClient(kek_uri, gcp_credentials)
kms_aead = kms_client.get_aead(kek_uri)
keyset_handle = read_keyset_handle(keyset_reader=JsonKeysetReader(json.dumps(keyset_json)),
                                   master_key_aead=kms_aead)

# Get the FPE primitive
fpe = keyset_handle.primitive(tink_fpe.Fpe)
```

### Dockerfile

As of this writing (27.03.2023), Tink does not yet provide Python wheels for versions `>1.6.x`.
Thus, in order to use Tink FPE, we need to build Tink, which involves using bazel and and
compiling protobuf sources. The following shows a Dockerfile that demonstrates how this can
be done. Notice that this is for the `x86` architecture. If you are on another
architecture (e.g. `arm`), you need to substitute the bazel and protobuf references to match
your system architecture.

```dockerfile
FROM python:3.10-bullseye

RUN apt-get update && apt-get upgrade -y

# Install curl and git
RUN apt-get install -y curl git

# Install bazel
RUN curl -L https://github.com/bazelbuild/bazelisk/releases/download/v1.16.0/bazelisk-linux-amd64 > /usr/local/bin/bazelisk && chmod +x /usr/local/bin/bazelisk

# Install latest protobuf compiler (note: protobuf-compiler from apt is an older non-compliant version)
WORKDIR /opt/protobuf
RUN curl -L https://github.com/protocolbuffers/protobuf/releases/download/v21.12/protoc-21.12-linux-x86_64.zip > protoc.zip
RUN unzip protoc.zip && chmod +x ./bin/protoc
RUN ln -s /opt/protobuf/bin/protoc /usr/local/bin/protoc

# Update pip
RUN pip install --upgrade pip

# ...
WORKDIR /app
```

## Known issues

// TODO: Describe issue about chunking that results in up to last 3 characters not being encrypted.
// TODO: Describe issue with minimum length depending on the alphabet radix (e.g. 4 characters for alphanumeric and 6 for digits)

## Contributing

Contributions are very welcome.
To learn more, see the [Contributor Guide].

## License

Distributed under the terms of the [MIT license][license],
_Tink FPE Python_ is free and open source software.

## Issues

If you encounter any problems,
please [file an issue] along with a detailed description.

## Credits

This project was generated from [@cjolowicz]'s [Hypermodern Python Cookiecutter] template.

[@cjolowicz]: https://github.com/cjolowicz
[pypi]: https://pypi.org/
[hypermodern python cookiecutter]: https://github.com/cjolowicz/cookiecutter-hypermodern-python
[file an issue]: https://github.com/statisticsnorway/tink-fpe/issues
[pip]: https://pip.pypa.io/

<!-- github-only -->

[license]: https://github.com/statisticsnorway/tink-fpe-python/blob/main/LICENSE
[contributor guide]: https://github.com/statisticsnorway/tink-fpe-python/blob/main/CONTRIBUTING.md
