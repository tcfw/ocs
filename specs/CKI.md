# CKI - Certificate and Key Infrastructure

## Introduction

This specification is part of the OCS family.

This specification outlines the format and semantics of certificates and private keys.

## Requirements

The goal of this specification is to develop a format and semantics to facilitate the use of OCS certificates and associated
private keys within applications to expand and develop an evolved PKI/WOT or multi-PKI environment. Such applications might include
but not limited to WWW, email, user authentication, service authentication, encrypted messages and/or signatures. Each certificate
with it's specific mode set, may facilitate PKI, WOT or Multi-PKI infrastructures.

## Exclusions

This specification does not outline certificate distribution, certificate revocation distribution or Certificate Authority conduct when in PKI and multi-PKI modes or the format and semantics of encrypted packet message formats.

## Certificate Modes

### PKI

PKI mode MUST operate with a SINGLE signature from a well known certificate authority. This is similar to X.509 PKI. For the signature
to be valid, the signing certificate/private key MUST be trusted or ultimately trusted OR containing a certificate in the signature chain which is trusted or ultimately trusted. The signing certificate and all certificates in the signature chain MUST have Certificate Authority flag as True.

### WOT

WOT, Web of Trust, mode SHOULD operate with AT LEAST one or more other signatures from certificates which MAY be indirectly-trusted, trusted, and/or ultimately trusted. If the signing certificate used to sign the immediate certificate is untrusted, said signing certificate SHOULD be signed by a trusted or ultimately trusted certificate OR contain a certificate in it's signing chain which is trusted or ultimately trusted. This is similar to the PGP/OpenPGP Web-of-Trust model.

The certificate MUST be self-signed.

### Multi-PKI

Multi-PKI, MPKI, mode MUST operate with AT LEAST one or more signatures from well known certificate authorities. Similar to normal PKI mode, for the signatures to be valid, each signing certificate/private key MUST be trusted or ultimately trusted OR containing a certificate in the signature chain which is trusted or ultimately trusted. Each signing certificate and all certificates in each signature chain MUST have a Certificate Authority flag as True.

---

## OCS Version 1 Certificate

Certificates must be encoded using MessagePack (msgpack) - See https://msgpack.org/

### Basic Fields

Version, CertType, Algo, ID, PublicKey, Subject, NotBefore and NotAfter MUST have a value.
Optionally, Entity, IsCA, Extensions and Revoke MAY be set.

For signatures, the data is to be encoded using msgpack.

Certificate fields MUST use the shorthand map key as follows when encoded using MessagePack:

- "v": Version as a uint8
- "t": CertType as a uint8
- "a": Algorithm/Algo as a uint16
- "c": Unique certificate ID as a byte slice
- "ca": IsCA as a bool
- "pk": Public Key as a byte slice
- "nb": Not Before as a timestamp
- "na": Not After as a timestamp
- "r": Revoke as a bool
- "s": Subject as a string
- "e": Entity (structure)
- "s": Signature list (go slice)
- "x": Extension

Entity fields MUST use the shorthand map key as follows when encoded using MessagePack:

- "o": Name/Organisation as a string
- "ou": Organisation Unit as a string
- "l": Locality as a string
- "st": State as a string
- "c": Country as a string
- "e": Email as a string

Signature fields MUST use the shorthand map key as follows when encoded using MessagePack:

- "c": Signing certificates unique ID as byte slice
- "a": Algorithm as uint8
- "s": Signature as a byte slice
- "p": Public Reference as byte slice

Extension fields MUST use the shorthand map key as follos when encoded using MessagePack:

- "t": Type as uint16
- "d": Data as byte slice

### CertType

The certificate type relates to the verification mode of which the certificate is intended to be used for. The type is indexed into a uint8 space as follows:

- 0: unknown/not set
- 1: PKI mode
- 2: Web of trust mode
- 3: Multi-PKI mode

### ID

The certificates ID SHOULD be cryptographically unique and MUST be 32 bytes long. Certificate IDs MUST be generated by a strong random source to attempt to avoid collision. The certificate ID identifies the certificate at time of generation. A CA or signing party MAY use any combination of the basic fields along with the certificate ID during identity verification before signing. Implementations SHOULD NOT assume that IDs are totally unique.

### Signature (struct)

The signature MUST contain the algorithm identifier used for the digital signature, unique certificate ID and digital signature. The signature MAY contain the public reference of the public certificate.

Signatures MUST NOT sign other signatures.

For the value of PublicRef, see the specs.

#### Signature Value

The signature value contains the digital signature computed upon a SHA3-512 of the msgpack encoding of ALL fields in the certificate EXCLUDING the signature list as well as the addition of the signing certificates ID appended to the byte slice result of the encoding.

By generating the signature, a CA certifies the validity of the information in the certificate fields.

### Algo/Algorithm

The cryptographic asymmetric key algorithms used to sign and verify signatures and in turn used for authentication for services like WWW etc.

Each algorithm and associated parameters are allocated a unique identifier in the 8 bit uint8 space as follows:

- 0: unknown/not set
- 1: ED25519
- 2: ECDSA using curve NIST P-256 (secp256r1)
- 3: ECDSA using curve NIST P-384 (secp384r1)
- 4: 2048 bit RSA PKCS1v15
- 5: 4096 bit RSA PKCS1v15

### Version

This field describes the version of the encoded certificate. The version MUST be set to 1.

### Entity

The entity fields and structure closely relate to the X.500 set of attributes to identify the entity to which the certificate is intended for. CAs SHOULD use the information during identity verification before signing. Certificate users SHOULD complete as many attributes as possible.

### Validity

THe certificate validity period is the time interval during which the signing parties will maintain information about the status of the certificate.

For a certificate to pass initial validation, the NotBefore timestamp MUST be before the time of validation and the NotAfter timestamp MUST be after the time of validation, inclusively.

The NotAfter timestamp SHOULD not be longer than 365 days after the NotBefore timestamp

### Subject

The subject field contextually relates to the use of the certificate.

If the certificate type is in WOT mode, the subject MAY contain the email address the certificate is intended to be used for.

If the certificate type is in PKI or Multi-PKI mode, the subject MAY be used for DNS based verification and SHOULD be treated as the CN (Common name).

### Public Key

The public key field MUST contain the public key of which was generated during the private key of which the certificate will be used for. The public key MUST match the Algo field type and MUST be used when signing other certificates.

The encoding of the public key depends on the type of algorithm used when generating the private key, SHOULD be in msgpack encoding.

### Encrypted Private Keys

Private keys should be stored in the encrypted format. The private key MUST be encrypted in AES-256-GCM using a argon2id derived key (times: 2, memory: 64kb, threads: 2) with a cryptographically random salt of 32 byte. The salt should be stored at the beginning of the byte slice followed by a nonce. The salt MUST be used as additional data in the encryption.

### Extensions

Extensions allow storing optional additional or abitrary data within the certificates. Each extensions must have a registered type ID set as a unsigned 16 bit integer acompanied by a byte slice of data related to the type. 