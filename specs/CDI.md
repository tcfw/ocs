# CDI - Certificate Distribution Infrastructure

## Introduction

This specification is part of the OCS family.

This specification outlines the mechanisms, formats, semantics and services of distributing certificates and revocation lists using IPFS (the InterPlanetary File System).

## Requirements

The goal of this specification is to develop mechanisms, formats, semantics and services to facilitate the distribution of OCS certificates (see CKI)
in a decentralised and secure manner as signatures of OCS certificates only contain references to certificates to verify signatures and not the certificates themselves. This specification may be used as a primary form of distribution or secondary in the case where it is not ideal to forward an entire signature chain to a receiving party.

The underlying infrastructure should be able to be free of centralised control but will require gateway nodes to store data and facilitate the network.

## Exclusions

This specification does not outline the creation or format of OCS certificates or the Certificate Authority conduct when in PKI or Multi-PKI modes or the format and semantics of encrypted packet message formats.

## IPFS

IPFS (the InterPlanetary File System) will be used as a basis for providing the decentralised network to distribute and store certificates as well as utilise the DHT to store additional metadata to assist in searching for keys that may assist WOT distribution.

IPFS facilitates the heavy lifting of providing distributed features such as storage, pubsub, peer connection, metadata and network traversal.

To speed up discovery and publishing of mutable and immutable data, all IPFS nodes MUST be run in a private network (sub network) using a unique swarm key specific to OCS-CDI and to avoid unnecessary storage caused by bit swapping in the main IPFS network.

## Security

OCS nodes MUST NOT store private keys of certificates. OCS nodes MUST only contain information which is only to be publicly available. OCS nodes MUST validate signatures where available.

## Nodes

Each node MUST contain an IPFS node running in full DHT mode (dht server) and connect only to other OCS nodes using the swarm key.
Nodes MAY provide a web portal whereby end users of certificates may upload certificates to be pinned.
Nodes MAY provide an IPFS-type gateway for retrieving certificates based on signature publicRefs
Nodes MUST NOT store or use OCS nodes to store arbitrary data which is not useful to the overall network and distribution of and revocation of OCS certificates.

## PublicRef

The PublicRef field of a Certificate Signature (struct) should be the multihash reference of the certificate in raw (msgpack) encoding (not PEM). The PublicRef MUST NOT be an IPNS or DNSLink reference as the PublicRef should relate directly to the certificate which was used to sign.

## Certificates

When a certificate is published, it MUST be published using the standard IPFS object add command to avoid unnecessary overhead from UnixFS objects. The certificate object MUST be in msgpack encoding.

## Bootstrap

The OCS node MUST NOT bootstrap to the standard IPFS nodes.

OCS nodes must bootstrap to the follow multiaddrs:
{{TODO}}

## Certificate Publish

Certificates can be published to a node using the Publish Request via an Web API request

## Revoke Lists

An individual certificate revoke can be located via a multihash of the certificate ID and signing certificate ID, stored inside the IPFS DHT coupled with a signature from the signing certificate and a reference to the signed revocation certificate. Format in msgpack MUST be:

- "s" Signature of the cert ID as byte slice
- "rr" Revoke reason as uint8
- "l" Link as block reference string

The signature of the revoke reference MUST match AT LEAST one of the signature in the original certificate.

## Web API

Each node SHOULD implement a common web API structure which is available over HTTPs or similarly secure channels.

The API SHOULD implement the following endpoints:

- /publish - to publish certificates
- /lookup - to lookup certificates using PublicRef, email or cert ID
- /revoke - to publish revoke lists

### Publish Requests

Publish requests list certificates for other users of OCS to download. The Publish request MUST be a HTTP POST request at the URL path "/publish" on the node.

Publish requests SHOULD be in messagepack OR json encoding and MUST include the follow fields:

- "c" the certificate (in raw or PEM)
- "s" a signature from the private key matching the public key in the certificate
- "sd" a cryptographically generated random 32 byte slice to be used to generate the signature "s"

When the certificate is supplied in PEM format, the URL MUST include a query parameter of "pem" where the value is "true" (e.g. "/publish?pem=true")

The OCS node MUST verify the signature using the associated signature data and the public key in the certificate of the request.

The response of the publish request MAY be an error (not http 200) if the signature fails or the certificate cannot be validated (SHOULD not include verification). If the request is successful (http code 200), the response MUST be in plain text format prefixed with "OK " (including the space) and a reference to the IPFS block as a CID string (base58 encoded multihash).

Example response: "OK QmY57CxHKnwk5Ebv4qjpCNE3nyW8ffUqCh74kohgDM2XHs"

## Lookup Requests

The lookup request allows users of OCS to find certificates to complete operations such as verify certificate chains.

The lookup request MUST allow 3 types of lookups; email, publicref or cert ID.

The lookup request MUST be a GET HTTP request at the URL path "/lookup". The response of a lookup request SHOULD either be an error response (not http code 200) and not expose any certificate OR, if successful, the API MUST respond with a http 200 and the found certificate in PEM format.

The lookup request MUST include a type parameter and a data parameter in the URL query. The type parameter MUST be URL query key "t" and be one of the following values:

- "email" to look up by an email
- "id" to look up using a cert ID
- "ref" to look up using the PublicRef
  The data parameter depends on the type "t" value. The data parameter MUST use the URL query key "d" The following values and formats SHOULD be accepted:
- when the type is "email", the data parameter MUST be a valid URL escaped email
- when the type is "id", the data parameter MUST be a URL escaped base64 encoded cert ID
- when the type is "ref", the data parameter MUST be a valid IPFS block reference in CID string (base58) format, matching the output from the Publish request.

Example request: /lookup?t=ref&d=QmY57CxHKnwk5Ebv4qjpCNE3nyW8ffUqCh74kohgDM2XHs

{{TODO}} - include revoked certificate responses

## Revoke Request

{{TODO}}
