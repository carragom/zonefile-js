# ZoneFileJS

An [RFC 1035](https://datatracker.ietf.org/doc/html/rfc1035) zone file
serializer and parser using [Peggy](https://peggyjs.org/)

**[📚 Full Documentation & API Reference on JSR →](https://jsr.io/@carragom/zonefile-js)**

## Features

- Parse BIND-style DNS zone files
- Support for 21+ DNS record types (SOA, NS, A, AAAA, MX, CNAME, TXT, SRV, CAA,
  DNSSEC records, and more)
- Optional `$ORIGIN` domain expansion
- Optional `$TTL` inheritance
- Serialize parsed zones back to zone file format
- Full TypeScript support with comprehensive type definitions

## Supported Record Types

- SOA - Start of Authority
- NS - Name Server
- A - IPv4 Address
- AAAA - IPv6 Address
- MX - Mail Exchange
- CNAME - Canonical Name
- PTR - Pointer (for reverse DNS)
- TXT - Text
- SRV - Service
- CAA - Certification Authority Authorization
- DNSKEY - DNS Public Key
- DS - Delegation Signer
- RRSIG - Resource Record Signature
- NSEC - Next Secure
- TLSA - TLS Authentication
- SSHFP - SSH Fingerprint
- DNAME - Delegation Name
- NAPTR - Naming Authority Pointer
- LOC - Location
- HINFO - Host Information
- SPF - Sender Policy Framework
- ZONEMD - Zone Message Digest

## Supported Directives

- **`$ORIGIN`** - Set the origin (domain name) for relative domain names
- **`$TTL`** - Set the default TTL for subsequent records

## Usupported Directives

### RFC 1035 Standard Directive

- **`$INCLUDE <filename> [origin]`** - Include another zone file
  - Not implemented due to complexity around file system access and security
    considerations
  - **Workaround:** Manually merge zone files or preprocess them before parsing

### BIND-Specific Extensions

No plans to implement

- **`$GENERATE`**
- **`$DATE`**

## Development

If you want to modify the parser grammar, follow these steps:

### Change The Grammar

Modify the grammar file `_internal/parser.peggy` as required.

### Test The New Grammar

Manually test the new grammar with a zone file that uses the new features:

```
deno run -RE npm:peggy@5 -T test.zone _internal/parser.peggy
```

### Regenerate Parser

If everything works as expected, regenerate `_internal/parser.js` from
`_internal/parser.peggy`:

```
deno task generate:parser
```

### Validate Syntax

Check for possible syntax/typing errors:

```
deno check
```

### Validate Linting

Check for linting errors:

```
deno lint
```

### Format Code

Format code:

```
deno fmt
```

### Run Tests

Run the testing suite to ensure everything works:

```
deno test -P
```

### Run Benchmarks

Optionally check the benchmarks:

```
deno bench -P
```
