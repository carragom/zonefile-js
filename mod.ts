// @deno-types="./_internal/parser.d.ts"
import * as parser from './_internal/parser.js'

/**
 * A DNS zone file parser and serializer for BIND-style zone files.
 * An {@link https://datatracker.ietf.org/doc/html/rfc1035 | RFC 1035} zone file
 * serializer and parser using {@link https://peggyjs.org/ | Peggy}.
 *
 * Supports parsing and creating 21+ DNS record types including SOA, NS, A, AAAA,
 * MX, CNAME, TXT, SRV, CAA, and various DNSSEC record types.
 *
 * @example Parse a zone file
 * ```ts
 * import { parseZone } from 'jsr:@carragom/zonefile-js'
 *
 * const zone = `
 * $ORIGIN example.com.
 * $TTL 86400
 * @       IN  SOA ns1.example.com. admin.example.com. (
 *                 2023100101 7200 3600 1209600 3600 )
 * @       IN  NS  ns1.example.com.
 * www     IN  A   192.0.2.1
 * `
 *
 * const entries = parseZone(zone, {
 *   expandDomains: true,
 *   inheritTTL: true
 * })
 * ```
 *
 * @example Create zone entries programmatically
 * ```ts
 * import { serializeZone, type ZoneEntry } from 'jsr:@carragom/zonefile-js'
 *
 * const entries: ZoneEntry[] = [
 *   // Directives
 *   { type: 'directive', name: '$ORIGIN', value: 'example.com.' },
 *   { type: 'directive', name: '$TTL', value: 86400 },
 *
 *   // SOA Record
 *   {
 *     type: 'record',
 *     domain: '@',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'SOA',
 *     data: {
 *       mname: 'ns1.example.com.',
 *       rname: 'admin.example.com.',
 *       serial: 2023100101,
 *       refresh: 7200,
 *       retry: 3600,
 *       expire: 1209600,
 *       minimum: 3600
 *     }
 *   },
 *
 *   // NS Record
 *   {
 *     type: 'record',
 *     domain: '@',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'NS',
 *     data: { ns: 'ns1.example.com.' }
 *   },
 *
 *   // A Record
 *   {
 *     type: 'record',
 *     domain: 'www',
 *     ttl: 3600,
 *     class: 'IN',
 *     recordType: 'A',
 *     data: { ip: '192.0.2.1' }
 *   },
 *
 *   // MX Record
 *   {
 *     type: 'record',
 *     domain: '@',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'MX',
 *     data: {
 *       priority: 10,
 *       mx: 'mail.example.com.'
 *     }
 *   },
 *
 *   // TXT Record
 *   {
 *     type: 'record',
 *     domain: '@',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'TXT',
 *     data: { txt: 'v=spf1 mx -all' }
 *   },
 *
 *   // CNAME Record
 *   {
 *     type: 'record',
 *     domain: 'blog',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'CNAME',
 *     data: { cname: 'www.example.com.' }
 *   }
 * ]
 *
 * const zoneFile = serializeZone(entries, { includeBlankLines: true })
 * console.log(zoneFile)
 * ```
 * @module zf
 */

/**
 * Represents a zone file directive ($ORIGIN or $TTL)
 * @example
 * ```ts
 * const originDirective: Directive = {
 *   type: 'directive',
 *   name: '$ORIGIN',
 *   value: 'example.com.'
 * }
 *
 * const ttlDirective: Directive = {
 *   type: 'directive',
 *   name: '$TTL',
 *   value: 86400
 * }
 * ```
 */
export interface Directive {
	/** Entry type identifier */
	type: 'directive'
	/** Directive name (e.g., '$ORIGIN', '$TTL') */
	name: string
	/** Directive value (domain name string for $ORIGIN, number for $TTL) */
	value: string | number
}

/**
 * SOA (Start of Authority) record data
 * @example
 * ```ts
 * const soaData: SOAData = {
 *   mname: 'ns1.example.com.',
 *   rname: 'admin.example.com.',
 *   serial: 2023100101,
 *   refresh: 7200,
 *   retry: 3600,
 *   expire: 1209600,
 *   minimum: 3600
 * }
 * ```
 */
export interface SOAData {
	/** Primary name server for the zone */
	mname: string
	/** Email address of the zone administrator (with @ replaced by .) */
	rname: string
	/** Zone serial number */
	serial: number
	/** Refresh interval in seconds */
	refresh: number
	/** Retry interval in seconds */
	retry: number
	/** Expiration time in seconds */
	expire: number
	/** Minimum TTL for negative caching */
	minimum: number
}

/**
 * NS (Name Server) record data
 */
export interface NSData {
	/** Name server domain name */
	ns: string
}

/**
 * MX (Mail Exchange) record data
 */
export interface MXData {
	/** Mail server priority (lower values have higher priority) */
	priority: number
	/** Mail server domain name */
	mx: string
}

/**
 * A (IPv4 Address) record data
 */
export interface AData {
	/** IPv4 address */
	ip: string
}

/**
 * AAAA (IPv6 Address) record data
 */
export interface AAAAData {
	/** IPv6 address */
	ip: string
}

/**
 * CNAME (Canonical Name) record data
 */
export interface CNAMEData {
	/** Canonical (target) domain name */
	cname: string
}

/**
 * PTR (Pointer) record data for reverse DNS lookups
 */
export interface PTRData {
	/** Domain name pointer */
	ptrdname: string
}

/**
 * TXT (Text) record data
 */
export interface TXTData {
	/** Text content */
	txt: string
}

/**
 * SRV (Service) record data
 */
export interface SRVData {
	/** Priority (lower values have higher priority) */
	priority: number
	/** Weight for records with the same priority */
	weight: number
	/** Service port number */
	port: number
	/** Target hostname */
	target: string
}

/**
 * CAA (Certification Authority Authorization) record data
 */
export interface CAAData {
	/** Flags (0 or 128 for critical) */
	flags: number
	/** Property tag (e.g., 'issue', 'issuewild', 'iodef') */
	tag: string
	/** Property value */
	value: string
}

/**
 * DNSKEY (DNS Public Key) record data for DNSSEC
 */
export interface DNSKEYData {
	/** Key flags */
	flags: number
	/** Protocol (always 3) */
	protocol: number
	/** Cryptographic algorithm identifier */
	algorithm: number
	/** Base64-encoded public key */
	publicKey: string
}

/**
 * DS (Delegation Signer) record data for DNSSEC
 */
export interface DSData {
	/** Key tag of the referenced DNSKEY */
	keyTag: number
	/** Cryptographic algorithm identifier */
	algorithm: number
	/** Digest algorithm identifier */
	digestType: number
	/** Hexadecimal digest of the DNSKEY */
	digest: string
}

/**
 * RRSIG (Resource Record Signature) record data for DNSSEC
 */
export interface RRSIGData {
	/** Type of RR covered by this signature */
	typeCovered: string
	/** Cryptographic algorithm identifier */
	algorithm: number
	/** Number of labels in the original RRSIG RR owner name */
	labels: number
	/** Original TTL of the covered RRset */
	originalTTL: number
	/** Signature expiration time (Unix timestamp) */
	expiration: number
	/** Signature inception time (Unix timestamp) */
	inception: number
	/** Key tag of the DNSKEY used to sign */
	keyTag: number
	/** Signer's domain name */
	signer: string
	/** Base64-encoded signature */
	signature: string
}

/**
 * NSEC (Next Secure) record data for DNSSEC authenticated denial of existence
 */
export interface NSECData {
	/** Next domain name in canonical order */
	nextDomain: string
	/** Array of RR types that exist at the owner name */
	recordTypes: string[]
}

/**
 * TLSA (TLS Authentication) record data for DANE
 */
export interface TLSAData {
	/** Certificate usage (0-3) */
	usage: number
	/** Selector (0=full cert, 1=SubjectPublicKeyInfo) */
	selector: number
	/** Matching type (0=exact, 1=SHA-256, 2=SHA-512) */
	matchingType: number
	/** Hexadecimal certificate association data */
	certificate: string
}

/**
 * SSHFP (SSH Fingerprint) record data
 */
export interface SSHFPData {
	/** Public key algorithm (1=RSA, 2=DSA, 3=ECDSA, 4=Ed25519) */
	algorithm: number
	/** Fingerprint type (1=SHA-1, 2=SHA-256) */
	fingerprintType: number
	/** Hexadecimal fingerprint */
	fingerprint: string
}

/**
 * DNAME (Delegation Name) record data
 */
export interface DNAMEData {
	/** Target domain name for redirection */
	target: string
}

/**
 * NAPTR (Naming Authority Pointer) record data for URI/service mapping
 */
export interface NAPTRData {
	/** Order preference (lower values processed first) */
	order: number
	/** Preference for records with same order */
	preference: number
	/** Flags controlling rewrite and lookup behavior */
	flags: string
	/** Service parameters */
	service: string
	/** Regular expression for rewriting */
	regexp: string
	/** Replacement domain name */
	replacement: string
}

/**
 * LOC (Location) record data for geographical location
 */
export interface LOCData {
	/** Location information as a string */
	content: string
}

/**
 * HINFO (Host Information) record data
 */
export interface HINFOData {
	/** CPU/hardware type */
	cpu: string
	/** Operating system type */
	os: string
}

/**
 * SPF (Sender Policy Framework) record data
 */
export interface SPFData {
	/** SPF policy text */
	text: string
}

/**
 * ZONEMD (Zone Message Digest) record data for zone integrity verification
 */
export interface ZONEMDData {
	/** SOA serial number of the zone */
	serial: number
	/** Digest scheme (1=SIMPLE) */
	scheme: number
	/** Hash algorithm identifier */
	hashAlgo: number
	/** Hexadecimal digest of the zone */
	digest: string
}

/**
 * Base interface for all DNS resource records
 */
export interface RRecord {
	/** Entry type identifier */
	type: 'record'
	/** Domain name (may be relative, @ for current origin, or FQDN with trailing dot) */
	domain: string
	/** Time-to-live in seconds (null if not specified) */
	ttl: number | null
	/** DNS class (typically 'IN' for Internet) */
	class: string
	/** DNS record type (e.g., 'A', 'MX', 'SOA') */
	recordType: string
	/** Record-specific data */
	data: unknown
}

/** SOA record with typed data */
export interface SOARecord extends RRecord {
	recordType: 'SOA'
	data: SOAData
}

/** NS record with typed data */
export interface NSRecord extends RRecord {
	recordType: 'NS'
	data: NSData
}

/** MX record with typed data */
export interface MXRecord extends RRecord {
	recordType: 'MX'
	data: MXData
}

/** A record with typed data */
export interface ARecord extends RRecord {
	recordType: 'A'
	data: AData
}

/** AAAA record with typed data */
export interface AAAARecord extends RRecord {
	recordType: 'AAAA'
	data: AAAAData
}

/** CNAME record with typed data */
export interface CNAMERecord extends RRecord {
	recordType: 'CNAME'
	data: CNAMEData
}

/** PTR record with typed data */
export interface PTRRecord extends RRecord {
	recordType: 'PTR'
	data: PTRData
}

/** TXT record with typed data */
export interface TXTRecord extends RRecord {
	recordType: 'TXT'
	data: TXTData
}

/** SRV record with typed data */
export interface SRVRecord extends RRecord {
	recordType: 'SRV'
	data: SRVData
}

/** CAA record with typed data */
export interface CAARecord extends RRecord {
	recordType: 'CAA'
	data: CAAData
}

/** DNSKEY record with typed data */
export interface DNSKEYRecord extends RRecord {
	recordType: 'DNSKEY'
	data: DNSKEYData
}

/** DS record with typed data */
export interface DSRecord extends RRecord {
	recordType: 'DS'
	data: DSData
}

/** RRSIG record with typed data */
export interface RRSIGRecord extends RRecord {
	recordType: 'RRSIG'
	data: RRSIGData
}

/** NSEC record with typed data */
export interface NSECRecord extends RRecord {
	recordType: 'NSEC'
	data: NSECData
}

/** TLSA record with typed data */
export interface TLSARecord extends RRecord {
	recordType: 'TLSA'
	data: TLSAData
}

/** SSHFP record with typed data */
export interface SSHFPRecord extends RRecord {
	recordType: 'SSHFP'
	data: SSHFPData
}

/** DNAME record with typed data */
export interface DNAMERecord extends RRecord {
	recordType: 'DNAME'
	data: DNAMEData
}

/** NAPTR record with typed data */
export interface NAPTRRecord extends RRecord {
	recordType: 'NAPTR'
	data: NAPTRData
}

/** LOC record with typed data */
export interface LOCRecord extends RRecord {
	recordType: 'LOC'
	data: LOCData
}

/** HINFO record with typed data */
export interface HINFORecord extends RRecord {
	recordType: 'HINFO'
	data: HINFOData
}

/** SPF record with typed data */
export interface SPFRecord extends RRecord {
	recordType: 'SPF'
	data: SPFData
}

/** ZONEMD record with typed data */
export interface ZONEMDRecord extends RRecord {
	recordType: 'ZONEMD'
	data: ZONEMDData
}

/**
 * Union type of all supported DNS record types
 */
export type Record =
	| SOARecord
	| NSRecord
	| MXRecord
	| ARecord
	| AAAARecord
	| CNAMERecord
	| PTRRecord
	| TXTRecord
	| SRVRecord
	| CAARecord
	| DNSKEYRecord
	| DSRecord
	| RRSIGRecord
	| NSECRecord
	| TLSARecord
	| SSHFPRecord
	| DNAMERecord
	| NAPTRRecord
	| LOCRecord
	| HINFORecord
	| SPFRecord
	| ZONEMDRecord

/**
 * A zone file entry - either a directive or a DNS record
 */
export type ZoneEntry = Directive | Record

/**
 * Options for parsing DNS zone files
 */
export interface ParseOptions {
	/**
	 * Whether to expand domain names using $ORIGIN directive
	 * - @ expands to current origin (e.g., example.com.)
	 * - Relative names get origin appended (e.g., ns -> ns.example.com.)
	 * - FQDNs (ending with .) remain unchanged
	 * @default false
	 */
	expandDomains?: boolean

	/**
	 * Whether to inherit TTL values from $TTL directive
	 * - Records without explicit TTL will use current $TTL value
	 * - Records with explicit TTL always use their own value
	 * @default false
	 */
	inheritTTL?: boolean
}

/**
 * Parse a DNS zone file string into structured data
 *
 * @param zoneFileContent - The zone file content as a string
 * @param options - Optional parsing options
 * @returns Array of parsed zone entries (directives and records)
 *
 * @example Basic parsing
 * ```ts
 * import { parseZone } from 'jsr:@carragom/zonefile-js'
 *
 * const zone = `
 * $ORIGIN example.com.
 * $TTL 86400
 * @       IN  SOA ns1.example.com. admin.example.com. (
 *                 2023100101 7200 3600 1209600 3600 )
 * @       IN  NS  ns1.example.com.
 * www     IN  A   192.0.2.1
 * `
 *
 * const entries = parseZone(zone)
 * // Returns array of Directive and Record objects
 * ```
 *
 * @example With domain expansion
 * ```ts
 * const zone = `
 * $ORIGIN example.com.
 * @       IN  A   192.0.2.1
 * www     IN  A   192.0.2.2
 * `
 *
 * const entries = parseZone(zone, { expandDomains: true })
 * // entries[0].domain === "example.com."
 * // entries[1].domain === "www.example.com."
 * ```
 *
 * @example With TTL inheritance
 * ```ts
 * const zone = `
 * $TTL 86400
 * example.com.  3600  IN  NS  ns1.example.com.
 * example.com.        IN  A   192.0.2.1
 * `
 *
 * const entries = parseZone(zone, { inheritTTL: true })
 * // entries[0].ttl === 3600 (explicit)
 * // entries[1].ttl === 86400 (inherited from $TTL)
 * ```
 */
export function parseZone(
	zoneFileContent: string,
	options?: ParseOptions,
): ZoneEntry[] {
	return parser.parse(zoneFileContent, options)
}

/**
 * Parse a DNS zone file from a file path
 *
 * @param filePath - Path to the zone file
 * @param options - Optional parsing options
 * @returns Promise resolving to array of parsed zone entries
 *
 * @example
 * ```ts
 * import { parseZoneFile } from 'jsr:@carragom/zonefile-js'
 *
 * const entries = await parseZoneFile('./zones/example.com.zone', {
 *   expandDomains: true,
 *   inheritTTL: true
 * })
 *
 * for (const entry of entries) {
 *   if (entry.type === 'record' && entry.recordType === 'A') {
 *     console.log(`${entry.domain} -> ${entry.data.ip}`)
 *   }
 * }
 * ```
 */
export async function parseZoneFile(
	filePath: string,
	options?: ParseOptions,
): Promise<ZoneEntry[]> {
	const content = await Deno.readTextFile(filePath)
	return parseZone(content, options)
}

// Re-export serialization functions
export {
	serializeEntry,
	serializeZone,
	serializeZoneFile,
} from './serialize.ts'
