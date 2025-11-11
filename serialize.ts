import type {
	AAAARecord,
	ARecord,
	CAARecord,
	CNAMERecord,
	Directive,
	DNAMERecord,
	DNSKEYRecord,
	DSRecord,
	HINFORecord,
	LOCRecord,
	MXRecord,
	NAPTRRecord,
	NSECRecord,
	NSRecord,
	PTRRecord,
	Record,
	RRSIGRecord,
	SOARecord,
	SPFRecord,
	SRVRecord,
	SSHFPRecord,
	TLSARecord,
	TXTRecord,
	ZoneEntry,
	ZONEMDRecord,
} from './mod.ts'

/**
 * Serialize a directive entry to zone file format
 */
function serializeDirective(directive: Directive): string {
	return `${directive.name} ${directive.value}`
}

/**
 * Serialize record data based on record type
 */
function serializeRecordData(record: Record): string {
	switch (record.recordType) {
		case 'SOA': {
			const r = record as SOARecord
			return `${r.data.mname} ${r.data.rname} ${r.data.serial} ${r.data.refresh} ${r.data.retry} ${r.data.expire} ${r.data.minimum}`
		}
		case 'NS': {
			const r = record as NSRecord
			return r.data.ns
		}
		case 'MX': {
			const r = record as MXRecord
			return `${r.data.priority} ${r.data.mx}`
		}
		case 'A': {
			const r = record as ARecord
			return r.data.ip
		}
		case 'AAAA': {
			const r = record as AAAARecord
			return r.data.ip
		}
		case 'CNAME': {
			const r = record as CNAMERecord
			return r.data.cname
		}
		case 'PTR': {
			const r = record as PTRRecord
			return r.data.ptrdname
		}
		case 'TXT': {
			const r = record as TXTRecord
			// Ensure text is quoted if it contains spaces
			const txt = r.data.txt
			return txt.includes(' ') || txt.includes('\t') ? `"${txt}"` : txt
		}
		case 'SRV': {
			const r = record as SRVRecord
			return `${r.data.priority} ${r.data.weight} ${r.data.port} ${r.data.target}`
		}
		case 'CAA': {
			const r = record as CAARecord
			return `${r.data.flags} ${r.data.tag} "${r.data.value}"`
		}
		case 'DNSKEY': {
			const r = record as DNSKEYRecord
			return `${r.data.flags} ${r.data.protocol} ${r.data.algorithm} ${r.data.publicKey}`
		}
		case 'DS': {
			const r = record as DSRecord
			return `${r.data.keyTag} ${r.data.algorithm} ${r.data.digestType} ${r.data.digest}`
		}
		case 'RRSIG': {
			const r = record as RRSIGRecord
			return `${r.data.typeCovered} ${r.data.algorithm} ${r.data.labels} ${r.data.originalTTL} ${r.data.expiration} ${r.data.inception} ${r.data.keyTag} ${r.data.signer} ${r.data.signature}`
		}
		case 'NSEC': {
			const r = record as NSECRecord
			return `${r.data.nextDomain} ${r.data.recordTypes.join(' ')}`
		}
		case 'TLSA': {
			const r = record as TLSARecord
			return `${r.data.usage} ${r.data.selector} ${r.data.matchingType} ${r.data.certificate}`
		}
		case 'SSHFP': {
			const r = record as SSHFPRecord
			return `${r.data.algorithm} ${r.data.fingerprintType} ${r.data.fingerprint}`
		}
		case 'DNAME': {
			const r = record as DNAMERecord
			return r.data.target
		}
		case 'NAPTR': {
			const r = record as NAPTRRecord
			return `${r.data.order} ${r.data.preference} "${r.data.flags}" "${r.data.service}" "${r.data.regexp}" ${r.data.replacement}`
		}
		case 'LOC': {
			const r = record as LOCRecord
			return r.data.content
		}
		case 'HINFO': {
			const r = record as HINFORecord
			return `"${r.data.cpu}" "${r.data.os}"`
		}
		case 'SPF': {
			const r = record as SPFRecord
			return `"${r.data.text}"`
		}
		case 'ZONEMD': {
			const r = record as ZONEMDRecord
			return `${r.data.serial} ${r.data.scheme} ${r.data.hashAlgo} ${r.data.digest}`
		}
	}
}

/**
 * Serialize a record entry to zone file format
 */
function serializeRecord(record: Record): string {
	const parts: string[] = []

	// Domain name (pad to 18 characters for alignment)
	parts.push(record.domain.padEnd(18))

	// TTL (optional) - but don't output for continuation lines (empty domain)
	// Continuation lines inherit TTL from previous record or $TTL directive
	if (record.ttl !== null && record.domain !== '') {
		parts.push(record.ttl.toString().padEnd(6))
	} else {
		parts.push(''.padEnd(6))
	}

	// Class
	parts.push(record.class.padEnd(4))

	// Record type
	parts.push(record.recordType.padEnd(8))

	// Record data
	parts.push(serializeRecordData(record))

	return parts.join(' ').trimEnd()
}

/**
 * Serialize a zone entry (directive or record) to zone file format
 *
 * @param entry - A single zone entry (directive or record)
 * @returns String representation of the entry in zone file format
 *
 * @example Serialize a directive
 * ```ts
 * import { serializeEntry } from 'jsr:@carragom/zonefile-js'
 *
 * const directive: Directive = {
 *   type: 'directive',
 *   name: '$ORIGIN',
 *   value: 'example.com.'
 * }
 *
 * const line = serializeEntry(directive)
 * // "$ORIGIN example.com."
 * ```
 *
 * @example Serialize an A record
 * ```ts
 * const record: ARecord = {
 *   type: 'record',
 *   domain: 'www',
 *   ttl: 3600,
 *   class: 'IN',
 *   recordType: 'A',
 *   data: { ip: '192.0.2.1' }
 * }
 *
 * const line = serializeEntry(record)
 * // "www               3600   IN    A         192.0.2.1"
 * ```
 */
export function serializeEntry(entry: ZoneEntry): string {
	if (entry.type === 'directive') {
		return serializeDirective(entry)
	} else {
		return serializeRecord(entry)
	}
}

/**
 * Serialize an array of zone entries to zone file format
 *
 * @param entries - Array of parsed zone entries
 * @param options - Optional serialization options
 * @param options.includeBlankLines - Add blank lines between different record types for readability (default: false)
 * @returns Zone file content as a string
 *
 * @example Basic serialization
 * ```ts
 * import { parseZone, serializeZone } from 'jsr:@carragom/zonefile-js'
 *
 * const zone = `
 * $ORIGIN example.com.
 * $TTL 86400
 * @  IN  NS  ns1.example.com.
 * @  IN  A   192.0.2.1
 * `
 *
 * const entries = parseZone(zone)
 * const output = serializeZone(entries)
 * console.log(output)
 * ```
 *
 * @example With blank lines for readability
 * ```ts
 * import { serializeZone, type ZoneEntry } from 'jsr:@carragom/zonefile-js'
 *
 * const entries: ZoneEntry[] = [
 *   { type: 'directive', name: '$ORIGIN', value: 'example.com.' },
 *   { type: 'directive', name: '$TTL', value: 86400 },
 *   {
 *     type: 'record',
 *     domain: '@',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'NS',
 *     data: { ns: 'ns1.example.com.' }
 *   },
 *   {
 *     type: 'record',
 *     domain: '@',
 *     ttl: null,
 *     class: 'IN',
 *     recordType: 'A',
 *     data: { ip: '192.0.2.1' }
 *   }
 * ]
 *
 * const output = serializeZone(entries, { includeBlankLines: true })
 * // Blank line will be added between NS and A records
 * ```
 */
export function serializeZone(
	entries: ZoneEntry[],
	options: { includeBlankLines?: boolean } = {},
): string {
	const { includeBlankLines = false } = options
	const lines: string[] = []
	let lastRecordType: string | null = null

	for (const entry of entries) {
		// Add blank line when record type changes (for readability)
		if (
			includeBlankLines &&
			entry.type === 'record' &&
			lastRecordType !== null &&
			lastRecordType !== entry.recordType
		) {
			lines.push('')
		}

		lines.push(serializeEntry(entry))

		if (entry.type === 'record') {
			lastRecordType = entry.recordType
		}
	}

	return lines.join('\n') + '\n'
}

/**
 * Serialize zone entries and write to a file
 *
 * @param filePath - Path to write the zone file
 * @param entries - Array of parsed zone entries
 * @param options - Optional serialization options
 * @param options.includeBlankLines - Add blank lines between different record types for readability (default: false)
 *
 * @example
 * ```ts
 * import { serializeZoneFile, type ZoneEntry } from 'jsr:@carragom/zonefile-js'
 *
 * const entries: ZoneEntry[] = [
 *   { type: 'directive', name: '$ORIGIN', value: 'example.com.' },
 *   { type: 'directive', name: '$TTL', value: 86400 },
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
 *   }
 * ]
 *
 * await serializeZoneFile('./zones/example.com.zone', entries)
 * ```
 */
export async function serializeZoneFile(
	filePath: string,
	entries: ZoneEntry[],
	options: { includeBlankLines?: boolean } = {},
): Promise<void> {
	const content = serializeZone(entries, options)
	await Deno.writeTextFile(filePath, content)
}
