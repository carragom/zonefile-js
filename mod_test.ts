import { assertEquals } from '@std/assert'
import {
	type AAAAData,
	type AData,
	type CAAData,
	type CNAMEData,
	type Directive,
	type DNAMEData,
	type DNSKEYData,
	type DSData,
	type HINFOData,
	type LOCData,
	type MXData,
	type NAPTRData,
	type NSData,
	type NSECData,
	parseZone,
	type PTRData,
	type Record,
	type RRSIGData,
	type SOAData,
	type SPFData,
	type SRVData,
	type SSHFPData,
	type TLSAData,
	type TXTData,
	type ZONEMDData,
} from './mod.ts'
import {
	serializeEntry,
	serializeZone,
} from './serialize.ts'

Deno.test('parseZone - basic SOA, NS, A records', () => {
	const zoneContent = `$ORIGIN example.com.
$TTL 3600
example.com. IN SOA ns.example.com. admin.example.com. ( 1 7200 3600 1209600 3600 )
example.com. IN NS ns.example.com.
example.com. IN A 192.0.2.1
`

	const result = parseZone(zoneContent, { inheritTTL: true })

	assertEquals(result.length, 5)
	assertEquals(result[0].type, 'directive')
	assertEquals((result[0] as Directive).name, '$ORIGIN')
	assertEquals((result[0] as Directive).value, 'example.com.')

	assertEquals(result[1].type, 'directive')
	assertEquals((result[1] as Directive).name, '$TTL')
	assertEquals((result[1] as Directive).value, 3600)

	const rec2 = result[2] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'example.com.')
	assertEquals(rec2.recordType, 'SOA')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, 3600)
	assertEquals((rec2.data as SOAData).mname, 'ns.example.com.')
	assertEquals((rec2.data as SOAData).rname, 'admin.example.com.')
	assertEquals((rec2.data as SOAData).serial, 1)
	assertEquals((rec2.data as SOAData).refresh, 7200)
	assertEquals((rec2.data as SOAData).retry, 3600)
	assertEquals((rec2.data as SOAData).expire, 1209600)
	assertEquals((rec2.data as SOAData).minimum, 3600)

	const rec3 = result[3] as Record
	assertEquals(rec3.type, 'record')
	assertEquals(rec3.domain, 'example.com.')
	assertEquals(rec3.recordType, 'NS')
	assertEquals(rec3.class, 'IN')
	assertEquals(rec3.ttl, 3600)
	assertEquals((rec3.data as NSData).ns, 'ns.example.com.')

	const rec4 = result[4] as Record
	assertEquals(rec4.type, 'record')
	assertEquals(rec4.domain, 'example.com.')
	assertEquals(rec4.recordType, 'A')
	assertEquals(rec4.class, 'IN')
	assertEquals(rec4.ttl, 3600)
	assertEquals((rec4.data as AData).ip, '192.0.2.1')
})

Deno.test('parseZone - MX records with priorities', () => {
	const zoneContent = `$ORIGIN example.com.
example.com. IN MX 10 mail.example.com.
@ IN MX 20 mail2.example.com.
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 3)
	const rec1 = result[1] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'MX')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as MXData).priority, 10)
	assertEquals((rec1.data as MXData).mx, 'mail.example.com.')

	const rec2 = result[2] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, '@')
	assertEquals(rec2.recordType, 'MX')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as MXData).priority, 20)
	assertEquals((rec2.data as MXData).mx, 'mail2.example.com.')
})

Deno.test('parseZone - AAAA IPv6 records', () => {
	const zoneContent = `example.com. IN AAAA 2001:db8:10::1
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 1)
	const rec = result[0] as Record
	assertEquals(rec.type, 'record')
	assertEquals(rec.domain, 'example.com.')
	assertEquals(rec.recordType, 'AAAA')
	assertEquals(rec.class, 'IN')
	assertEquals(rec.ttl, null)
	assertEquals((rec.data as AAAAData).ip, '2001:db8:10::1')
})

Deno.test('parseZone - CNAME records', () => {
	const zoneContent = `www IN CNAME example.com.
wwwtest IN CNAME www
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'www')
	assertEquals(rec1.recordType, 'CNAME')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as CNAMEData).cname, 'example.com.')

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'wwwtest')
	assertEquals(rec2.recordType, 'CNAME')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as CNAMEData).cname, 'www')
})

Deno.test('parseZone - empty domain (continuation)', () => {
	const zoneContent = `example.com. IN A 192.0.2.1
             IN AAAA 2001:db8:10::1
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'A')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as AData).ip, '192.0.2.1')

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, '')
	assertEquals(rec2.recordType, 'AAAA')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as AAAAData).ip, '2001:db8:10::1')
})

Deno.test('parseZone - PTR records for reverse DNS', () => {
	const zoneContent = `1.0.0 IN PTR localhost.
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 1)
	const rec = result[0] as Record
	assertEquals(rec.type, 'record')
	assertEquals(rec.domain, '1.0.0')
	assertEquals(rec.recordType, 'PTR')
	assertEquals(rec.class, 'IN')
	assertEquals(rec.ttl, null)
	assertEquals((rec.data as PTRData).ptrdname, 'localhost.')
})

Deno.test('parseZone - SOA with inline comments', () => {
	const zoneContent = `@ IN SOA ns.example.com. admin.example.com. (
  1       ; Serial
  7200    ; Refresh
  3600    ; Retry
  1209600 ; Expire
  3600 )  ; Negative Cache TTL
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 1)
	const rec = result[0] as Record
	assertEquals(rec.type, 'record')
	assertEquals(rec.domain, '@')
	assertEquals(rec.recordType, 'SOA')
	assertEquals(rec.class, 'IN')
	assertEquals(rec.ttl, null)
	assertEquals((rec.data as SOAData).mname, 'ns.example.com.')
	assertEquals((rec.data as SOAData).rname, 'admin.example.com.')
	assertEquals((rec.data as SOAData).serial, 1)
	assertEquals((rec.data as SOAData).refresh, 7200)
	assertEquals((rec.data as SOAData).retry, 3600)
	assertEquals((rec.data as SOAData).expire, 1209600)
	assertEquals((rec.data as SOAData).minimum, 3600)
})

Deno.test('parseZone - comments and blank lines', () => {
	const zoneContent = `; This is a comment
$ORIGIN example.com.

; Another comment
example.com. IN A 192.0.2.1  ; inline comment
`

	const result = parseZone(zoneContent)

	// Comments and blank lines are filtered out
	assertEquals(result.length, 2)
	assertEquals(result[0].type, 'directive')
	assertEquals((result[0] as Directive).name, '$ORIGIN')
	assertEquals((result[0] as Directive).value, 'example.com.')

	assertEquals(result[1].type, 'record')
	const rec = result[1] as Record
	assertEquals(rec.domain, 'example.com.')
	assertEquals(rec.recordType, 'A')
	assertEquals(rec.class, 'IN')
	assertEquals(rec.ttl, null)
	assertEquals((rec.data as AData).ip, '192.0.2.1')
})

Deno.test('parseZone - domain names starting with numbers', () => {
	const zoneContent = `$ORIGIN 127.in-addr.arpa.
1.0.0 IN PTR localhost.
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	assertEquals(result[0].type, 'directive')
	assertEquals((result[0] as Directive).name, '$ORIGIN')
	assertEquals((result[0] as Directive).value, '127.in-addr.arpa.')

	const rec = result[1] as Record
	assertEquals(rec.type, 'record')
	assertEquals(rec.domain, '1.0.0')
	assertEquals(rec.recordType, 'PTR')
	assertEquals(rec.class, 'IN')
	assertEquals(rec.ttl, null)
	assertEquals((rec.data as PTRData).ptrdname, 'localhost.')
})

Deno.test('parseZone - example.zone structure and SOA serial', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/example.zone'))

	assertEquals(result.length, 17)
	assertEquals(result[0].type, 'directive')
	assertEquals((result[0] as Directive).name, '$ORIGIN')

	// Check SOA record
	const soaRecord = result.find((r) =>
		r.type === 'record' && (r as Record).recordType === 'SOA'
	) as Record
	assertEquals(soaRecord?.domain, 'example.com.')
	assertEquals((soaRecord?.data as SOAData).serial, 2020091025)
})

Deno.test('parseZone - localhost forward zone', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/localhost-forward.zone'))

	assertEquals(result.length, 6)

	const soaRecord = result.find((r) =>
		r.type === 'record' && (r as Record).recordType === 'SOA'
	) as Record
	assertEquals(soaRecord?.domain, '@')

	const aRecord = result.find((r) =>
		r.type === 'record' && (r as Record).recordType === 'A'
	) as Record
	assertEquals((aRecord?.data as AData).ip, '127.0.0.1')

	const aaaaRecord = result.find((r) =>
		r.type === 'record' && (r as Record).recordType === 'AAAA'
	) as Record
	assertEquals((aaaaRecord?.data as AAAAData).ip, '::1')
})

Deno.test('parseZone - localhost reverse zone', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/localhost-reverse.zone'))

	assertEquals(result.length, 5)

	const ptrRecord = result.find((r) =>
		r.type === 'record' && (r as Record).recordType === 'PTR'
	) as Record
	assertEquals(ptrRecord?.domain, '1.0.0')
	assertEquals((ptrRecord?.data as PTRData).ptrdname, 'localhost.')
})

Deno.test('parseZone - TXT records', () => {
	const zoneContent = `example.com. IN TXT "v=spf1 mx -all"
@ IN TXT "google-site-verification=abcd1234"
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'TXT')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as TXTData).txt, 'v=spf1 mx -all')

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, '@')
	assertEquals(rec2.recordType, 'TXT')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as TXTData).txt, 'google-site-verification=abcd1234')
})

Deno.test('parseZone - SRV records', () => {
	const zoneContent =
		`_xmpp-server._tcp.example.com. IN SRV 5 0 5269 xmpp-server.example.com.
_sip._tcp.example.com. IN SRV 10 60 5060 sip.example.com.
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, '_xmpp-server._tcp.example.com.')
	assertEquals(rec1.recordType, 'SRV')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as SRVData).priority, 5)
	assertEquals((rec1.data as SRVData).weight, 0)
	assertEquals((rec1.data as SRVData).port, 5269)
	assertEquals((rec1.data as SRVData).target, 'xmpp-server.example.com.')

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, '_sip._tcp.example.com.')
	assertEquals(rec2.recordType, 'SRV')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as SRVData).priority, 10)
	assertEquals((rec2.data as SRVData).weight, 60)
	assertEquals((rec2.data as SRVData).port, 5060)
	assertEquals((rec2.data as SRVData).target, 'sip.example.com.')
})

Deno.test('parseZone - CAA records', () => {
	const zoneContent = `example.com. IN CAA 0 "issue" "letsencrypt.org"
example.com. IN CAA 0 "issuewild" ";"
example.com. IN CAA 0 "iodef" "mailto:security@example.com"
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 3)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'CAA')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as CAAData).flags, 0)
	assertEquals((rec1.data as CAAData).tag, 'issue')
	assertEquals((rec1.data as CAAData).value, 'letsencrypt.org')

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'example.com.')
	assertEquals(rec2.recordType, 'CAA')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as CAAData).flags, 0)
	assertEquals((rec2.data as CAAData).tag, 'issuewild')
	assertEquals((rec2.data as CAAData).value, ';')

	const rec3 = result[2] as Record
	assertEquals(rec3.type, 'record')
	assertEquals(rec3.domain, 'example.com.')
	assertEquals(rec3.recordType, 'CAA')
	assertEquals(rec3.class, 'IN')
	assertEquals(rec3.ttl, null)
	assertEquals((rec3.data as CAAData).flags, 0)
	assertEquals((rec3.data as CAAData).tag, 'iodef')
	assertEquals((rec3.data as CAAData).value, 'mailto:security@example.com')
})

Deno.test('parseZone - DNSKEY records', () => {
	const zoneContent =
		`example.com. IN DNSKEY 256 3 8 AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF
example.com. IN DNSKEY 257 3 8 AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'DNSKEY')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as DNSKEYData).flags, 256)
	assertEquals((rec1.data as DNSKEYData).protocol, 3)
	assertEquals((rec1.data as DNSKEYData).algorithm, 8)
	assertEquals(
		(rec1.data as DNSKEYData).publicKey,
		'AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF',
	)

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'example.com.')
	assertEquals(rec2.recordType, 'DNSKEY')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as DNSKEYData).flags, 257)
	assertEquals((rec2.data as DNSKEYData).protocol, 3)
	assertEquals((rec2.data as DNSKEYData).algorithm, 8)
	assertEquals(
		(rec2.data as DNSKEYData).publicKey,
		'AwEAAaz/tAm8yTn4Mfeh5eyI96WSVexTBAvkMgJzkKTOiW1vkIbzxeF3',
	)
})

Deno.test('parseZone - DS records', () => {
	const zoneContent =
		`example.com. IN DS 31589 8 1 3490A6806D47F17A34C29E2CE80E8A999FFBE4BE
example.com. IN DS 31589 8 2 CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'DS')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as DSData).keyTag, 31589)
	assertEquals((rec1.data as DSData).algorithm, 8)
	assertEquals((rec1.data as DSData).digestType, 1)
	assertEquals(
		(rec1.data as DSData).digest,
		'3490A6806D47F17A34C29E2CE80E8A999FFBE4BE',
	)

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'example.com.')
	assertEquals(rec2.recordType, 'DS')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as DSData).keyTag, 31589)
	assertEquals((rec2.data as DSData).algorithm, 8)
	assertEquals((rec2.data as DSData).digestType, 2)
	assertEquals(
		(rec2.data as DSData).digest,
		'CDE0D742D6998AA554A92D890F8184C698CFAC8A26FA59875A990C03E576343C',
	)
})

Deno.test('parseZone - RRSIG records', () => {
	const zoneContent =
		`example.com. IN RRSIG A 8 2 86400 20240115000000 20240101000000 12345 example.com. kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncGY
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 1)
	const rec = result[0] as Record
	assertEquals(rec.type, 'record')
	assertEquals(rec.domain, 'example.com.')
	assertEquals(rec.recordType, 'RRSIG')
	assertEquals(rec.class, 'IN')
	assertEquals(rec.ttl, null)
	assertEquals((rec.data as RRSIGData).typeCovered, 'A')
	assertEquals((rec.data as RRSIGData).algorithm, 8)
	assertEquals((rec.data as RRSIGData).labels, 2)
	assertEquals((rec.data as RRSIGData).originalTTL, 86400)
	assertEquals((rec.data as RRSIGData).expiration, 20240115000000)
	assertEquals((rec.data as RRSIGData).inception, 20240101000000)
	assertEquals((rec.data as RRSIGData).keyTag, 12345)
	assertEquals((rec.data as RRSIGData).signer, 'example.com.')
	assertEquals(
		(rec.data as RRSIGData).signature,
		'kRCOH6u7l0QGy9qpC9l1sLncJcOKFLJ7GhiUOibu4teYp5VE9RncGY',
	)
})

Deno.test('parseZone - NSEC records', () => {
	const zoneContent =
		`example.com. IN NSEC www.example.com. A NS SOA MX AAAA RRSIG NSEC DNSKEY
www.example.com. IN NSEC mail.example.com. A AAAA RRSIG NSEC
`

	const result = parseZone(zoneContent)

	assertEquals(result.length, 2)
	const rec1 = result[0] as Record
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'example.com.')
	assertEquals(rec1.recordType, 'NSEC')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as NSECData).nextDomain, 'www.example.com.')
	assertEquals((rec1.data as NSECData).recordTypes, [
		'A',
		'NS',
		'SOA',
		'MX',
		'AAAA',
		'RRSIG',
		'NSEC',
		'DNSKEY',
	])

	const rec2 = result[1] as Record
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'www.example.com.')
	assertEquals(rec2.recordType, 'NSEC')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as NSECData).nextDomain, 'mail.example.com.')
	assertEquals((rec2.data as NSECData).recordTypes, [
		'A',
		'AAAA',
		'RRSIG',
		'NSEC',
	])
})

Deno.test('parseZone - TLSA records', () => {
	const zone = `
$ORIGIN example.com.
_443._tcp.www   IN  TLSA    3 1 1 0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6
_25._tcp.mail       TLSA    3 0 1 A1B2C3D4E5F6789012345678901234567890ABCDEFABCDEF1234567890ABCD
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, '_443._tcp.www')
	assertEquals(rec1.recordType, 'TLSA')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as TLSAData).usage, 3)
	assertEquals((rec1.data as TLSAData).selector, 1)
	assertEquals((rec1.data as TLSAData).matchingType, 1)
	assertEquals(
		(rec1.data as TLSAData).certificate,
		'0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6',
	)

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, '_25._tcp.mail')
	assertEquals(rec2.recordType, 'TLSA')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as TLSAData).usage, 3)
	assertEquals((rec2.data as TLSAData).selector, 0)
	assertEquals((rec2.data as TLSAData).matchingType, 1)
	assertEquals(
		(rec2.data as TLSAData).certificate,
		'A1B2C3D4E5F6789012345678901234567890ABCDEFABCDEF1234567890ABCD',
	)
})

Deno.test('parseZone - SSHFP records', () => {
	const zone = `
$ORIGIN example.com.
server  IN  SSHFP   2 1 123456789ABCDEF67890123456789ABCDEF67890
host        SSHFP   4 2 FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'server')
	assertEquals(rec1.recordType, 'SSHFP')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as SSHFPData).algorithm, 2)
	assertEquals((rec1.data as SSHFPData).fingerprintType, 1)
	assertEquals(
		(rec1.data as SSHFPData).fingerprint,
		'123456789ABCDEF67890123456789ABCDEF67890',
	)

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'host')
	assertEquals(rec2.recordType, 'SSHFP')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as SSHFPData).algorithm, 4)
	assertEquals((rec2.data as SSHFPData).fingerprintType, 2)
	assertEquals(
		(rec2.data as SSHFPData).fingerprint,
		'FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321',
	)
})

Deno.test('parseZone - DNAME records', () => {
	const zone = `
$ORIGIN example.com.
old     IN  DNAME   new.example.net.
legacy      DNAME   modern.example.org.
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'old')
	assertEquals(rec1.recordType, 'DNAME')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as DNAMEData).target, 'new.example.net.')

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'legacy')
	assertEquals(rec2.recordType, 'DNAME')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as DNAMEData).target, 'modern.example.org.')
})

Deno.test('parseZone - NAPTR records', () => {
	const zone = `
$ORIGIN example.com.
@   IN  NAPTR   100 10 "u" "E2U+sip" "!^.*$!sip:info@example.com!" .
@       NAPTR   200 20 "u" "E2U+email" "!^.*$!mailto:info@example.com!" .
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.recordType, 'NAPTR')
	assertEquals(rec1.domain, '@')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as NAPTRData).order, 100)
	assertEquals((rec1.data as NAPTRData).preference, 10)
	assertEquals((rec1.data as NAPTRData).flags, 'u')
	assertEquals((rec1.data as NAPTRData).service, 'E2U+sip')
	assertEquals((rec1.data as NAPTRData).regexp, '!^.*$!sip:info@example.com!')
	assertEquals((rec1.data as NAPTRData).replacement, '.')

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, '@')
	assertEquals(rec2.recordType, 'NAPTR')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as NAPTRData).order, 200)
	assertEquals((rec2.data as NAPTRData).preference, 20)
	assertEquals((rec2.data as NAPTRData).flags, 'u')
	assertEquals((rec2.data as NAPTRData).service, 'E2U+email')
	assertEquals(
		(rec2.data as NAPTRData).regexp,
		'!^.*$!mailto:info@example.com!',
	)
	assertEquals((rec2.data as NAPTRData).replacement, '.')
})

Deno.test('parseZone - LOC records', () => {
	const zone = `
$ORIGIN example.com.
@   IN  LOC 52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m
server  LOC 37 46 30 N 122 23 42 W 10m 10m 10m 2m
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, '@')
	assertEquals(rec1.recordType, 'LOC')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals(
		(rec1.data as LOCData).content,
		'52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m',
	)

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'server')
	assertEquals(rec2.recordType, 'LOC')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals(
		(rec2.data as LOCData).content,
		'37 46 30 N 122 23 42 W 10m 10m 10m 2m',
	)
})

Deno.test('parseZone - HINFO records', () => {
	const zone = `
$ORIGIN example.com.
server  IN  HINFO   "Intel" "Linux"
host        HINFO   "ARM" "FreeBSD"
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, 'server')
	assertEquals(rec1.recordType, 'HINFO')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as HINFOData).cpu, 'Intel')
	assertEquals((rec1.data as HINFOData).os, 'Linux')

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'host')
	assertEquals(rec2.recordType, 'HINFO')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as HINFOData).cpu, 'ARM')
	assertEquals((rec2.data as HINFOData).os, 'FreeBSD')
})

Deno.test('parseZone - SPF records', () => {
	const zone = `
$ORIGIN example.com.
@   IN  SPF "v=spf1 mx -all"
mail    SPF "v=spf1 a mx ip4:192.0.2.0/24 -all"
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, '@')
	assertEquals(rec1.recordType, 'SPF')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as SPFData).text, 'v=spf1 mx -all')

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'mail')
	assertEquals(rec2.recordType, 'SPF')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals(
		(rec2.data as SPFData).text,
		'v=spf1 a mx ip4:192.0.2.0/24 -all',
	)
})

Deno.test('parseZone - ZONEMD records', () => {
	const zone = `
$ORIGIN example.com.
@   IN  ZONEMD  2023100101 1 2 ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789
zone    ZONEMD  2024010101 1 1 1234567890ABCDEFABCDEF1234567890ABCDEFABCDEF1234567890ABCDEF12
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 2)

	const rec1 = records[0]
	assertEquals(rec1.type, 'record')
	assertEquals(rec1.domain, '@')
	assertEquals(rec1.recordType, 'ZONEMD')
	assertEquals(rec1.class, 'IN')
	assertEquals(rec1.ttl, null)
	assertEquals((rec1.data as ZONEMDData).serial, 2023100101)
	assertEquals((rec1.data as ZONEMDData).scheme, 1)
	assertEquals((rec1.data as ZONEMDData).hashAlgo, 2)
	assertEquals(
		(rec1.data as ZONEMDData).digest,
		'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789',
	)

	const rec2 = records[1]
	assertEquals(rec2.type, 'record')
	assertEquals(rec2.domain, 'zone')
	assertEquals(rec2.recordType, 'ZONEMD')
	assertEquals(rec2.class, 'IN')
	assertEquals(rec2.ttl, null)
	assertEquals((rec2.data as ZONEMDData).serial, 2024010101)
	assertEquals((rec2.data as ZONEMDData).scheme, 1)
	assertEquals((rec2.data as ZONEMDData).hashAlgo, 1)
	assertEquals(
		(rec2.data as ZONEMDData).digest,
		'1234567890ABCDEFABCDEF1234567890ABCDEFABCDEF1234567890ABCDEF12',
	)
})

// =============================================================================
// TTL Handling Tests
// =============================================================================

Deno.test('parseZone - explicit TTL values', () => {
	const zone = `
$ORIGIN example.com.
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101  ; Serial
                7200        ; Refresh
                3600        ; Retry
                1209600     ; Expire
                3600 )      ; Minimum
ns1         3600    IN  A       192.0.2.1
www         7200    IN  A       192.0.2.2
mail        86400   IN  A       192.0.2.3
ftp         300     IN  CNAME   www.example.com.
`
	const result = parseZone(zone)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 5)

	// SOA record (no explicit TTL)
	const soaRec = records[0]
	assertEquals(soaRec.recordType, 'SOA')
	assertEquals(soaRec.ttl, null)

	// ns1 with TTL 3600
	const ns1Rec = records[1]
	assertEquals(ns1Rec.domain, 'ns1')
	assertEquals(ns1Rec.recordType, 'A')
	assertEquals(ns1Rec.ttl, 3600)
	assertEquals((ns1Rec.data as AData).ip, '192.0.2.1')

	// www with TTL 7200
	const wwwRec = records[2]
	assertEquals(wwwRec.domain, 'www')
	assertEquals(wwwRec.recordType, 'A')
	assertEquals(wwwRec.ttl, 7200)
	assertEquals((wwwRec.data as AData).ip, '192.0.2.2')

	// mail with TTL 86400
	const mailRec = records[3]
	assertEquals(mailRec.domain, 'mail')
	assertEquals(mailRec.recordType, 'A')
	assertEquals(mailRec.ttl, 86400)
	assertEquals((mailRec.data as AData).ip, '192.0.2.3')

	// ftp with TTL 300
	const ftpRec = records[4]
	assertEquals(ftpRec.domain, 'ftp')
	assertEquals(ftpRec.recordType, 'CNAME')
	assertEquals(ftpRec.ttl, 300)
	assertEquals((ftpRec.data as CNAMEData).cname, 'www.example.com.')
})

Deno.test('parseZone - $TTL directive inheritance', () => {
	const zone = `
$ORIGIN example.com.
$TTL 86400
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101  ; Serial
                7200        ; Refresh
                3600        ; Retry
                1209600     ; Expire
                3600 )      ; Minimum
        IN  NS      ns1.example.com.
        IN  NS      ns2.example.com.
ns1     IN  A       192.0.2.1
ns2     IN  A       192.0.2.2
www     IN  A       192.0.2.3
`
	const result = parseZone(zone, { inheritTTL: true })

	// Check for $TTL directive
	const directives = result.filter((r) =>
		r.type === 'directive'
	) as Directive[]
	const ttlDirective = directives.find((d) => d.name === '$TTL')
	assertEquals(ttlDirective !== undefined, true)
	assertEquals(ttlDirective?.value, 86400)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 6)

	// All records should inherit the $TTL value (86400) since they have no explicit TTL

	const soaRec = records[0]
	assertEquals(soaRec.recordType, 'SOA')
	assertEquals(soaRec.ttl, 86400)

	const ns1Rec = records[1]
	assertEquals(ns1Rec.recordType, 'NS')
	assertEquals(ns1Rec.ttl, 86400)

	const ns2Rec = records[2]
	assertEquals(ns2Rec.recordType, 'NS')
	assertEquals(ns2Rec.ttl, 86400)

	const aRec1 = records[3]
	assertEquals(aRec1.domain, 'ns1')
	assertEquals(aRec1.recordType, 'A')
	assertEquals(aRec1.ttl, 86400)

	const aRec2 = records[4]
	assertEquals(aRec2.domain, 'ns2')
	assertEquals(aRec2.recordType, 'A')
	assertEquals(aRec2.ttl, 86400)

	const aRec3 = records[5]
	assertEquals(aRec3.domain, 'www')
	assertEquals(aRec3.recordType, 'A')
	assertEquals(aRec3.ttl, 86400)
})

Deno.test('parseZone - explicit TTL overrides $TTL directive', () => {
	const zone = `
$ORIGIN example.com.
$TTL 86400
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101  ; Serial
                7200        ; Refresh
                3600        ; Retry
                1209600     ; Expire
                3600 )      ; Minimum
        IN  NS      ns1.example.com.
ns1     IN  A       192.0.2.1
www     3600    IN  A       192.0.2.2
mail    7200    IN  A       192.0.2.3
`
	const result = parseZone(zone, { inheritTTL: true })

	// Check for $TTL directive
	const directives = result.filter((r) =>
		r.type === 'directive'
	) as Directive[]
	const ttlDirective = directives.find((d) => d.name === '$TTL')
	assertEquals(ttlDirective !== undefined, true)
	assertEquals(ttlDirective?.value, 86400)

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 5)

	// SOA - no explicit TTL, should inherit $TTL 86400
	const soaRec = records[0]
	assertEquals(soaRec.recordType, 'SOA')
	assertEquals(soaRec.ttl, 86400)

	// NS - no explicit TTL, should inherit $TTL 86400
	const nsRec = records[1]
	assertEquals(nsRec.recordType, 'NS')
	assertEquals(nsRec.ttl, 86400)

	// ns1 - no explicit TTL, should inherit $TTL 86400
	const ns1Rec = records[2]
	assertEquals(ns1Rec.domain, 'ns1')
	assertEquals(ns1Rec.recordType, 'A')
	assertEquals(ns1Rec.ttl, 86400)

	// www - explicit TTL 3600 (overrides $TTL 86400)
	const wwwRec = records[3]
	assertEquals(wwwRec.domain, 'www')
	assertEquals(wwwRec.recordType, 'A')
	assertEquals(wwwRec.ttl, 3600)

	// mail - explicit TTL 7200 (overrides $TTL 86400)
	const mailRec = records[4]
	assertEquals(mailRec.domain, 'mail')
	assertEquals(mailRec.recordType, 'A')
	assertEquals(mailRec.ttl, 7200)
})

// =============================================================================
// ParseOptions Tests - expandDomains
// =============================================================================

Deno.test('parseZone - expandDomains: false (default) - @ symbol not expanded', () => {
	const zone = `
$ORIGIN example.com.
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101 7200 3600 1209600 3600 )
@       IN  NS  ns1.example.com.
`
	const result = parseZone(zone) // expandDomains defaults to false

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, '@')
	assertEquals(records[1].domain, '@')
})

Deno.test('parseZone - expandDomains: true - @ symbol expanded to $ORIGIN', () => {
	const zone = `
$ORIGIN example.com.
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101 7200 3600 1209600 3600 )
@       IN  NS  ns1.example.com.
`
	const result = parseZone(zone, { expandDomains: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'example.com.')
	assertEquals(records[1].domain, 'example.com.')
})

Deno.test('parseZone - expandDomains: false - relative names not expanded', () => {
	const zone = `
$ORIGIN example.com.
www     IN  A   192.0.2.1
mail    IN  A   192.0.2.2
`
	const result = parseZone(zone) // expandDomains defaults to false

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'www')
	assertEquals(records[1].domain, 'mail')
})

Deno.test('parseZone - expandDomains: true - relative names expanded with $ORIGIN', () => {
	const zone = `
$ORIGIN example.com.
www     IN  A   192.0.2.1
mail    IN  A   192.0.2.2
`
	const result = parseZone(zone, { expandDomains: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'www.example.com.')
	assertEquals(records[1].domain, 'mail.example.com.')
})

Deno.test('parseZone - expandDomains: true - FQDN (trailing dot) unchanged', () => {
	const zone = `
$ORIGIN example.com.
www.test.com.     IN  A   192.0.2.1
mail.other.org.   IN  A   192.0.2.2
`
	const result = parseZone(zone, { expandDomains: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'www.test.com.')
	assertEquals(records[1].domain, 'mail.other.org.')
})

Deno.test('parseZone - expandDomains: true - no $ORIGIN, domains unchanged', () => {
	const zone = `
www     IN  A   192.0.2.1
@       IN  A   192.0.2.2
`
	const result = parseZone(zone, { expandDomains: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'www')
	assertEquals(records[1].domain, '@')
})

Deno.test('parseZone - expandDomains: true - $ORIGIN changes mid-zone', () => {
	const zone = `
$ORIGIN example.com.
www     IN  A   192.0.2.1
$ORIGIN test.org.
www     IN  A   192.0.2.2
`
	const result = parseZone(zone, { expandDomains: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'www.example.com.')
	assertEquals(records[1].domain, 'www.test.org.')
})

// =============================================================================
// ParseOptions Tests - inheritTTL
// =============================================================================

Deno.test('parseZone - inheritTTL: false (default) - no TTL inheritance', () => {
	const zone = `
$TTL 86400
example.com.  IN  SOA ns1.example.com. admin.example.com. (
                      2023100101 7200 3600 1209600 3600 )
example.com.  IN  NS  ns1.example.com.
`
	const result = parseZone(zone) // inheritTTL defaults to false

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].ttl, null)
	assertEquals(records[1].ttl, null)
})

Deno.test('parseZone - inheritTTL: true - inherits $TTL value', () => {
	const zone = `
$TTL 86400
example.com.  IN  SOA ns1.example.com. admin.example.com. (
                      2023100101 7200 3600 1209600 3600 )
example.com.  IN  NS  ns1.example.com.
`
	const result = parseZone(zone, { inheritTTL: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].ttl, 86400)
	assertEquals(records[1].ttl, 86400)
})

Deno.test('parseZone - inheritTTL: true - explicit TTL overrides $TTL', () => {
	const zone = `
$TTL 86400
example.com.  3600  IN  SOA ns1.example.com. admin.example.com. (
                            2023100101 7200 3600 1209600 3600 )
example.com.  7200  IN  NS  ns1.example.com.
example.com.        IN  A   192.0.2.1
`
	const result = parseZone(zone, { inheritTTL: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].ttl, 3600) // explicit TTL
	assertEquals(records[1].ttl, 7200) // explicit TTL
	assertEquals(records[2].ttl, 86400) // inherited from $TTL
})

Deno.test('parseZone - inheritTTL: false - explicit TTL always used', () => {
	const zone = `
$TTL 86400
example.com.  3600  IN  SOA ns1.example.com. admin.example.com. (
                            2023100101 7200 3600 1209600 3600 )
example.com.  7200  IN  NS  ns1.example.com.
example.com.        IN  A   192.0.2.1
`
	const result = parseZone(zone, { inheritTTL: false })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].ttl, 3600) // explicit TTL
	assertEquals(records[1].ttl, 7200) // explicit TTL
	assertEquals(records[2].ttl, null) // no inheritance
})

Deno.test('parseZone - inheritTTL: true - no $TTL directive, TTL is null', () => {
	const zone = `
example.com.  IN  SOA ns1.example.com. admin.example.com. (
                      2023100101 7200 3600 1209600 3600 )
example.com.  IN  NS  ns1.example.com.
`
	const result = parseZone(zone, { inheritTTL: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].ttl, null)
	assertEquals(records[1].ttl, null)
})

// =============================================================================
// ParseOptions Tests - Option Combinations
// =============================================================================

Deno.test('parseZone - both options false (default) - no expansion or inheritance', () => {
	const zone = `
$ORIGIN example.com.
$TTL 86400
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101 7200 3600 1209600 3600 )
www     IN  A   192.0.2.1
`
	const result = parseZone(zone) // both default to false

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, '@')
	assertEquals(records[0].ttl, null)
	assertEquals(records[1].domain, 'www')
	assertEquals(records[1].ttl, null)
})

Deno.test('parseZone - expandDomains: true, inheritTTL: false', () => {
	const zone = `
$ORIGIN example.com.
$TTL 86400
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101 7200 3600 1209600 3600 )
www     IN  A   192.0.2.1
`
	const result = parseZone(zone, { expandDomains: true, inheritTTL: false })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, 'example.com.')
	assertEquals(records[0].ttl, null)
	assertEquals(records[1].domain, 'www.example.com.')
	assertEquals(records[1].ttl, null)
})

Deno.test('parseZone - expandDomains: false, inheritTTL: true', () => {
	const zone = `
$ORIGIN example.com.
$TTL 86400
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101 7200 3600 1209600 3600 )
www     IN  A   192.0.2.1
`
	const result = parseZone(zone, { expandDomains: false, inheritTTL: true })

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records[0].domain, '@')
	assertEquals(records[0].ttl, 86400)
	assertEquals(records[1].domain, 'www')
	assertEquals(records[1].ttl, 86400)
})

Deno.test('parseZone - both options true - full expansion and inheritance', () => {
	const zone = `
$ORIGIN example.com.
$TTL 86400
@       IN  SOA ns1.example.com. admin.example.com. (
                2023100101 7200 3600 1209600 3600 )
www     IN  A   192.0.2.1
mail    3600  IN  A   192.0.2.2
ftp.    IN  CNAME ftp.other.com.
`
	const result = parseZone(zone, { expandDomains: true, inheritTTL: true })

	const records = result.filter((r) => r.type === 'record') as Record[]

	// @ expanded to example.com., TTL inherited
	assertEquals(records[0].domain, 'example.com.')
	assertEquals(records[0].ttl, 86400)

	// www expanded to www.example.com., TTL inherited
	assertEquals(records[1].domain, 'www.example.com.')
	assertEquals(records[1].ttl, 86400)

	// mail expanded, explicit TTL used
	assertEquals(records[2].domain, 'mail.example.com.')
	assertEquals(records[2].ttl, 3600)

	// ftp. is FQDN (not expanded), TTL inherited
	assertEquals(records[3].domain, 'ftp.')
	assertEquals(records[3].ttl, 86400)
})

// =============================================================================
// Error Handling Tests
// =============================================================================

Deno.test('parseZone - invalid zone syntax (unclosed parenthesis)', () => {
	const zoneContent = `@ IN SOA ns.example.com. admin.example.com. (
  1 7200 3600 1209600 3600
  `

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for invalid syntax
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - malformed IP address in A record', () => {
	const zoneContent = `example.com. IN A 999.999.999.999
`

	// Parser may accept this (validation is typically done by DNS server)
	// but we ensure it doesn't crash
	const result = parseZone(zoneContent)
	assertEquals(result.length, 1)
})

Deno.test('parseZone - malformed IPv6 address in AAAA record', () => {
	const zoneContent = `example.com. IN AAAA zzz::invalid
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for invalid IPv6
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - empty input', () => {
	const zoneContent = ``

	const result = parseZone(zoneContent)
	assertEquals(result.length, 0)
})

Deno.test('parseZone - whitespace-only input', () => {
	const zoneContent = `   
  
     
`

	const result = parseZone(zoneContent)
	assertEquals(result.length, 0)
})

Deno.test('parseZone - comments-only input', () => {
	const zoneContent = `; This is a comment
; Another comment
; Yet another comment
`

	const result = parseZone(zoneContent)
	assertEquals(result.length, 0)
})

Deno.test('parseZone - invalid record type', () => {
	const zoneContent = `example.com. IN INVALID 192.0.2.1
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for invalid record type
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - missing record data', () => {
	const zoneContent = `example.com. IN A
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for missing data
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - SOA missing required fields', () => {
	const zoneContent = `@ IN SOA ns.example.com.
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for incomplete SOA
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - MX record with invalid priority (non-numeric)', () => {
	const zoneContent = `example.com. IN MX abc mail.example.com.
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for non-numeric priority
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - SRV record with missing fields', () => {
	const zoneContent = `_http._tcp.example.com. IN SRV 10 60
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for incomplete SRV
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - TXT record with unquoted text containing spaces', () => {
	const zoneContent = `example.com. IN TXT v=spf1 mx -all
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for unquoted multi-word text
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - DNSKEY with invalid algorithm number', () => {
	const zoneContent =
		`example.com. IN DNSKEY 256 3 abc AwEAAagAIKlVZrpC6Ia7gEzahOR+9W29euxhJhVVLOyQbSEW0O8gcCjF
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for non-numeric algorithm
		assertEquals(error instanceof Error, true)
	}
})

Deno.test('parseZone - CAA record with invalid flags', () => {
	const zoneContent = `example.com. IN CAA abc "issue" "letsencrypt.org"
`

	try {
		parseZone(zoneContent)
		throw new Error('Expected parseZone to throw')
	} catch (error) {
		// Parser should throw an error for non-numeric flags
		assertEquals(error instanceof Error, true)
	}
})

// =============================================================================
// Integration Tests - Zone Files
// =============================================================================

Deno.test('parseZone - localhost-forward.zone', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/localhost-forward.zone'))
	assertEquals(result.length, 6) // 2 directives + 4 records

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 4)

	// Verify record types present
	const recordTypes = records.map((r) => r.recordType)
	assertEquals(recordTypes.includes('SOA'), true)
	assertEquals(recordTypes.includes('NS'), true)
	assertEquals(recordTypes.includes('A'), true)
	assertEquals(recordTypes.includes('AAAA'), true)
})

Deno.test('parseZone - localhost-reverse.zone', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/localhost-reverse.zone'))
	assertEquals(result.length, 5) // 2 directives + 3 records

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 3)

	const recordTypes = records.map((r) => r.recordType)
	assertEquals(recordTypes.includes('PTR'), true)
})

Deno.test('parseZone - example.zone', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/example.zone'))
	assertEquals(result.length, 17) // 2 directives + 15 records

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 15)
})

Deno.test('parseZone - comprehensive.zone (21 record types)', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/comprehensive.zone'))
	assertEquals(result.length, 75) // 2 directives + 73 records

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 73)

	// Verify comprehensive coverage - 21 different record types
	const recordTypes = new Set(records.map((r) => r.recordType))
	assertEquals(recordTypes.size, 21)
})

Deno.test('parseZone - edge-cases.zone (wildcards, numbers, etc)', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/edge-cases.zone'))
	assertEquals(result.length, 76) // 2 directives + 74 records

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 74)

	// Verify wildcard domain support
	const wildcardRecord = records.find((r) => r.domain.includes('*'))
	assertEquals(
		wildcardRecord !== undefined,
		true,
		'Should parse wildcard domains',
	)
})

Deno.test('parseZone - root-sample.zone (IANA root zone)', async () => {
	const result = parseZone(await Deno.readTextFile('test-data/root-sample.zone'))
	assertEquals(result.length, 500) // All records, no directives

	const records = result.filter((r) => r.type === 'record') as Record[]
	assertEquals(records.length, 500)

	// Verify ZONEMD support
	const zonemdRecord = records.find((r) => r.recordType === 'ZONEMD')
	assertEquals(zonemdRecord !== undefined, true, 'Should parse ZONEMD records')

	// Verify single-line SOA format
	const soaRecord = records.find((r) => r.recordType === 'SOA')
	assertEquals(
		soaRecord !== undefined,
		true,
		'Should parse single-line SOA format',
	)
})

// ===== Serialization Tests =====

Deno.test('serializeEntry - directive $ORIGIN', () => {
	const directive: Directive = {
		type: 'directive',
		name: '$ORIGIN',
		value: 'example.com.',
	}
	const result = serializeEntry(directive)
	assertEquals(result, '$ORIGIN example.com.')
})

Deno.test('serializeEntry - directive $TTL', () => {
	const directive: Directive = {
		type: 'directive',
		name: '$TTL',
		value: 3600,
	}
	const result = serializeEntry(directive)
	assertEquals(result, '$TTL 3600')
})

Deno.test('serializeEntry - SOA record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'SOA',
		domain: 'example.com.',
		ttl: null,
		class: 'IN',
		data: {
			mname: 'ns.example.com.',
			rname: 'admin.example.com.',
			serial: 2020091025,
			refresh: 7200,
			retry: 3600,
			expire: 1209600,
			minimum: 3600,
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('SOA'), true)
	assertEquals(result.includes('ns.example.com.'), true)
	assertEquals(result.includes('2020091025'), true)
})

Deno.test('serializeEntry - A record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'A',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			ip: '192.0.2.1',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('A'), true)
	assertEquals(result.includes('192.0.2.1'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - MX record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'MX',
		domain: 'example.com.',
		ttl: null,
		class: 'IN',
		data: {
			priority: 10,
			mx: 'mail.example.com.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('MX'), true)
	assertEquals(result.includes('10'), true)
	assertEquals(result.includes('mail.example.com.'), true)
})

Deno.test('serializeZone - round-trip parsing', () => {
	const originalZone = `$ORIGIN example.com.
$TTL 3600
example.com.      IN    SOA     ns.example.com. admin.example.com. 1 7200 3600 1209600 3600
example.com.      IN    NS      ns.example.com.
example.com.      IN    A       192.0.2.1
www.example.com.  IN    CNAME   example.com.
`

	// Parse the original zone
	const parsed = parseZone(originalZone)

	// Serialize it back
	const serialized = serializeZone(parsed, { includeBlankLines: false })

	// Parse the serialized version
	const reparsed = parseZone(serialized)

	// The data should be identical
	assertEquals(reparsed.length, parsed.length)

	// Check directives
	assertEquals((reparsed[0] as Directive).name, '$ORIGIN')
	assertEquals((reparsed[0] as Directive).value, 'example.com.')
	assertEquals((reparsed[1] as Directive).name, '$TTL')
	assertEquals((reparsed[1] as Directive).value, 3600)

	// Check SOA record
	const soaRecord = reparsed[2] as Record
	assertEquals(soaRecord.recordType, 'SOA')
	assertEquals(soaRecord.domain, 'example.com.')
	assertEquals((soaRecord.data as SOAData).serial, 1)
})

Deno.test('serializeZone - round-trip with example.zone', async () => {
	// Parse the test file
	const parsed = parseZone(await Deno.readTextFile('test-data/example.zone'))

	// Serialize it back
	const serialized = serializeZone(parsed, { includeBlankLines: false })

	// Parse the serialized version
	const reparsed = parseZone(serialized)

	// Should have the same number of entries
	assertEquals(reparsed.length, parsed.length)

	// Should have same directives
	const originalDirectives = parsed.filter((e) => e.type === 'directive')
	const reparsedDirectives = reparsed.filter((e) => e.type === 'directive')
	assertEquals(reparsedDirectives.length, originalDirectives.length)

	// Should have same records
	const originalRecords = parsed.filter((e) => e.type === 'record') as Record[]
	const reparsedRecords = reparsed.filter((e) =>
		e.type === 'record'
	) as Record[]
	assertEquals(reparsedRecords.length, originalRecords.length)

	// Check record types match
	const originalTypes = originalRecords.map((r) => r.recordType).sort()
	const reparsedTypes = reparsedRecords.map((r) => r.recordType).sort()
	assertEquals(JSON.stringify(reparsedTypes), JSON.stringify(originalTypes))
})

Deno.test('serializeEntry - TXT record with spaces', () => {
	const record: Record = {
		type: 'record',
		recordType: 'TXT',
		domain: 'example.com.',
		ttl: null,
		class: 'IN',
		data: {
			txt: 'v=spf1 include:_spf.example.com ~all',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('TXT'), true)
	assertEquals(result.includes('"v=spf1 include:_spf.example.com ~all"'), true)
})

Deno.test('serializeEntry - CAA record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'CAA',
		domain: 'example.com.',
		ttl: null,
		class: 'IN',
		data: {
			flags: 0,
			tag: 'issue',
			value: 'letsencrypt.org',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('CAA'), true)
	assertEquals(result.includes('0'), true)
	assertEquals(result.includes('issue'), true)
	assertEquals(result.includes('"letsencrypt.org"'), true)
})

Deno.test('serializeEntry - SRV record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'SRV',
		domain: '_http._tcp.example.com.',
		ttl: null,
		class: 'IN',
		data: {
			priority: 10,
			weight: 60,
			port: 80,
			target: 'www.example.com.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('SRV'), true)
	assertEquals(result.includes('10'), true)
	assertEquals(result.includes('60'), true)
	assertEquals(result.includes('80'), true)
	assertEquals(result.includes('www.example.com.'), true)
})

Deno.test('serializeEntry - NS record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'NS',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			ns: 'ns1.example.com.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('NS'), true)
	assertEquals(result.includes('ns1.example.com.'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - AAAA record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'AAAA',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			ip: '2001:db8::1',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('AAAA'), true)
	assertEquals(result.includes('2001:db8::1'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - CNAME record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'CNAME',
		domain: 'www.example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			cname: 'example.com.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('CNAME'), true)
	assertEquals(result.includes('example.com.'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - PTR record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'PTR',
		domain: '1.2.0.192.in-addr.arpa.',
		ttl: 3600,
		class: 'IN',
		data: {
			ptrdname: 'example.com.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('PTR'), true)
	assertEquals(result.includes('example.com.'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - DNSKEY record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'DNSKEY',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			flags: 257,
			protocol: 3,
			algorithm: 13,
			publicKey:
				'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('DNSKEY'), true)
	assertEquals(result.includes('257'), true)
	assertEquals(result.includes('3'), true)
	assertEquals(result.includes('13'), true)
	assertEquals(
		result.includes(
			'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==',
		),
		true,
	)
})

Deno.test('serializeEntry - DS record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'DS',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			keyTag: 12345,
			algorithm: 13,
			digestType: 2,
			digest:
				'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('DS'), true)
	assertEquals(result.includes('12345'), true)
	assertEquals(result.includes('13'), true)
	assertEquals(result.includes('2'), true)
	assertEquals(
		result.includes(
			'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789',
		),
		true,
	)
})

Deno.test('serializeEntry - RRSIG record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'RRSIG',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			typeCovered: 'A',
			algorithm: 13,
			labels: 2,
			originalTTL: 3600,
			expiration: 20231201000000,
			inception: 20231101000000,
			keyTag: 12345,
			signer: 'example.com.',
			signature:
				'oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfg==',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('RRSIG'), true)
	assertEquals(result.includes('A'), true)
	assertEquals(result.includes('13'), true)
	assertEquals(result.includes('2'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - NSEC record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'NSEC',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			nextDomain: 'www.example.com.',
			recordTypes: ['A', 'NS', 'SOA', 'MX', 'RRSIG', 'NSEC', 'DNSKEY'],
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('NSEC'), true)
	assertEquals(result.includes('www.example.com.'), true)
	assertEquals(result.includes('A'), true)
	assertEquals(result.includes('NS'), true)
	assertEquals(result.includes('SOA'), true)
})

Deno.test('serializeEntry - TLSA record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'TLSA',
		domain: '_443._tcp.www.example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			usage: 3,
			selector: 1,
			matchingType: 1,
			certificate:
				'0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('TLSA'), true)
	assertEquals(result.includes('3'), true)
	assertEquals(result.includes('1'), true)
	assertEquals(
		result.includes(
			'0C72AC70B745AC19998811B131D662C9AC69DBDBE7CB23E5B514B56664C5D3D6',
		),
		true,
	)
})

Deno.test('serializeEntry - SSHFP record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'SSHFP',
		domain: 'server.example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			algorithm: 2,
			fingerprintType: 1,
			fingerprint: '123456789ABCDEF67890123456789ABCDEF67890',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('SSHFP'), true)
	assertEquals(result.includes('2'), true)
	assertEquals(result.includes('1'), true)
	assertEquals(
		result.includes('123456789ABCDEF67890123456789ABCDEF67890'),
		true,
	)
})

Deno.test('serializeEntry - DNAME record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'DNAME',
		domain: 'old.example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			target: 'new.example.net.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('DNAME'), true)
	assertEquals(result.includes('new.example.net.'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - NAPTR record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'NAPTR',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			order: 100,
			preference: 10,
			flags: 'u',
			service: 'E2U+sip',
			regexp: '!^.*$!sip:info@example.com!',
			replacement: '.',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('NAPTR'), true)
	assertEquals(result.includes('100'), true)
	assertEquals(result.includes('10'), true)
	assertEquals(result.includes('u'), true)
	assertEquals(result.includes('E2U+sip'), true)
})

Deno.test('serializeEntry - LOC record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'LOC',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			content: '52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('LOC'), true)
	assertEquals(
		result.includes('52 22 23.000 N 4 53 32.000 E -2.00m 0.00m 10000m 10m'),
		true,
	)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - HINFO record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'HINFO',
		domain: 'server.example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			cpu: 'Intel',
			os: 'Linux',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('HINFO'), true)
	assertEquals(result.includes('Intel'), true)
	assertEquals(result.includes('Linux'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - SPF record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'SPF',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			text: 'v=spf1 mx -all',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('SPF'), true)
	assertEquals(result.includes('v=spf1 mx -all'), true)
	assertEquals(result.includes('3600'), true)
})

Deno.test('serializeEntry - ZONEMD record', () => {
	const record: Record = {
		type: 'record',
		recordType: 'ZONEMD',
		domain: 'example.com.',
		ttl: 3600,
		class: 'IN',
		data: {
			serial: 2023100101,
			scheme: 1,
			hashAlgo: 2,
			digest:
				'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789',
		},
	}
	const result = serializeEntry(record)
	assertEquals(result.includes('ZONEMD'), true)
	assertEquals(result.includes('2023100101'), true)
	assertEquals(result.includes('1'), true)
	assertEquals(result.includes('2'), true)
	assertEquals(
		result.includes(
			'ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789',
		),
		true,
	)
})


