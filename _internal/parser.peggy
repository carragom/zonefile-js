{{
  function expandDomain(domain, origin, shouldExpand) {
    if (!shouldExpand || !origin) return domain;
    if (domain === '@') return origin;
    if (domain.endsWith('.')) return domain;
    if (domain === '') return domain;
    return domain + '.' + origin;
  }
  
  function resolveTTL(explicitTTL, currentTTL, shouldInherit) {
    if (explicitTTL !== null) return explicitTTL;
    return shouldInherit ? currentTTL : null;
  }
}}

{
  let currentTTL = null;
  let currentOrigin = null;
  const expandDomains = options?.expandDomains || false;
  const inheritTTL = options?.inheritTTL || false;
}

// PEG grammar for BIND zone files
Zone = _ records:((Directive / Record / Comment / BlankLine) _)* { return records.map(([r, _]) => r).filter(r => r); }

Directive = "$ORIGIN" [ \t]* domain:Domain [ \t]* Comment? { currentOrigin = domain; return { type: 'directive', name: '$ORIGIN', value: domain }; } / "$TTL" [ \t]* ttl:Number [ \t]* Comment? { currentTTL = ttl; return { type: 'directive', name: '$TTL', value: ttl }; }

Record = domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "SOA" [ \t]+ data:SOAData [ \t]* Comment? { return { type: 'record', recordType: 'SOA', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "NS" [ \t]+ data:NSData [ \t]* Comment? { return { type: 'record', recordType: 'NS', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "MX" [ \t]+ data:MXData [ \t]* Comment? { return { type: 'record', recordType: 'MX', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "PTR" [ \t]+ data:PTRData [ \t]* Comment? { return { type: 'record', recordType: 'PTR', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "TXT" [ \t]+ data:TXTData [ \t]* Comment? { return { type: 'record', recordType: 'TXT', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "SRV" [ \t]+ data:SRVData [ \t]* Comment? { return { type: 'record', recordType: 'SRV', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "CAA" [ \t]+ data:CAAData [ \t]* Comment? { return { type: 'record', recordType: 'CAA', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "DNSKEY" [ \t]+ data:DNSKEYData [ \t]* Comment? { return { type: 'record', recordType: 'DNSKEY', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "DS" [ \t]+ data:DSData [ \t]* Comment? { return { type: 'record', recordType: 'DS', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "RRSIG" [ \t]+ data:RRSIGData [ \t]* Comment? { return { type: 'record', recordType: 'RRSIG', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "NSEC" [ \t]+ data:NSECData [ \t]* Comment? { return { type: 'record', recordType: 'NSEC', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "TLSA" [ \t]+ data:TLSAData [ \t]* Comment? { return { type: 'record', recordType: 'TLSA', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "SSHFP" [ \t]+ data:SSHFPData [ \t]* Comment? { return { type: 'record', recordType: 'SSHFP', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "DNAME" [ \t]+ data:DNAMEData [ \t]* Comment? { return { type: 'record', recordType: 'DNAME', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "NAPTR" [ \t]+ data:NAPTRData [ \t]* Comment? { return { type: 'record', recordType: 'NAPTR', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "LOC" [ \t]+ data:LOCData [ \t]* Comment? { return { type: 'record', recordType: 'LOC', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "HINFO" [ \t]+ data:HINFOData [ \t]* Comment? { return { type: 'record', recordType: 'HINFO', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "SPF" [ \t]+ data:SPFData [ \t]* Comment? { return { type: 'record', recordType: 'SPF', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "A" [ \t]+ data:AData [ \t]* Comment? { return { type: 'record', recordType: 'A', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "AAAA" [ \t]+ data:AAAData [ \t]* Comment? { return { type: 'record', recordType: 'AAAA', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "CNAME" [ \t]+ data:CNAMEData [ \t]* Comment? { return { type: 'record', recordType: 'CNAME', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:Domain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "ZONEMD" [ \t]+ data:ZONEMDData [ \t]* Comment? { return { type: 'record', recordType: 'ZONEMD', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / [ \t]+ class_:Class [ \t]+ "SOA" [ \t]+ data:SOAData [ \t]* Comment? { return { type: 'record', recordType: 'SOA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "NS" [ \t]+ data:NSData [ \t]* Comment? { return { type: 'record', recordType: 'NS', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "MX" [ \t]+ data:MXData [ \t]* Comment? { return { type: 'record', recordType: 'MX', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "PTR" [ \t]+ data:PTRData [ \t]* Comment? { return { type: 'record', recordType: 'PTR', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "TXT" [ \t]+ data:TXTData [ \t]* Comment? { return { type: 'record', recordType: 'TXT', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "SRV" [ \t]+ data:SRVData [ \t]* Comment? { return { type: 'record', recordType: 'SRV', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "CAA" [ \t]+ data:CAAData [ \t]* Comment? { return { type: 'record', recordType: 'CAA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "DNSKEY" [ \t]+ data:DNSKEYData [ \t]* Comment? { return { type: 'record', recordType: 'DNSKEY', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "DS" [ \t]+ data:DSData [ \t]* Comment? { return { type: 'record', recordType: 'DS', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "RRSIG" [ \t]+ data:RRSIGData [ \t]* Comment? { return { type: 'record', recordType: 'RRSIG', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "NSEC" [ \t]+ data:NSECData [ \t]* Comment? { return { type: 'record', recordType: 'NSEC', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "TLSA" [ \t]+ data:TLSAData [ \t]* Comment? { return { type: 'record', recordType: 'TLSA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "SSHFP" [ \t]+ data:SSHFPData [ \t]* Comment? { return { type: 'record', recordType: 'SSHFP', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "DNAME" [ \t]+ data:DNAMEData [ \t]* Comment? { return { type: 'record', recordType: 'DNAME', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "NAPTR" [ \t]+ data:NAPTRData [ \t]* Comment? { return { type: 'record', recordType: 'NAPTR', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "LOC" [ \t]+ data:LOCData [ \t]* Comment? { return { type: 'record', recordType: 'LOC', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "HINFO" [ \t]+ data:HINFOData [ \t]* Comment? { return { type: 'record', recordType: 'HINFO', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "SPF" [ \t]+ data:SPFData [ \t]* Comment? { return { type: 'record', recordType: 'SPF', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "A" [ \t]+ data:AData [ \t]* Comment? { return { type: 'record', recordType: 'A', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "AAAA" [ \t]+ data:AAAData [ \t]* Comment? { return { type: 'record', recordType: 'AAAA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "CNAME" [ \t]+ data:CNAMEData [ \t]* Comment? { return { type: 'record', recordType: 'CNAME', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ class_:Class [ \t]+ "ZONEMD" [ \t]+ data:ZONEMDData [ \t]* Comment? { return { type: 'record', recordType: 'ZONEMD', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: class_, data }; }
  / [ \t]+ "SOA" [ \t]+ data:SOAData [ \t]* Comment? { return { type: 'record', recordType: 'SOA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "NS" [ \t]+ data:NSData [ \t]* Comment? { return { type: 'record', recordType: 'NS', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "MX" [ \t]+ data:MXData [ \t]* Comment? { return { type: 'record', recordType: 'MX', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "PTR" [ \t]+ data:PTRData [ \t]* Comment? { return { type: 'record', recordType: 'PTR', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "TXT" [ \t]+ data:TXTData [ \t]* Comment? { return { type: 'record', recordType: 'TXT', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "SRV" [ \t]+ data:SRVData [ \t]* Comment? { return { type: 'record', recordType: 'SRV', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "CAA" [ \t]+ data:CAAData [ \t]* Comment? { return { type: 'record', recordType: 'CAA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "DNSKEY" [ \t]+ data:DNSKEYData [ \t]* Comment? { return { type: 'record', recordType: 'DNSKEY', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "DS" [ \t]+ data:DSData [ \t]* Comment? { return { type: 'record', recordType: 'DS', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "RRSIG" [ \t]+ data:RRSIGData [ \t]* Comment? { return { type: 'record', recordType: 'RRSIG', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "NSEC" [ \t]+ data:NSECData [ \t]* Comment? { return { type: 'record', recordType: 'NSEC', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "TLSA" [ \t]+ data:TLSAData [ \t]* Comment? { return { type: 'record', recordType: 'TLSA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "SSHFP" [ \t]+ data:SSHFPData [ \t]* Comment? { return { type: 'record', recordType: 'SSHFP', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "DNAME" [ \t]+ data:DNAMEData [ \t]* Comment? { return { type: 'record', recordType: 'DNAME', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "NAPTR" [ \t]+ data:NAPTRData [ \t]* Comment? { return { type: 'record', recordType: 'NAPTR', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "LOC" [ \t]+ data:LOCData [ \t]* Comment? { return { type: 'record', recordType: 'LOC', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "HINFO" [ \t]+ data:HINFOData [ \t]* Comment? { return { type: 'record', recordType: 'HINFO', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "SPF" [ \t]+ data:SPFData [ \t]* Comment? { return { type: 'record', recordType: 'SPF', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "A" [ \t]+ data:AData [ \t]* Comment? { return { type: 'record', recordType: 'A', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "AAAA" [ \t]+ data:AAAData [ \t]* Comment? { return { type: 'record', recordType: 'AAAA', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "CNAME" [ \t]+ data:CNAMEData [ \t]* Comment? { return { type: 'record', recordType: 'CNAME', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / [ \t]+ "ZONEMD" [ \t]+ data:ZONEMDData [ \t]* Comment? { return { type: 'record', recordType: 'ZONEMD', domain: '', ttl: resolveTTL(null, currentTTL, inheritTTL), class: 'IN', data }; }
  / domain:NumberDomain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* "PTR" [ \t]+ data:PTRData [ \t]* Comment? { return { type: 'record', recordType: 'PTR', domain: expandDomain(domain, currentOrigin, expandDomains), ttl: resolveTTL(ttl, currentTTL, inheritTTL), class: class_ || 'IN', data }; }
  / domain:NumberDomain [ \t]* ttl:TTL? [ \t]* class_:Class? [ \t]* recordType:RecordType [ \t]+ [^\n]* { throw new Error(`Number-only domain "${expandDomain(domain, currentOrigin, expandDomains)}" is only supported for PTR records, not ${recordType}`); }

Comment = ";" [^\n]* { return null; }

BlankLine = [ \t]* [\n] { return null; }

Domain = !NumberOnly ("*." [a-zA-Z0-9._-]+ / [a-zA-Z0-9@._-]+) { return text(); }  // Allow wildcards, @, _, and relative names, but not pure numbers

NumberDomain = [0-9]+ { return text(); }  // Pure numbers allowed for PTR records in reverse zones

TTL = Number

Class = "IN"

SOAData = mname:DomainValue [ \t\n]+ rname:DomainValue [ \t\n]+ "(" [ \t\n]* serial:Number ([ \t]* Comment)? [ \t\n]+ refresh:Number ([ \t]* Comment)? [ \t\n]+ retry:Number ([ \t]* Comment)? [ \t\n]+ expire:Number ([ \t]* Comment)? [ \t\n]+ minimum:Number ([ \t]* Comment)? [ \t\n]* ")" { return { mname, rname, serial, refresh, retry, expire, minimum }; }
  / mname:DomainValue [ \t]+ rname:DomainValue [ \t]+ serial:Number [ \t]+ refresh:Number [ \t]+ retry:Number [ \t]+ expire:Number [ \t]+ minimum:Number { return { mname, rname, serial, refresh, retry, expire, minimum }; }

NSData = ns:DomainValue { return { ns }; }

MXData = priority:Number [ \t]+ mx:DomainValue { return { priority, mx }; }

AData = ip:IPv4 { return { ip }; }

AAAData = ip:IPv6 { return { ip }; }

CNAMEData = cname:DomainValue { return { cname }; }

ZONEMDData = serial:Number [ \t]+ scheme:Number [ \t]+ hashAlgo:Number [ \t]+ digest:HexString { return { serial, scheme, hashAlgo, digest }; }

PTRData = ptrdname:DomainValue { return { ptrdname }; }

TXTData = txt:QuotedString { return { txt }; }

SRVData = priority:Number [ \t]+ weight:Number [ \t]+ port:Number [ \t]+ target:DomainValue { return { priority, weight, port, target }; }

CAAData = flags:Number [ \t]+ tag:QuotedString [ \t]+ value:QuotedString { return { flags, tag, value }; }

DNSKEYData = flags:Number [ \t]+ protocol:Number [ \t]+ algorithm:Number [ \t]+ publicKey:Base64String { return { flags, protocol, algorithm, publicKey }; }

DSData = keyTag:Number [ \t]+ algorithm:Number [ \t]+ digestType:Number [ \t]+ digest:HexString { return { keyTag, algorithm, digestType, digest }; }

RRSIGData = typeCovered:RecordType [ \t]+ algorithm:Number [ \t]+ labels:Number [ \t]+ originalTTL:Number [ \t]+ expiration:Timestamp [ \t]+ inception:Timestamp [ \t]+ keyTag:Number [ \t]+ signer:DomainValue [ \t]+ signature:Base64String { return { typeCovered, algorithm, labels, originalTTL, expiration, inception, keyTag, signer, signature }; }

NSECData = nextDomain:DomainValue [ \t]+ recordTypes:RecordTypeList { return { nextDomain, recordTypes }; }

TLSAData = usage:Number [ \t]+ selector:Number [ \t]+ matchingType:Number [ \t]+ certificate:HexString { return { usage, selector, matchingType, certificate }; }

SSHFPData = algorithm:Number [ \t]+ fingerprintType:Number [ \t]+ fingerprint:HexString { return { algorithm, fingerprintType, fingerprint }; }

DNAMEData = target:DomainValue { return { target }; }

NAPTRData = order:Number [ \t]+ preference:Number [ \t]+ flags:QuotedString [ \t]+ service:QuotedString [ \t]+ regexp:QuotedString [ \t]+ replacement:DomainValue { return { order, preference, flags, service, regexp, replacement }; }

LOCData = content:LOCContent { return { content }; }

HINFOData = cpu:QuotedString [ \t]+ os:QuotedString { return { cpu, os }; }

SPFData = text:QuotedString { return { text }; }

LOCContent = [^\n;]+ { return text().trim(); }

DomainValue = d:Domain &([ \t] / ";" / [\n] / !.) { return d; }

QuotedString = "\"" content:[^\"]* "\"" { return content.join(''); }

Base64String = [A-Za-z0-9+/=]+ { return text(); }

HexString = [0-9A-Fa-f]+ { return text(); }

RecordType = [A-Z0-9]+ { return text(); }

RecordTypeList = first:RecordType rest:([ \t]+ RecordType)* { return [first, ...rest.map(([_, rt]) => rt)]; }

Timestamp = [0-9]+ { return parseInt(text()); }

Number = [0-9]+ { return parseInt(text()); }

NumberOnly = [0-9]+ !([a-zA-Z@._-])  // Pure numbers without domain characters

IPv4 = [0-9]+ "." [0-9]+ "." [0-9]+ "." [0-9]+ { return text(); }

IPv6 = [0-9a-fA-F:]+ { return text(); }  // Simplified IPv6 regex

_ = ([ \t]* [\n])*