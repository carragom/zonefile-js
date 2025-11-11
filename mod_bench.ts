/**
 * DNS Zone Parser Benchmarks
 *
 * Performance benchmarks for parsing zone files of various sizes.
 *
 * Usage:
 *   deno bench                    # Run all benchmarks
 *   deno bench --filter "root"    # Run specific benchmark
 */

import { parseZoneFile } from './mod.ts'

// Small zone files (< 10 records)
Deno.bench('parse localhost-forward.zone (4 records)', async () => {
	await parseZoneFile('test-data/localhost-forward.zone')
})

Deno.bench('parse localhost-reverse.zone (3 records)', async () => {
	await parseZoneFile('test-data/localhost-reverse.zone')
})

// Medium zone files (10-100 records)
Deno.bench('parse example.zone (15 records)', async () => {
	await parseZoneFile('test-data/example.zone')
})

Deno.bench('parse comprehensive.zone (73 records)', async () => {
	await parseZoneFile('test-data/comprehensive.zone')
})

Deno.bench('parse edge-cases.zone (74 records)', async () => {
	await parseZoneFile('test-data/edge-cases.zone')
})

// Large zone file (real-world IANA root zone sample)
Deno.bench('parse root-sample.zone (500 records)', async () => {
	await parseZoneFile('test-data/root-sample.zone')
})
