/**
 * DNS Zone Parser Benchmarks
 *
 * Performance benchmarks for parsing zone files of various sizes.
 *
 * Usage:
 *   deno bench                    # Run all benchmarks
 *   deno bench --filter "root"    # Run specific benchmark
 */

import { parseZone } from './mod.ts'

// Pre-load zone file contents to isolate parsing performance
const localhostForward = await Deno.readTextFile('test-data/localhost-forward.zone')
const localhostReverse = await Deno.readTextFile('test-data/localhost-reverse.zone')
const example = await Deno.readTextFile('test-data/example.zone')
const comprehensive = await Deno.readTextFile('test-data/comprehensive.zone')
const edgeCases = await Deno.readTextFile('test-data/edge-cases.zone')
const rootSample = await Deno.readTextFile('test-data/root-sample.zone')

// Small zone files (< 10 records)
Deno.bench('parse localhost-forward.zone (4 records)', () => {
	parseZone(localhostForward)
})

Deno.bench('parse localhost-reverse.zone (3 records)', () => {
	parseZone(localhostReverse)
})

// Medium zone files (10-100 records)
Deno.bench('parse example.zone (15 records)', () => {
	parseZone(example)
})

Deno.bench('parse comprehensive.zone (73 records)', () => {
	parseZone(comprehensive)
})

Deno.bench('parse edge-cases.zone (74 records)', () => {
	parseZone(edgeCases)
})

// Large zone file (real-world IANA root zone sample)
Deno.bench('parse root-sample.zone (500 records)', () => {
	parseZone(rootSample)
})
