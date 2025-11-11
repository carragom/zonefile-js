import type { ZoneEntry } from '../mod.ts'

export interface ParseOptions {
	grammarSource?: string
	startRule?: string
	/**
	 * Whether to expand domain names using $ORIGIN directive
	 * @default false
	 */
	expandDomains?: boolean
	/**
	 * Whether to inherit TTL values from $TTL directive
	 * @default false
	 */
	inheritTTL?: boolean
}

export function parse(input: string, options?: ParseOptions): ZoneEntry[]
