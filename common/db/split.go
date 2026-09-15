package db

import "strings"

// splitStatements splits a SQL script into its individual statements.
//
// Splitting is needed because a migration has to be applied statement by
// statement: only then can a single statement's failure be reported against the
// text that caused it, and only then can the ledger adoption path in migrate()
// skip an ALTER that a previous build already applied.
//
// A semicolon terminates a statement only when it is not inside a comment, a
// string literal, a quoted identifier or a BEGIN ... END block. `strings.Split`
// on ";" got all four wrong, which is #44: a semicolon in a migration's prose
// cut the file mid-sentence and the fragments no longer parsed.
//
// Comments are stripped rather than carried through — they are of no use to
// SQLite and a file whose only content is a comment must not produce a
// statement. A line comment leaves its newline behind so it cannot weld the
// tokens on either side together.
//
// The one construct deliberately not handled is transaction control:
// migrate() wraps each migration in a transaction of its own, so a migration
// file must not open or close one. A `BEGIN` in leading position is therefore
// read as transaction control and passed through as its own statement (where
// SQLite will reject it as a nested transaction) rather than being mistaken for
// the opening of a compound statement, which would swallow the rest of the file.
func splitStatements(script string) []string {
	var (
		statements []string
		current    strings.Builder
		word       strings.Builder
		// depth counts open BEGIN/CASE blocks. Semicolons inside one belong to
		// the block, not to the statement containing it.
		depth int
		// leading reports whether the word about to be flushed is the first of
		// the statement, which is what distinguishes `BEGIN;` (transaction
		// control) from the `BEGIN` of a trigger body.
		leading = true
	)

	endStatement := func() {
		if s := strings.TrimSpace(current.String()); s != "" {
			statements = append(statements, s)
		}
		current.Reset()
		depth = 0
		leading = true
	}

	flushWord := func() {
		if word.Len() == 0 {
			return
		}
		keyword := strings.ToUpper(word.String())
		word.Reset()

		switch keyword {
		case "BEGIN":
			if !leading {
				depth++
			}
		case "CASE":
			depth++
		case "END":
			// Guard against underflow: `END` also closes constructs we do not
			// count, and a malformed script should not make the rest of the
			// file unsplittable.
			if depth > 0 {
				depth--
			}
		}
		leading = false
	}

	for i := 0; i < len(script); i++ {
		c := script[i]

		if isWordByte(c) {
			word.WriteByte(c)
			current.WriteByte(c)
			continue
		}
		flushWord()

		switch {
		case c == '-' && i+1 < len(script) && script[i+1] == '-':
			nl := strings.IndexByte(script[i:], '\n')
			if nl < 0 {
				i = len(script)
				break
			}
			i += nl // the loop's i++ steps past the newline we write here
			current.WriteByte('\n')

		case c == '/' && i+1 < len(script) && script[i+1] == '*':
			end := strings.Index(script[i+2:], "*/")
			if end < 0 {
				i = len(script)
				break
			}
			i += 2 + end + 1 // land on the '/' of the closing "*/"
			current.WriteByte(' ')

		case c == '\'' || c == '"' || c == '`' || c == '[':
			i = copyQuoted(&current, script, i)

		case c == ';':
			if depth > 0 {
				current.WriteByte(c)
			} else {
				endStatement()
			}

		default:
			current.WriteByte(c)
		}
	}

	flushWord()
	endStatement()

	return statements
}

// copyQuoted copies the quoted run starting at script[start] into dst verbatim,
// delimiters included, and returns the index of its closing delimiter. A
// doubled delimiter is an escape for the delimiter itself, which is how SQLite
// writes an apostrophe inside a string literal; bracket quoting has no escape.
//
// An unterminated run returns the script's last byte rather than its length, so
// that the caller's own i++ still steps past the end and ends its loop.
func copyQuoted(dst *strings.Builder, script string, start int) int {
	open := script[start]
	closer := open
	if open == '[' {
		closer = ']'
	}

	dst.WriteByte(open)

	for i := start + 1; i < len(script); i++ {
		c := script[i]
		dst.WriteByte(c)
		if c != closer {
			continue
		}
		if closer != ']' && i+1 < len(script) && script[i+1] == closer {
			i++
			dst.WriteByte(script[i])
			continue
		}
		return i
	}

	return len(script) - 1
}

// isWordByte reports whether c can appear in a SQL keyword or identifier. Bytes
// at or above 0x80 are the continuation and lead bytes of a multi-byte rune,
// which can only be part of an identifier here; treating them as word bytes
// keeps a UTF-8 identifier from being cut into pieces.
func isWordByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z',
		c >= 'A' && c <= 'Z',
		c >= '0' && c <= '9',
		c == '_', c == '$', c >= 0x80:
		return true
	}
	return false
}
