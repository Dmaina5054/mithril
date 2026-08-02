package proxy

import (
	"bufio"
	"encoding/binary"
)

const sniPeekSize = 512 // matches eBPF Feature 2's socket filter window, spec section 4

// PeekSNI looks at up to sniPeekSize bytes of a new connection without
// consuming them — subsequent reads through br (not the original
// net.Conn) will still see these bytes. Returns "" with no error if the
// data isn't a TLS ClientHello, is truncated, or has no SNI — this is a
// best-effort enrichment, never a reason to fail the connection.
//
// Complements the eBPF socket-filter SNI extractor (Feature 2) for
// connections where that filter fires too late or the handshake is
// non-standard, and works on hosts where eBPF socket filters are
// restricted.
func PeekSNI(br *bufio.Reader) (string, error) {
	buf, err := br.Peek(sniPeekSize)
	// Peek returns a short slice + error (often io.EOF) when fewer than
	// sniPeekSize bytes are available yet — still parse what we got,
	// the ClientHello may simply be smaller than the window.
	if len(buf) == 0 {
		return "", err
	}
	return parseSNI(buf), nil
}

// parseSNI extracts the first SNI hostname from a byte slice starting
// at a TLS record header. Never panics on malformed/truncated input —
// any structural surprise just returns "".
func parseSNI(buf []byte) string {
	const (
		recordHeaderLen    = 5
		handshakeHeaderLen = 4
		typeHandshake      = 0x16
		typeClientHello    = 0x01
		extSNI             = 0x0000
		sniHostName        = 0x00
	)

	if len(buf) < recordHeaderLen || buf[0] != typeHandshake {
		return ""
	}

	body := buf[recordHeaderLen:]
	if len(body) < handshakeHeaderLen || body[0] != typeClientHello {
		return ""
	}
	body = body[handshakeHeaderLen:]

	// client_version(2) + random(32)
	if len(body) < 34 {
		return ""
	}
	body = body[34:]

	// session_id
	if len(body) < 1 {
		return ""
	}
	sidLen := int(body[0])
	body = body[1:]
	if len(body) < sidLen {
		return ""
	}
	body = body[sidLen:]

	// cipher_suites
	if len(body) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < csLen {
		return ""
	}
	body = body[csLen:]

	// compression_methods
	if len(body) < 1 {
		return ""
	}
	cmLen := int(body[0])
	body = body[1:]
	if len(body) < cmLen {
		return ""
	}
	body = body[cmLen:]

	// extensions — absent entirely is valid (very old clients); no SNI
	// to find either way.
	if len(body) < 2 {
		return ""
	}
	extTotalLen := int(binary.BigEndian.Uint16(body[:2]))
	body = body[2:]
	if len(body) < extTotalLen {
		extTotalLen = len(body) // truncated by our 512-byte window — parse what we have
	}
	extensions := body[:extTotalLen]

	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions[:2])
		extLen := int(binary.BigEndian.Uint16(extensions[2:4]))
		extensions = extensions[4:]
		if len(extensions) < extLen {
			return "" // truncated mid-extension — can't trust what's left
		}
		extData := extensions[:extLen]
		extensions = extensions[extLen:]

		if extType != extSNI {
			continue
		}

		// server_name_list: list_length(2) + entries{name_type(1), name_length(2), name}
		if len(extData) < 2 {
			return ""
		}
		list := extData[2:]
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(binary.BigEndian.Uint16(list[1:3]))
			list = list[3:]
			if len(list) < nameLen {
				return ""
			}
			if nameType == sniHostName {
				return string(list[:nameLen])
			}
			list = list[nameLen:]
		}
		return "" // SNI extension present but no host_name entry found
	}

	return ""
}
