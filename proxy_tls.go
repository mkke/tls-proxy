package main

import (
	"log"
	"net"
	"strconv"
)

func proxyTLSConnection(downstream net.Conn, config ProxyConfigs) {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		log.Printf("TLS: read at pos 0 failed: %v", err)
		_ = downstream.Close()
		return
	}
	if firstByte[0] != 0x16 {
		log.Printf("TLS: unexpected data")
		_ = downstream.Close()
		return
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
	if err != nil {
		log.Printf("TLS: read at pos 1 failed: %v", err)
		_ = downstream.Close()
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		log.Printf("TLS: expected TLS version >= 3.1")
		_ = downstream.Close()
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		log.Printf("TLS: reading restLength bytes failed: %v", err)
		_ = downstream.Close()
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, err = downstream.Read(rest)
	if err != nil {
		log.Printf("TLS: reading rest of bytes failed: %v", err)
		_ = downstream.Close()
		return
	}

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		log.Printf("TLS: expected ClientHello handshake")
		_ = downstream.Close()
		return
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		log.Printf("TLS: expected TLS extensions")
		_ = downstream.Close()
		return
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {

			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current += 1
			if nameType != 0 {
				log.Printf("TLS: extension is not a hostname")
				_ = downstream.Close()
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		log.Printf("TLS: no hostname found")
		_ = downstream.Close()
		return
	}

	pc := config.GetHostConfig(hostname)
	if pc == nil {
		log.Printf("TLS: no upstream found for %s", hostname)
		_ = downstream.Close()
		return
	}

	dialAddr := pc.TargetHost + ":" + strconv.Itoa(pc.TargetPort)
	var upstream net.Conn
	if pc.Dialer != nil {
		upstream, err = pc.Dialer.Dial("tcp", dialAddr)
	} else {
		upstream, err = net.Dial("tcp", dialAddr)
	}
	if err != nil {
		log.Printf("TLS: connection %s (sni %s) -> upstream %s failed: %v", downstream.RemoteAddr(), hostname, dialAddr, err)
		_ = downstream.Close()
		return
	}
	log.Printf("TLS: connected %s (sni %s) -> upstream %s", downstream.RemoteAddr(), hostname, dialAddr)

	_, err = upstream.Write(firstByte)
	if err != nil {
		log.Printf("TLS: upstream %s write failed: %v", dialAddr, err)
		_ = downstream.Close()
		return
	}
	_, err = upstream.Write(versionBytes)
	if err != nil {
		log.Printf("TLS: upstream %s write failed: %v", dialAddr, err)
		_ = downstream.Close()
		return
	}
	_, err = upstream.Write(restLengthBytes)
	if err != nil {
		log.Printf("TLS: upstream %s write failed: %v", dialAddr, err)
		_ = downstream.Close()
		return
	}
	_, err = upstream.Write(rest)
	if err != nil {
		log.Printf("TLS: upstream %s write failed: %v", dialAddr, err)
		_ = downstream.Close()
		return
	}

	go copyAndClose(upstream, downstream)
	go copyAndClose(downstream, upstream)
}
