package main

import (
	"bufio"
	"container/list"
	"io"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
)

func copyAndClose(dst io.WriteCloser, src io.Reader) {
	defer dst.Close()

	_, err := io.Copy(dst, src)
	if err != nil {
		log.Printf("write failed: %v", err)
	}
}

var pathRegexp = regexp.MustCompile(`^(\S+\s+)(\S+)(\s.+)?$`)

func proxyHTTPConnection(downstream net.Conn, config ProxyConfigs) {
	reader := bufio.NewReader(downstream)
	hostname := ""
	path := ""
	readLines := list.New()

	// read first line
	bytes, _, err := reader.ReadLine()
	if err != nil {
		log.Printf("HTTP: read failed: %v", err)
		_ = downstream.Close()
		return
	}
	line := string(bytes)

	firstLineMatch := pathRegexp.FindStringSubmatch(line)
	if firstLineMatch == nil {
		log.Printf("HTTP: unexpected first line '%s'", line)
		_ = downstream.Close()
		return
	}
	path = firstLineMatch[2]

	for {
		bytes, _, err := reader.ReadLine()
		if err != nil {
			log.Printf("HTTP: read failed: %v", err)
			_ = downstream.Close()
			return
		}
		line := string(bytes)
		readLines.PushBack(line)
		if line == "" {
			// End of HTTP headers
			break
		}
		if strings.HasPrefix(line, "Host: ") {
			hostname = strings.TrimPrefix(line, "Host: ")
			break
		}
	}

	pc := config.GetHostPathConfig(hostname, path)
	if pc == nil {
		log.Printf("HTTP: no upstream found for %s%s", hostname, path)
		_ = downstream.Close()
		return
	}

	if pc.RewritePath != "" {
		path = pc.MatchPathRegexp.ReplaceAllString(path, pc.RewritePath)
	}
	readLines.PushFront(firstLineMatch[1] + path + firstLineMatch[3])

	dialAddr := pc.TargetHost + ":" + strconv.Itoa(pc.TargetPort)
	var upstream net.Conn
	if pc.Dialer != nil {
		upstream, err = pc.Dialer.Dial("tcp", dialAddr)
	} else {
		upstream, err = net.Dial("tcp", dialAddr)
	}
	if err != nil {
		log.Printf("HTTP: connection %s (host %s) -> upstream %s failed: %v", downstream.RemoteAddr(), hostname, dialAddr, err)
		_ = downstream.Close()
		return
	}
	log.Printf("HTTP: connected %s (host %s) -> upstream %s", downstream.RemoteAddr(), hostname, dialAddr)

	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		_, err := upstream.Write([]byte(line))
		if err != nil {
			log.Printf("HTTP: upstream %s write failed: %v", dialAddr, err)
			_ = downstream.Close()
			return
		}
		_, err = upstream.Write([]byte("\n"))
		if err != nil {
			log.Printf("HTTP: upstream %s write failed: %v", dialAddr, err)
			_ = downstream.Close()
			return
		}
	}

	go copyAndClose(upstream, reader)
	go copyAndClose(downstream, upstream)
}
