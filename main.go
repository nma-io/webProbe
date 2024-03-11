package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/net/html"
	"golang.org/x/net/http2"
)

// Global constants
const (
	version = "2024.0.1"
	author  = "Nicholas Albright (@nma-io)"
)

func checkProtocolsAndOrgs(url string) ([]string, []string, error) {
	supportedProtocols := make(map[string]bool)
	var orgNames []string
	checkProtocol(url, "http3", supportedProtocols, &orgNames)
	checkProtocol(url, "h2", supportedProtocols, &orgNames)
	checkProtocol(url, "http/1.1", supportedProtocols, &orgNames)
	var protocols []string
	for proto := range supportedProtocols {
		protocols = append(protocols, proto)
	}

	return protocols, orgNames, nil
}

func getProtocolDetails(url, proto string) (int, string, string, []string, error) {
	var transport http.RoundTripper
	var orgNames []string

	switch proto {
	case "http3":
		transport = &http3.RoundTripper{
			TLSClientConfig: &tls.Config{},
		}
	case "h2":
		transport = &http2.Transport{
			TLSClientConfig: &tls.Config{NextProtos: []string{"h2"}},
		}
	default: // end with http 1.1
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{NextProtos: []string{"http/1.1"}},
		}
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		// hndle errors from inaccessable protocols
		if strings.Contains(err.Error(), "unexpected ALPN protocol") {
			return 0, "", "", nil, fmt.Errorf("protocol %s not supported", proto)
		} else if strings.Contains(err.Error(), "timeout: no recent network activity") {
			return 0, "", "", nil, fmt.Errorf("protocol %s timed out", proto)
		}
		return 0, "", "", nil, err
	}
	defer resp.Body.Close()

	var protocolUsed string
	switch resp.Proto {
	case "HTTP/2.0":
		protocolUsed = "h2"
	case "HTTP/1.1":
		protocolUsed = "http/1.1"
	default:
		protocolUsed = "http3"
	}

	// get names from cert
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		for _, cert := range resp.TLS.PeerCertificates {
			if len(cert.Subject.Organization) > 0 {
				orgNames = append(orgNames, strings.Join(cert.Subject.Organization, ", "))
			}
		}
	}

	// extract the title from the response body
	title, err := parseTitle(resp.Body)
	if err != nil {
		return 0, "", "", nil, err
	}

	return resp.StatusCode, title, protocolUsed, orgNames, nil
}

func checkProtocol(url string, proto string, supportedProtocols map[string]bool, orgNames *[]string) {
	var transport http.RoundTripper

	switch proto {
	case "h2":
		t := &http2.Transport{
			TLSClientConfig: &tls.Config{NextProtos: []string{"h2"}},
		}
		transport = t
	case "http3":
		t := &http3.RoundTripper{
			TLSClientConfig: &tls.Config{},
		}
		transport = t
	default:
		t := &http.Transport{
			TLSClientConfig: &tls.Config{NextProtos: []string{"http/1.1"}},
		}
		transport = t
	}

	client := &http.Client{Transport: transport}
	resp, err := client.Get(url)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		supportedProtocols[resp.Proto] = true

		if len(*orgNames) == 0 {
			for _, cert := range resp.TLS.PeerCertificates {
				if len(cert.Subject.Organization) > 0 {
					*orgNames = append(*orgNames, strings.Join(cert.Subject.Organization, ", "))
				}
			}
		}
	}
}

func getHTTPResponseAndTitle(url string) (int, string, string, error) {
	protocols := []string{"http3", "h2", "http/1.1"}

	for _, proto := range protocols {
		var transport http.RoundTripper

		switch proto {
		case "h2":
			t := &http2.Transport{
				TLSClientConfig: &tls.Config{NextProtos: []string{"h2"}},
			}
			transport = t
		case "http3":
			t := &http3.RoundTripper{
				TLSClientConfig: &tls.Config{},
			}
			transport = t
		default:
			t := &http.Transport{
				TLSClientConfig: &tls.Config{NextProtos: []string{"http/1.1"}},
			}
			transport = t
		}

		client := &http.Client{Transport: transport}
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()

			// extract the title
			title, err := parseTitle(resp.Body)
			if err != nil {
				return 0, "", "", err
			}

			return resp.StatusCode, title, resp.Proto, nil
		}
	}

	return 0, "", "", fmt.Errorf("failed to connect with any protocol")
}

func parseTitle(body io.Reader) (string, error) {
	tokenizer := html.NewTokenizer(body)
	for {
		tokenType := tokenizer.Next()
		switch {
		case tokenType == html.ErrorToken:
			return "", tokenizer.Err()
		case tokenType == html.StartTagToken || tokenType == html.SelfClosingTagToken:
			token := tokenizer.Token()
			if token.Data == "title" {
				tokenizer.Next()
				return tokenizer.Token().Data, nil
			}
		}
	}
	return "", nil // no title...
}

func isDowngraded(requested, used string) bool {
	return requested != used
}

func getDescriptiveProtocolName(protocol string) string {
	switch protocol {
	case "http3":
		return "HTTP/3 (QUIC)"
	case "h2":
		return "HTTP/2 (TCP MULTIPLEXING)"
	case "http/1.1":
		return "HTTP/1.1 (TRADITIONAL)"
	default:
		return protocol // unsupported protocol
	}
}

func main() {
	log.SetFlags(0)
	log.Printf("HTTP Probe v%s, by %s\n", version, author)

	var url string
	if len(os.Args) > 1 {
		url = os.Args[1]
	} else {
		fmt.Print("Enter the website URL: ")
		scanner := bufio.NewScanner(os.Stdin)
		if scanner.Scan() {
			url = scanner.Text()
		}
		if scanner.Err() != nil {
			log.Fatal("Error reading input:", scanner.Err())
		}
	}

	if !strings.Contains(url, "https://") {
		url = "https://" + url
	}

	protocols := []string{"http3", "h2", "http/1.1"} // check for all three major protocols

	for _, protocol := range protocols {
		urlStr := color.New(color.FgRed).Sprint(url)
		statusCode, title, protocolUsed, orgNames, err := getProtocolDetails(url, protocol)
		if err != nil {
			if strings.Contains(err.Error(), "not supported") || strings.Contains(err.Error(), "timed out") {
				urlStr = color.New(color.FgRed).Sprintf(url+":"+" Protocol %s is not available for %s", protocol, url)
				fmt.Println(urlStr)
			} else {
				color.Red("Error fetching details for protocol %s: %v\n", protocol, err)
			}
			continue
		}

		// adjust the protocol display if downgraded by a security proxy (zscaler?)
		downgradedMsg := ""
		if isDowngraded(protocol, protocolUsed) {
			downgradedMsg = fmt.Sprintf(" [Downgraded from %s]", protocol)
		}

		orgNamesStr := color.New(color.FgGreen).Sprint("[" + strings.Join(orgNames, " -> ") + "]")
		statusCodeStr := color.New(color.FgCyan).Sprint(fmt.Sprintf("[%d]", statusCode))
		titleStr := color.New(color.FgMagenta).Sprint(fmt.Sprintf("[%s]", title))
		descriptiveProtocol := color.New(color.FgYellow).Sprint(getDescriptiveProtocolName(protocolUsed + downgradedMsg))

		fmt.Printf("%s: %s %s %s %s\n", urlStr, descriptiveProtocol, orgNamesStr, statusCodeStr, titleStr)

	}
	if len(os.Args) <= 1 {
		// look for enter if this was double clicked from the desktop.
		fmt.Println("Press [ENTER] to exit...")
		bufio.NewReader(os.Stdin).ReadBytes('\n')
	}
}
