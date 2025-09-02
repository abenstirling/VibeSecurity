package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type CheckResult struct {
	Check   string             `json:"check"`
	Status  string             `json:"status"`
	Details string             `json:"details"`
	Timing  map[string]float64 `json:"timing"`
}

type TimingStats struct {
	TotalTime           float64                    `json:"total_time"`
	CheckBreakdown      map[string]map[string]any  `json:"check_breakdown"`
	NetworkTimeTotal    float64                    `json:"network_time_total"`
	ProcessingTimeTotal float64                    `json:"processing_time_total"`
	SlowestChecks       []map[string]any           `json:"slowest_checks"`
}

type ScanResult struct {
	URL         string                     `json:"url"`
	Timestamp   string                     `json:"timestamp"`
	Checks      []CheckResult              `json:"checks"`
	Timings     map[string]map[string]any  `json:"timings"`
	TimingStats TimingStats                `json:"timing_stats"`
	TotalTime   float64                    `json:"total_time"`
	Summary     map[string]int             `json:"summary"`
}

type SecurityScanner struct {
	URL        string
	HTTPClient *http.Client
	Timings    map[string]map[string]any
}

func NewSecurityScanner(targetURL string) *SecurityScanner {
	return &SecurityScanner{
		URL: targetURL,
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
			},
		},
		Timings: make(map[string]map[string]any),
	}
}

func (s *SecurityScanner) timeCheck(checkName string, checkFunc func() CheckResult) CheckResult {
	start := time.Now()
	result := checkFunc()
	
	totalTime := time.Since(start).Seconds()
	
	// For simplicity, we'll treat all time as network time since Go's concurrent nature
	// makes it harder to separate network vs processing time precisely
	networkTime := totalTime
	processingTime := 0.0
	
	timing := map[string]any{
		"total":      totalTime,
		"network":    networkTime,
		"processing": processingTime,
	}
	
	s.Timings[checkName] = timing
	result.Timing = map[string]float64{
		"total":      totalTime,
		"network":    networkTime,
		"processing": processingTime,
	}
	
	return result
}

func (s *SecurityScanner) CheckHTTPS() CheckResult {
	return s.timeCheck("HTTPS Usage", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "HTTPS Usage",
				Status:  "fail",
				Details: "Could not verify HTTPS usage",
			}
		}
		defer resp.Body.Close()
		
		isHTTPS := strings.HasPrefix(s.URL, "https://")
		status := "pass"
		details := "Site uses HTTPS"
		if !isHTTPS {
			status = "fail"
			details = "Site does not use HTTPS"
		}
		
		return CheckResult{
			Check:   "HTTPS Usage",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) CheckSSLValidity() CheckResult {
	return s.timeCheck("SSL Certificate", func() CheckResult {
		parsedURL, err := url.Parse(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "SSL Certificate",
				Status:  "fail",
				Details: "Invalid URL",
			}
		}
		
		conn, err := tls.Dial("tcp", parsedURL.Host+":443", &tls.Config{
			ServerName: parsedURL.Hostname(),
		})
		if err != nil {
			return CheckResult{
				Check:   "SSL Certificate",
				Status:  "fail",
				Details: "Invalid or expired SSL certificate",
			}
		}
		defer conn.Close()
		
		return CheckResult{
			Check:   "SSL Certificate",
			Status:  "pass",
			Details: "Valid SSL certificate",
		}
	})
}

func (s *SecurityScanner) CheckCSP() CheckResult {
	return s.timeCheck("Content Security Policy", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "Content Security Policy",
				Status:  "warning",
				Details: "Could not verify CSP configuration",
			}
		}
		defer resp.Body.Close()
		
		csp := resp.Header.Get("Content-Security-Policy")
		status := "pass"
		details := "CSP is configured"
		if csp == "" {
			status = "warning"
			details = "CSP is not configured"
		}
		
		return CheckResult{
			Check:   "Content Security Policy",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) CheckXFrameOptions() CheckResult {
	return s.timeCheck("X-Frame-Options", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "X-Frame-Options",
				Status:  "warning",
				Details: "Could not verify X-Frame-Options configuration",
			}
		}
		defer resp.Body.Close()
		
		xfo := resp.Header.Get("X-Frame-Options")
		status := "pass"
		details := "X-Frame-Options is configured"
		if xfo == "" {
			status = "warning"
			details = "X-Frame-Options is not configured"
		}
		
		return CheckResult{
			Check:   "X-Frame-Options",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) CheckHSTS() CheckResult {
	return s.timeCheck("HSTS", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "HSTS",
				Status:  "warning",
				Details: "Could not verify HSTS configuration",
			}
		}
		defer resp.Body.Close()
		
		hsts := resp.Header.Get("Strict-Transport-Security")
		status := "pass"
		details := "HSTS is configured"
		if hsts == "" {
			status = "warning"
			details = "HSTS is not configured"
		}
		
		return CheckResult{
			Check:   "HSTS",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) CheckDirectoryListing() CheckResult {
	return s.timeCheck("Directory Listing", func() CheckResult {
		targetURL := s.URL
		if !strings.HasSuffix(targetURL, "/") {
			targetURL += "/"
		}
		
		resp, err := s.HTTPClient.Get(targetURL)
		if err != nil {
			return CheckResult{
				Check:   "Directory Listing",
				Status:  "pass",
				Details: "Could not verify directory listing configuration",
			}
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return CheckResult{
				Check:   "Directory Listing",
				Status:  "pass",
				Details: "Could not read response body",
			}
		}
		
		// Parse HTML and look for directory-like links
		doc, err := html.Parse(strings.NewReader(string(body)))
		if err != nil {
			return CheckResult{
				Check:   "Directory Listing",
				Status:  "pass",
				Details: "Could not parse HTML",
			}
		}
		
		hasDirectoryListing := s.containsDirectoryLinks(doc)
		status := "pass"
		details := "Directory listing appears to be disabled"
		if hasDirectoryListing {
			status = "warning"
			details = "Directory listing may be enabled"
		}
		
		return CheckResult{
			Check:   "Directory Listing",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) containsDirectoryLinks(n *html.Node) bool {
	if n.Type == html.ElementNode && n.Data == "a" {
		for _, attr := range n.Attr {
			if attr.Key == "href" && strings.HasSuffix(attr.Val, "/") {
				return true
			}
		}
	}
	
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if s.containsDirectoryLinks(c) {
			return true
		}
	}
	
	return false
}

func (s *SecurityScanner) CheckServerInfo() CheckResult {
	return s.timeCheck("Server Information", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "Server Information",
				Status:  "warning",
				Details: "Could not verify server information configuration",
			}
		}
		defer resp.Body.Close()
		
		server := resp.Header.Get("Server")
		status := "pass"
		details := "Server information is hidden"
		if server != "" {
			status = "warning"
			details = fmt.Sprintf("Server information is exposed: %s", server)
		}
		
		return CheckResult{
			Check:   "Server Information",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) CheckAdminPages() CheckResult {
	return s.timeCheck("Admin Pages", func() CheckResult {
		adminPaths := []string{"/admin", "/wp-admin", "/administrator", "/manager"}
		
		for _, path := range adminPaths {
			resp, err := s.HTTPClient.Get(s.URL + path)
			if err != nil {
				continue
			}
			resp.Body.Close()
			
			if resp.StatusCode == 200 {
				return CheckResult{
					Check:   "Admin Pages",
					Status:  "warning",
					Details: fmt.Sprintf("Admin page found at %s", path),
				}
			}
		}
		
		return CheckResult{
			Check:   "Admin Pages",
			Status:  "pass",
			Details: "No common admin pages found",
		}
	})
}

func (s *SecurityScanner) CheckHTTPSForms() CheckResult {
	return s.timeCheck("HTTPS Forms", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "HTTPS Forms",
				Status:  "warning",
				Details: "Could not verify form security",
			}
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return CheckResult{
				Check:   "HTTPS Forms",
				Status:  "warning",
				Details: "Could not read response body",
			}
		}
		
		doc, err := html.Parse(strings.NewReader(string(body)))
		if err != nil {
			return CheckResult{
				Check:   "HTTPS Forms",
				Status:  "warning",
				Details: "Could not parse HTML",
			}
		}
		
		insecureForms := s.countInsecureForms(doc)
		status := "pass"
		details := "All forms use HTTPS"
		if insecureForms > 0 {
			status = "fail"
			details = fmt.Sprintf("Found %d forms using HTTP", insecureForms)
		}
		
		return CheckResult{
			Check:   "HTTPS Forms",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) countInsecureForms(n *html.Node) int {
	count := 0
	
	if n.Type == html.ElementNode && n.Data == "form" {
		for _, attr := range n.Attr {
			if attr.Key == "action" && strings.HasPrefix(attr.Val, "http://") {
				count++
				break
			}
		}
	}
	
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		count += s.countInsecureForms(c)
	}
	
	return count
}

func (s *SecurityScanner) CheckExposedAPIKeys() CheckResult {
	return s.timeCheck("Exposed API Keys", func() CheckResult {
		resp, err := s.HTTPClient.Get(s.URL)
		if err != nil {
			return CheckResult{
				Check:   "Exposed API Keys",
				Status:  "warning",
				Details: "Could not verify API key exposure",
			}
		}
		defer resp.Body.Close()
		
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return CheckResult{
				Check:   "Exposed API Keys",
				Status:  "warning",
				Details: "Could not read response body",
			}
		}
		
		content := strings.ToLower(string(body))
		
		patterns := map[string]*regexp.Regexp{
			"stripe":   regexp.MustCompile(`sk_(live|test)_[0-9a-zA-Z]{24}`),
			"aws":      regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
			"github":   regexp.MustCompile(`ghp_[0-9a-zA-Z]{36}`),
			"google":   regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
			"firebase": regexp.MustCompile(`[0-9a-zA-Z\-]{20}\.[0-9a-zA-Z\-]{20}\.[0-9a-zA-Z\-]{20}`),
		}
		
		var foundKeys []string
		for keyType, pattern := range patterns {
			matches := pattern.FindAllString(content, -1)
			for _, match := range matches {
				foundKeys = append(foundKeys, fmt.Sprintf("%s: %s", strings.ToUpper(keyType), match))
			}
		}
		
		status := "pass"
		details := "No exposed API keys found"
		if len(foundKeys) > 0 {
			status = "fail"
			details = fmt.Sprintf("Found %d exposed API keys:\n%s", len(foundKeys), strings.Join(foundKeys, "\n"))
		}
		
		return CheckResult{
			Check:   "Exposed API Keys",
			Status:  status,
			Details: details,
		}
	})
}

func (s *SecurityScanner) Scan() ScanResult {
	start := time.Now()
	fmt.Fprintf(os.Stderr, "Starting scan for %s\n", s.URL)
	
	checks := []CheckResult{
		s.CheckHTTPS(),
		s.CheckSSLValidity(),
		s.CheckCSP(),
		s.CheckXFrameOptions(),
		s.CheckHSTS(),
		s.CheckDirectoryListing(),
		s.CheckServerInfo(),
		s.CheckAdminPages(),
		s.CheckHTTPSForms(),
		s.CheckExposedAPIKeys(),
	}
	
	totalTime := time.Since(start).Seconds()
	fmt.Fprintf(os.Stderr, "\nScan completed in %.2fs\n", totalTime)
	
	// Calculate timing statistics
	timingStats := TimingStats{
		TotalTime:           totalTime,
		CheckBreakdown:      s.Timings,
		NetworkTimeTotal:    0,
		ProcessingTimeTotal: 0,
		SlowestChecks:       []map[string]any{},
	}
	
	for checkName, timing := range s.Timings {
		if networkTime, ok := timing["network"].(float64); ok {
			timingStats.NetworkTimeTotal += networkTime
		}
		if processingTime, ok := timing["processing"].(float64); ok {
			timingStats.ProcessingTimeTotal += processingTime
		}
		
		if totalTime, ok := timing["total"].(float64); ok {
			slowestCheck := map[string]any{
				"check":           checkName,
				"total_time":      totalTime,
				"network_time":    timing["network"],
				"processing_time": timing["processing"],
			}
			timingStats.SlowestChecks = append(timingStats.SlowestChecks, slowestCheck)
		}
	}
	
	// Count status summary
	summary := map[string]int{
		"pass":    0,
		"warning": 0,
		"fail":    0,
		"total":   len(checks),
	}
	
	for _, check := range checks {
		summary[check.Status]++
	}
	
	return ScanResult{
		URL:         s.URL,
		Timestamp:   time.Now().Format(time.RFC3339),
		Checks:      checks,
		Timings:     s.Timings,
		TimingStats: timingStats,
		TotalTime:   totalTime,
		Summary:     summary,
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <url>\n", os.Args[0])
		os.Exit(1)
	}
	
	targetURL := os.Args[1]
	scanner := NewSecurityScanner(targetURL)
	result := scanner.Scan()
	
	jsonOutput, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error marshaling JSON: %v\n", err)
		os.Exit(1)
	}
	
	fmt.Println(string(jsonOutput))
}