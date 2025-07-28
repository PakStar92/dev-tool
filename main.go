// Direct CDN URL Video Extractor in Go - No File Storage
// Returns direct download URLs by parsing HTML forms and APIs

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/gin-gonic/gin"
)

// Configuration
const (
	USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	TIMEOUT    = 30 * time.Second
)

// Service configurations
var SERVICES = map[string]ServiceConfig{
	"savefrom": {
		URL:          "https://savefrom.net",
		Method:       "parseFormSubmission",
		FormSelector: "#sf_form",
		InputName:    "sf_url",
	},
	"y2mate": {
		URL:             "https://www.y2mate.com",
		Method:          "parseMultiStep",
		AnalyzeEndpoint: "/mates/analyze/ajax",
		ConvertEndpoint: "/mates/convert",
	},
	"loader": {
		URL:             "https://loader.to",
		Method:          "parseDirectAPI",
		APIEndpoint:     "/api/button",
		ConvertEndpoint: "/api/convert",
	},
	"savetube": {
		URL:         "https://savetube.me",
		Method:      "parseAjaxAPI",
		APIEndpoint: "/api/convert",
	},
}

// Data structures
type ServiceConfig struct {
	URL             string
	Method          string
	FormSelector    string
	InputName       string
	APIEndpoint     string
	AnalyzeEndpoint string
	ConvertEndpoint string
}

type DirectDownload struct {
	DirectURL string `json:"directUrl"`
	Quality   string `json:"quality"`
	Format    string `json:"format"`
	Service   string `json:"service"`
	Type      string `json:"type"`
	Size      string `json:"size,omitempty"`
}

type ExtractResponse struct {
	Success   bool             `json:"success"`
	Downloads []DirectDownload `json:"downloads"`
	Services  []string         `json:"services"`
	Total     int              `json:"total"`
	Error     string           `json:"error,omitempty"`
}

type Y2MateAnalyzeResponse struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

type Y2MateConvertResponse struct {
	Status string `json:"status"`
	Result string `json:"result"`
}

// Direct URL Extractor
type DirectURLExtractor struct {
	client *http.Client
}

func NewDirectURLExtractor() *DirectURLExtractor {
	return &DirectURLExtractor{
		client: &http.Client{
			Timeout: TIMEOUT,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

// HTTP request helper
func (d *DirectURLExtractor) makeRequest(method, requestURL string, body interface{}) (*http.Response, error) {
	var bodyReader *strings.Reader
	if body != nil {
		if formData, ok := body.(url.Values); ok {
			bodyReader = strings.NewReader(formData.Encode())
		} else if str, ok := body.(string); ok {
			bodyReader = strings.NewReader(str)
		}
	}

	req, err := http.NewRequest(method, requestURL, bodyReader)
	if err != nil {
		return nil, err
	}

	// Set comprehensive headers
	req.Header.Set("User-Agent", USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	if method == "POST" && bodyReader != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	return d.client.Do(req)
}

// Extract video ID from URL
func (d *DirectURLExtractor) getVideoID(videoURL string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([^&\n?#]+)`),
		regexp.MustCompile(`youtube\.com\/v\/([^&\n?#]+)`),
		regexp.MustCompile(`(?:instagram\.com\/p\/|instagram\.com\/reel\/)([^\/\?]+)`),
		regexp.MustCompile(`(?:tiktok\.com\/@[^\/]+\/video\/|vm\.tiktok\.com\/)([^\/\?]+)`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(videoURL)
		if len(matches) > 1 {
			return matches[1]
		}
	}
	return ""
}

// Parse SaveFrom.net HTML form
func (d *DirectURLExtractor) parseSaveFromNet(videoURL string) []DirectDownload {
	log.Printf("[SaveFrom] Parsing form for: %s", videoURL)

	// Step 1: Get main page to extract form data
	resp, err := d.makeRequest("GET", SERVICES["savefrom"].URL, nil)
	if err != nil {
		log.Printf("[SaveFrom] Main page error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("[SaveFrom] Parse main page error: %v", err)
		return nil
	}

	// Extract form data
	form := doc.Find(SERVICES["savefrom"].FormSelector)
	action, _ := form.Attr("action")
	if action == "" {
		action = "/process"
	}

	// Get hidden form fields
	formData := url.Values{}
	form.Find("input[type=\"hidden\"]").Each(func(i int, s *goquery.Selection) {
		name, _ := s.Attr("name")
		value, _ := s.Attr("value")
		if name != "" && value != "" {
			formData.Set(name, value)
		}
	})

	// Add video URL
	formData.Set(SERVICES["savefrom"].InputName, videoURL)

	// Step 2: Submit form
	submitResp, err := d.makeRequest("POST", SERVICES["savefrom"].URL+action, formData)
	if err != nil {
		log.Printf("[SaveFrom] Submit error: %v", err)
		return nil
	}
	defer submitResp.Body.Close()

	submitResp.Header.Set("Referer", SERVICES["savefrom"].URL)
	submitResp.Header.Set("Origin", SERVICES["savefrom"].URL)

	// Step 3: Parse download links
	downloadDoc, err := goquery.NewDocumentFromReader(submitResp.Body)
	if err != nil {
		log.Printf("[SaveFrom] Parse download page error: %v", err)
		return nil
	}

	var downloads []DirectDownload

	// Look for direct CDN URLs
	downloadDoc.Find(".download-link, a[href*=\"googlevideo.com\"], a[href*=\"fbcdn.net\"], a[href*=\"cdninstagram.com\"]").Each(func(i int, s *goquery.Selection) {
		href, exists := s.Attr("href")
		if !exists {
			return
		}

		// Check if it's a direct CDN URL
		if strings.Contains(href, "googlevideo.com") || strings.Contains(href, "fbcdn.net") || strings.Contains(href, "cdninstagram.com") {
			quality := "Unknown"
			if qualityMatch := regexp.MustCompile(`(\d+p|\d+x\d+|HD|SD)`).FindString(s.Text()); qualityMatch != "" {
				quality = qualityMatch
			}

			format := "mp4"
			if formatMatch := regexp.MustCompile(`mime=video%2F(\w+)|\.(\w+)`).FindStringSubmatch(href); len(formatMatch) > 1 {
				if formatMatch[1] != "" {
					format = formatMatch[1]
				} else if formatMatch[2] != "" {
					format = formatMatch[2]
				}
			}

			downloads = append(downloads, DirectDownload{
				DirectURL: href,
				Quality:   quality,
				Format:    format,
				Service:   "savefrom",
				Type:      "video",
			})
		}
	})

	// Look for JavaScript variables containing URLs
	downloadDoc.Find("script").Each(func(i int, s *goquery.Selection) {
		scriptText := s.Text()
		urlRegex := regexp.MustCompile(`https://[^"']+(?:googlevideo\.com|fbcdn\.net|cdninstagram\.com)[^"']*`)
		matches := urlRegex.FindAllString(scriptText, -1)

		for _, match := range matches {
			// Check if already exists
			exists := false
			for _, existing := range downloads {
				if existing.DirectURL == match {
					exists = true
					break
				}
			}

			if !exists {
				downloads = append(downloads, DirectDownload{
					DirectURL: match,
					Quality:   "Auto",
					Format:    "mp4",
					Service:   "savefrom",
					Type:      "video",
				})
			}
		}
	})

	log.Printf("[SaveFrom] Found %d direct URLs", len(downloads))
	return downloads
}

// Parse Y2Mate multi-step process
func (d *DirectURLExtractor) parseY2Mate(videoURL string) []DirectDownload {
	log.Printf("[Y2Mate] Multi-step parsing for: %s", videoURL)

	videoID := d.getVideoID(videoURL)
	if videoID == "" {
		log.Printf("[Y2Mate] Could not extract video ID")
		return nil
	}

	// Step 1: Analyze video
	analyzeData := url.Values{
		"url":     {videoURL},
		"q_auto": {"0"},
		"ajax":   {"1"},
	}

	analyzeResp, err := d.makeRequest("POST", SERVICES["y2mate"].URL+SERVICES["y2mate"].AnalyzeEndpoint, analyzeData)
	if err != nil {
		log.Printf("[Y2Mate] Analyze error: %v", err)
		return nil
	}
	defer analyzeResp.Body.Close()

	analyzeResp.Header.Set("Referer", fmt.Sprintf("%s/youtube/%s", SERVICES["y2mate"].URL, videoID))
	analyzeResp.Header.Set("X-Requested-With", "XMLHttpRequest")

	var analyzeResponse Y2MateAnalyzeResponse
	if err := json.NewDecoder(analyzeResp.Body).Decode(&analyzeResponse); err != nil {
		log.Printf("[Y2Mate] Analyze decode error: %v", err)
		return nil
	}

	if analyzeResponse.Status != "ok" {
		log.Printf("[Y2Mate] Analysis failed")
		return nil
	}

	// Step 2: Parse conversion options
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(analyzeResponse.Result))
	if err != nil {
		log.Printf("[Y2Mate] Parse analyze result error: %v", err)
		return nil
	}

	type ConversionOption struct {
		K        string
		Quality  string
		Format   string
		FQuality string
	}

	var options []ConversionOption
	doc.Find(".download-items tr").Each(func(i int, s *goquery.Selection) {
		quality := strings.TrimSpace(s.Find(".text-left").First().Text())
		format := strings.TrimSpace(s.Find(".text-center").First().Text())
		downloadBtn := s.Find(".download-btn")

		if downloadBtn.Length() > 0 {
			k, _ := downloadBtn.Attr("data-ftype")
			fquality, _ := downloadBtn.Attr("data-fquality")

			options = append(options, ConversionOption{
				K:        k,
				Quality:  quality,
				Format:   strings.ToLower(format),
				FQuality: fquality,
			})
		}
	})

	// Step 3: Convert options to get direct URLs
	var downloads []DirectDownload
	for i, option := range options {
		if i >= 3 { // Limit to 3 requests
			break
		}

		convertData := url.Values{
			"vid":        {videoID},
			"k":          {option.K},
			"ftype":      {option.Format},
			"fquality":   {option.FQuality},
			"token":      {""},
			"timeExpire": {""},
			"client":     {"y2mate"},
		}

		convertResp, err := d.makeRequest("POST", SERVICES["y2mate"].URL+SERVICES["y2mate"].ConvertEndpoint, convertData)
		if err != nil {
			log.Printf("[Y2Mate] Convert error for %s: %v", option.Quality, err)
			continue
		}

		convertResp.Header.Set("X-Requested-With", "XMLHttpRequest")

		var convertResponse Y2MateConvertResponse
		if err := json.NewDecoder(convertResp.Body).Decode(&convertResponse); err != nil {
			convertResp.Body.Close()
			log.Printf("[Y2Mate] Convert decode error: %v", err)
			continue
		}
		convertResp.Body.Close()

		if convertResponse.Status == "ok" {
			resultDoc, err := goquery.NewDocumentFromReader(strings.NewReader(convertResponse.Result))
			if err != nil {
				continue
			}

			directURL, exists := resultDoc.Find("a[href*=\"download\"]").First().Attr("href")
			if exists && directURL != "" {
				downloadType := "video"
				if option.Format == "mp3" {
					downloadType = "audio"
				}

				downloads = append(downloads, DirectDownload{
					DirectURL: directURL,
					Quality:   option.Quality,
					Format:    option.Format,
					Service:   "y2mate",
					Type:      downloadType,
				})
			}
		}
	}

	log.Printf("[Y2Mate] Found %d direct URLs", len(downloads))
	return downloads
}

// Parse Loader.to API
func (d *DirectURLExtractor) parseLoaderTo(videoURL string) []DirectDownload {
	log.Printf("[Loader.to] API parsing for: %s", videoURL)

	// Step 1: Get conversion options
	apiURL := fmt.Sprintf("%s%s/?url=%s", SERVICES["loader"].URL, SERVICES["loader"].APIEndpoint, url.QueryEscape(videoURL))
	resp, err := d.makeRequest("GET", apiURL, nil)
	if err != nil {
		log.Printf("[Loader.to] API error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	resp.Header.Set("Referer", SERVICES["loader"].URL)
	resp.Header.Set("X-Requested-With", "XMLHttpRequest")

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Printf("[Loader.to] Parse error: %v", err)
		return nil
	}

	type ConvertOption struct {
		ConvertURL string
		Quality    string
		Format     string
	}

	var options []ConvertOption
	doc.Find(".convert-btn, .download-btn").Each(func(i int, s *goquery.Selection) {
		format, _ := s.Attr("data-format")
		quality, _ := s.Attr("data-quality")
		convertURL, _ := s.Attr("data-convert-url")

		if convertURL != "" {
			if format == "" {
				format = "mp4"
			}
			if quality == "" {
				quality = "auto"
			}

			options = append(options, ConvertOption{
				ConvertURL: convertURL,
				Quality:    quality,
				Format:     format,
			})
		}
	})

	// Step 2: Convert each option
	var downloads []DirectDownload
	for i, option := range options {
		if i >= 2 { // Limit requests
			break
		}

		convertResp, err := d.makeRequest("GET", option.ConvertURL, nil)
		if err != nil {
			log.Printf("[Loader.to] Convert error: %v", err)
			continue
		}

		convertResp.Header.Set("Referer", SERVICES["loader"].URL)
		convertResp.Header.Set("X-Requested-With", "XMLHttpRequest")

		// Try to parse as JSON first
		var jsonResponse map[string]interface{}
		if err := json.NewDecoder(convertResp.Body).Decode(&jsonResponse); err == nil {
			if directURL, ok := jsonResponse["url"].(string); ok && directURL != "" {
				downloadType := "video"
				if option.Format == "mp3" {
					downloadType = "audio"
				}

				downloads = append(downloads, DirectDownload{
					DirectURL: directURL,
					Quality:   option.Quality,
					Format:    option.Format,
					Service:   "loader.to",
					Type:      downloadType,
				})
			}
		} else {
			// Parse as HTML
			convertResp.Body.Close()
			convertResp, err = d.makeRequest("GET", option.ConvertURL, nil)
			if err != nil {
				continue
			}

			convertDoc, err := goquery.NewDocumentFromReader(convertResp.Body)
			if err != nil {
				convertResp.Body.Close()
				continue
			}

			directURL, exists := convertDoc.Find("a[href*=\"download\"], a[download]").First().Attr("href")
			if exists && strings.HasPrefix(directURL, "http") {
				downloadType := "video"
				if option.Format == "mp3" {
					downloadType = "audio"
				}

				downloads = append(downloads, DirectDownload{
					DirectURL: directURL,
					Quality:   option.Quality,
					Format:    option.Format,
					Service:   "loader.to",
					Type:      downloadType,
				})
			}
		}
		convertResp.Body.Close()
	}

	log.Printf("[Loader.to] Found %d direct URLs", len(downloads))
	return downloads
}

// Parse SaveTube AJAX API
func (d *DirectURLExtractor) parseSaveTube(videoURL string) []DirectDownload {
	log.Printf("[SaveTube] AJAX parsing for: %s", videoURL)

	formData := url.Values{
		"url":     {videoURL},
		"format":  {"mp4"},
		"quality": {"auto"},
	}

	resp, err := d.makeRequest("POST", SERVICES["savetube"].URL+SERVICES["savetube"].APIEndpoint, formData)
	if err != nil {
		log.Printf("[SaveTube] Request error: %v", err)
		return nil
	}
	defer resp.Body.Close()

	resp.Header.Set("Referer", SERVICES["savetube"].URL)
	resp.Header.Set("X-Requested-With", "XMLHttpRequest")

	var downloads []DirectDownload

	// Try JSON response first
	var jsonResponse map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&jsonResponse); err == nil {
		if status, ok := jsonResponse["status"].(string); ok && status == "success" {
			if downloadsData, ok := jsonResponse["downloads"].([]interface{}); ok {
				for _, item := range downloadsData {
					if itemMap, ok := item.(map[string]interface{}); ok {
						if directURL, ok := itemMap["url"].(string); ok && strings.HasPrefix(directURL, "http") {
							quality := "auto"
							if q, ok := itemMap["quality"].(string); ok {
								quality = q
							}

							format := "mp4"
							if f, ok := itemMap["format"].(string); ok {
								format = f
							}

							downloadType := "video"
							if t, ok := itemMap["type"].(string); ok {
								downloadType = t
							}

							downloads = append(downloads, DirectDownload{
								DirectURL: directURL,
								Quality:   quality,
								Format:    format,
								Service:   "savetube",
								Type:      downloadType,
							})
						}
					}
				}
			}
		}
	} else {
		// Parse as HTML
		resp.Body.Close()
		resp, err = d.makeRequest("POST", SERVICES["savetube"].URL+SERVICES["savetube"].APIEndpoint, formData)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		doc, err := goquery.NewDocumentFromReader(resp.Body)
		if err != nil {
			return nil
		}

		doc.Find(".download-option, .download-link").Each(func(i int, s *goquery.Selection) {
			var href string
			if link := s.Find("a"); link.Length() > 0 {
				href, _ = link.Attr("href")
			} else {
				href, _ = s.Attr("href")
			}

			if href != "" && strings.HasPrefix(href, "http") {
				quality := strings.TrimSpace(s.Find(".quality").Text())
				if quality == "" {
					quality = "auto"
				}

				format := strings.TrimSpace(s.Find(".format").Text())
				if format == "" {
					format = "mp4"
				} else {
					format = strings.ToLower(format)
				}

				downloadType := "video"
				if format == "mp3" {
					downloadType = "audio"
				}

				downloads = append(downloads, DirectDownload{
					DirectURL: href,
					Quality:   quality,
					Format:    format,
					Service:   "savetube",
					Type:      downloadType,
				})
			}
		})
	}

	log.Printf("[SaveTube] Found %d direct URLs", len(downloads))
	return downloads
}

// Main extraction function
func (d *DirectURLExtractor) getAllDirectURLs(videoURL string) ExtractResponse {
	log.Printf("[DirectExtractor] Processing: %s", videoURL)

	// Run all parsers concurrently
	type result struct {
		downloads []DirectDownload
		service   string
	}

	results := make(chan result, 4)

	go func() {
		downloads := d.parseSaveFromNet(videoURL)
		results <- result{downloads, "savefrom"}
	}()

	go func() {
		downloads := d.parseY2Mate(videoURL)
		results <- result{downloads, "y2mate"}
	}()

	go func() {
		downloads := d.parseLoaderTo(videoURL)
		results <- result{downloads, "loader.to"}
	}()

	go func() {
		downloads := d.parseSaveTube(videoURL)
		results <- result{downloads, "savetube"}
	}()

	// Collect results
	var allDownloads []DirectDownload
	var services []string

	for i := 0; i < 4; i++ {
		select {
		case res := <-results:
			if len(res.downloads) > 0 {
				allDownloads = append(allDownloads, res.downloads...)
				services = append(services, res.service)
				log.Printf("[%s] Found %d direct URLs", res.service, len(res.downloads))
			}
		case <-time.After(45 * time.Second):
			log.Printf("Timeout waiting for service results")
		}
	}

	// Remove duplicates and sort
	uniqueDownloads := d.removeDuplicates(allDownloads)
	sortedDownloads := d.sortByQuality(uniqueDownloads)

	return ExtractResponse{
		Success:   len(sortedDownloads) > 0,
		Downloads: sortedDownloads,
		Services:  services,
		Total:     len(sortedDownloads),
	}
}

func (d *DirectURLExtractor) removeDuplicates(downloads []DirectDownload) []DirectDownload {
	seen := make(map[string]bool)
	var unique []DirectDownload

	for _, download := range downloads {
		key := fmt.Sprintf("%s-%s-%s", download.DirectURL, download.Quality, download.Format)
		if !seen[key] {
			seen[key] = true
			unique = append(unique, download)
		}
	}

	return unique
}

func (d *DirectURLExtractor) sortByQuality(downloads []DirectDownload) []DirectDownload {
	qualityOrder := map[string]int{
		"1080p": 5, "720p": 4, "480p": 3, "360p": 2, "auto": 1, "unknown": 0,
	}

	sort.Slice(downloads, func(i, j int) bool {
		iQuality := qualityOrder[strings.ToLower(downloads[i].Quality)]
		jQuality := qualityOrder[strings.ToLower(downloads[j].Quality)]
		return iQuality > jQuality
	})

	return downloads
}


// HTTP Handlers
func setupRoutes() *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.Default()
	extractor := NewDirectURLExtractor()

	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	router.GET("/api/direct-urls", func(c *gin.Context) {
		videoURL := c.Query("url")
		if videoURL == "" {
			c.JSON(400, ExtractResponse{
				Success: false,
				Error:   "URL parameter is required",
			})
			return
		}

		log.Printf("[API] Getting direct URLs for: %s", videoURL)
		result := extractor.getAllDirectURLs(videoURL)

		if !result.Success {
			result.Error = "No direct URLs found. The video might be private, unavailable, or services are down."
		}

		c.JSON(200, result)
	})

	router.GET("/health", func(c *gin.Context) {
		serviceList := make([]string, 0, len(SERVICES))
		for service := range SERVICES {
			serviceList = append(serviceList, service)
		}

		c.JSON(200, gin.H{
			"status":   "OK",
			"message":  "Direct Video URL Extractor",
			"services": serviceList,
			"note":     "Returns direct CDN URLs without file storage",
		})
	})

	router.GET("/", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")
		c.String(200, htmlInterface)
	})

	return router
}

const htmlInterface = `
<!DOCTYPE html>
<html>
<head>
    <title>🎯 Go Direct Video URL Extractor</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { background: rgba(255,255,255,0.95); padding: 30px; border-radius: 15px; margin-bottom: 20px; box-shadow: 0 8px 32px rgba(0,0,0,0.1); backdrop-filter: blur(10px); }
        h1 { color: #333; text-align: center; margin-bottom: 10px; font-size: 2.5em; }
        .subtitle { text-align: center; color: #666; margin-bottom: 30px; font-size: 1.1em; }
        .note { background: linear-gradient(45deg, #f8f9fa, #e9ecef); border-left: 4px solid #007bff; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .input-group { display: flex; gap: 10px; margin-bottom: 20px; }
        input[type="url"] { flex: 1; padding: 15px; border: 2px solid #ddd; border-radius: 8px; font-size: 16px; transition: border-color 0.3s; }
        input[type="url"]:focus { border-color: #667eea; outline: none; box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1); }
        button { padding: 15px 30px; background: linear-gradient(45deg, #667eea, #764ba2); color: white; border: none; border-radius: 8px; cursor: pointer; font-size: 16px; font-weight: bold; transition: all 0.3s; }
        button:hover { transform: translateY(-2px); box-shadow: 0 4px 15px rgba(0,0,0,0.2); }
        button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; }
        .url-item { background: linear-gradient(45deg, #f8f9fa, #ffffff); padding: 25px; margin: 15px 0; border-radius: 12px; border-left: 5px solid #667eea; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }
        .url-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .url-title { font-weight: bold; color: #333; font-size: 1.1em; }
        .url-meta { color: #666; font-size: 0.9em; }
        .direct-url { background: #2d3748; color: #e2e8f0; padding: 15px; border-radius: 8px; font-family: 'Courier New', monospace; word-break: break-all; margin: 15px 0; font-size: 0.9em; }
        .button-group { display: flex; gap: 10px; margin-top: 15px; }
        .copy-btn { background: linear-gradient(45deg, #28a745, #20c997); color: white; border: none; padding: 10px 20px; border-radius: 6px; cursor: pointer; font-weight: bold; transition: all 0.2s; }
        .copy-btn:hover { transform: translateY(-1px); box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
        .open-btn { background: linear-gradient(45deg, #17a2b8, #138496); color: white; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; transition: all 0.2s; display: inline-block; }
        .open-btn:hover { transform: translateY(-1px); box-shadow: 0 2px 8px rgba(0,0,0,0.2); }
        .loading { text-align: center; margin: 30px 0; color: #667eea; font-size: 1.2em; }
        .spinner { border: 3px solid #f3f3f3; border-top: 3px solid #667eea; border-radius: 50%; width: 40px; height: 40px; animation: spin 1s linear infinite; margin: 0 auto 20px; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .error { color: #dc3545; background: linear-gradient(45deg, #f8d7da, #f5c6cb); padding: 20px; border-radius: 8px; border: 1px solid #f5c6cb; }
        .success { color: #155724; background: linear-gradient(45deg, #d4edda, #c3e6cb); padding: 20px; border-radius: 8px; border: 1px solid #c3e6cb; margin-bottom: 20px; }
        .stats { display: flex; justify-content: space-around; background: #e9ecef; padding: 15px; border-radius: 8px; margin: 15px 0; }
        .stat-item { text-align: center; }
        .stat-number { font-size: 1.5em; font-weight: bold; color: #667eea; }
        .stat-label { font-size: 0.9em; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎯 Go Direct URL Extractor</h1>
        <p class="subtitle">Extract direct CDN URLs without file storage</p>
        
        <div class="note">
            <strong>🚀 How it works:</strong> This Go-powered tool parses HTML forms from multiple video services and extracts direct CDN URLs (googlevideo.com, fbcdn.net, cdninstagram.com) that can be used for direct downloading or streaming. No files are stored on the server.
        </div>
        
        <div class="input-group">
            <input type="url" id="videoUrl" placeholder="Enter video URL (YouTube, Instagram, TikTok, Facebook, etc.)" />
            <button onclick="extractDirectUrls()" id="extractBtn">🎯 Extract URLs</button>
        </div>
    </div>
    
    <div id="results"></div>

    <script>
        async function extractDirectUrls() {
            const url = document.getElementById('videoUrl').value;
            const resultsDiv = document.getElementById('results');
            const extractBtn = document.getElementById('extractBtn');
            
            if (!url) {
                alert('Please enter a valid URL');
                return;
            }
            
            extractBtn.disabled = true;
            extractBtn.textContent = '🔄 Extracting...';
            
            resultsDiv.innerHTML = \`
                <div class="container">
                    <div class="loading">
                        <div class="spinner"></div>
                        🔍 Parsing HTML forms and extracting direct CDN URLs...
                        <br><small>Processing multiple services concurrently</small>
                    </div>
                </div>
            \`;
            
            try {
                const response = await fetch('/api/direct-urls?url=' + encodeURIComponent(url));
                const data = await response.json();
                
                if (data.success && data.downloads.length > 0) {
                    let html = \`
                        <div class="container">
                            <h3>✅ Direct CDN URLs Extracted</h3>
                            <div class="success">🎉 Successfully extracted from: \${data.services.join(', ')}</div>
                            <div class="stats">
                                <div class="stat-item">
                                    <div class="stat-number">\${data.total}</div>
                                    <div class="stat-label">Direct URLs</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-number">\${data.services.length}</div>
                                    <div class="stat-label">Services</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-number">\${data.downloads.filter(d => d.type === 'video').length}</div>
                                    <div class="stat-label">Video</div>
                                </div>
                                <div class="stat-item">
                                    <div class="stat-number">\${data.downloads.filter(d => d.type === 'audio').length}</div>
                                    <div class="stat-label">Audio</div>
                                </div>
                            </div>
                        </div>
                    \`;
                    
                    data.downloads.forEach((item, index) => {
                        const typeIcon = item.type === 'audio' ? '🎵' : '🎥';
                        const qualityBadge = getQualityBadge(item.quality);
                        
                        html += \`
                            <div class="container">
                                <div class="url-item">
                                    <div class="url-header">
                                        <div class="url-title">
                                            \${typeIcon} \${qualityBadge} \${item.format.toUpperCase()} 
                                        </div>
                                        <div class="url-meta">📡 via \${item.service}</div>
                                    </div>
                                    <div class="direct-url">\${item.directUrl}</div>
                                    <div class="button-group">
                                        <button class="copy-btn" onclick="copyToClipboard('\${item.directUrl}', this)">
                                            📋 Copy URL
                                        </button>
                                        <a href="\${item.directUrl}" target="_blank" class="open-btn">
                                            🔗 Open Direct
                                        </a>
                                        <button class="copy-btn" onclick="downloadDirect('\${item.directUrl}', '\${item.format}')" style="background: linear-gradient(45deg, #dc3545, #c82333);">
                                            ⬇️ Download
                                        </button>
                                    </div>
                                </div>
                            </div>
                        \`;
                    });
                    
                    resultsDiv.innerHTML = html;
                } else {
                    resultsDiv.innerHTML = \`
                        <div class="container">
                            <div class="error">
                                ❌ No direct URLs found
                                <br><br>
                                <strong>Possible reasons:</strong>
                                <ul style="margin: 10px 0; text-align: left;">
                                    <li>Video is private or unavailable</li>
                                    <li>Platform has changed their structure</li>
                                    <li>Services are temporarily down</li>
                                    <li>URL format is not supported</li>
                                </ul>
                                <strong>Try:</strong> Different video URL or wait a few minutes
                            </div>
                        </div>
                    \`;
                }
            } catch (error) {
                resultsDiv.innerHTML = \`
                    <div class="container">
                        <div class="error">
                            ❌ Extraction Error: \${error.message}
                            <br><br>
                            Please check your internet connection and try again.
                        </div>
                    </div>
                \`;
            } finally {
                extractBtn.disabled = false;
                extractBtn.textContent = '🎯 Extract URLs';
            }
        }
        
        function getQualityBadge(quality) {
            const badges = {
                '1080p': '<span style="background:#28a745;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">1080p</span>',
                '720p': '<span style="background:#17a2b8;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">720p</span>',
                '480p': '<span style="background:#ffc107;color:black;padding:2px 8px;border-radius:12px;font-size:0.8em;">480p</span>',
                '360p': '<span style="background:#6c757d;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">360p</span>',
                'auto': '<span style="background:#007bff;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">AUTO</span>',
            };
            return badges[quality.toLowerCase()] || \`<span style="background:#6c757d;color:white;padding:2px 8px;border-radius:12px;font-size:0.8em;">\${quality}</span>\`;
        }
        
        async function copyToClipboard(text, button) {
            try {
                await navigator.clipboard.writeText(text);
                const originalText = button.textContent;
                button.textContent = '✅ Copied!';
                button.style.background = 'linear-gradient(45deg, #28a745, #20c997)';
                
                setTimeout(() => {
                    button.textContent = originalText;
                    button.style.background = '';
                }, 2000);
            } catch (err) {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                button.textContent = '✅ Copied!';
                setTimeout(() => {
                    button.textContent = '📋 Copy URL';
                }, 2000);
            }
        }
        
        function downloadDirect(url, format) {
            // Create a temporary download link
            const a = document.createElement('a');
            a.href = url;
            a.download = \`video_\${Date.now()}.\${format}\`;
            a.target = '_blank';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
        }

        // Allow Enter key to trigger extraction
        document.getElementById('videoUrl').addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                extractDirectUrls();
            }
        });

        // Auto-focus on URL input
        document.getElementById('videoUrl').focus();
    </script>
</body>
</html>
`

func main() {
	log.Println("🎯 Starting Go Direct Video URL Extractor...")

	router := setupRoutes()

	port := "8080"
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	log.Printf("🌐 Web interface: http://localhost:%s", port)
	log.Printf("📡 API endpoint: http://localhost:%s/api/direct-urls", port)
	log.Printf("💡 Returns direct CDN URLs without file storage")
	log.Printf("🚀 Services: %v", getServiceNames())

	if err := router.Run(":" + port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func getServiceNames() []string {
	names := make([]string, 0, len(SERVICES))
	for name := range SERVICES {
		names = append(names, name)
	}
	return names
}
