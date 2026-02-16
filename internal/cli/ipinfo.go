package cli

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

type IPInfo struct {
	IP          string  `json:"query"`
	Status      string  `json:"status"`
	Country     string  `json:"country"`
	CountryCode string  `json:"countryCode"`
	Region      string  `json:"regionName"`
	City        string  `json:"city"`
	ISP         string  `json:"isp"`
	Org         string  `json:"org"`
	AS          string  `json:"as"`
	Lat         float64 `json:"lat"`
	Lon         float64 `json:"lon"`
	Timezone    string  `json:"timezone"`
	Mobile      bool    `json:"mobile"`
	Proxy       bool    `json:"proxy"`
	Hosting     bool    `json:"hosting"`
}

func LookupIP(rawAddr string) *IPInfo {
	ip := extractIP(rawAddr)
	if ip == "" {
		return nil
	}

	if isLoopback(ip) {
		return &IPInfo{
			IP:      ip,
			Status:  "local",
			Country: "Loopback",
			ISP:     "localhost",
			City:    "local machine",
		}
	}

	client := &http.Client{Timeout: 5 * time.Second}
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=status,message,country,countryCode,regionName,city,isp,org,as,lat,lon,timezone,mobile,proxy,hosting,query", ip)

	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var info IPInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}

	if info.Status != "success" {
		return nil
	}

	return &info
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}

func isLoopback(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback()
}

func printIPInfo(info *IPInfo) {
	if info == nil {
		dimmed.Println("  │  IP lookup failed")
		return
	}

	if info.Status == "local" {
		dimmed.Println("  │  IP: localhost (loopback — local test)")
		return
	}

	fmt.Printf("  │  IP          : %s\n", bold.Sprintf("%s", info.IP))
	fmt.Printf("  │  Location    : %s, %s, %s %s\n",
		info.City, info.Region, info.Country,
		flag(info.CountryCode))
	fmt.Printf("  │  ISP         : %s\n", info.ISP)
	fmt.Printf("  │  Org         : %s\n", info.Org)
	fmt.Printf("  │  ASN         : %s\n", info.AS)
	fmt.Printf("  │  Timezone    : %s\n", info.Timezone)
	fmt.Printf("  │  Coordinates : %.4f, %.4f\n", info.Lat, info.Lon)

	var flags []string
	if info.Proxy {
		flags = append(flags, red.Sprintf("PROXY/VPN"))
	}
	if info.Hosting {
		flags = append(flags, yellow.Sprintf("HOSTING/DATACENTER"))
	}
	if info.Mobile {
		flags = append(flags, cyan.Sprintf("MOBILE"))
	}
	if len(flags) > 0 {
		fmt.Printf("  │  Flags       : %s\n", strings.Join(flags, " "))
	} else {
		green.Println("  │  Flags       : none (residential)")
	}
}

func flag(code string) string {
	if len(code) != 2 {
		return ""
	}
	r1 := rune(code[0]-'A') + 0x1F1E6
	r2 := rune(code[1]-'A') + 0x1F1E6
	return string([]rune{r1, r2})
}
