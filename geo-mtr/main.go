package main

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"
)

// GeoLocation 存储地理位置信息
type GeoLocation struct {
	Country string `json:"country"`
	Region  string `json:"regionName"`
	City    string `json:"city"`
}

// getGeoLocation 获取地理位置
func getGeoLocation(ip string) GeoLocation {
	url := fmt.Sprintf("http://ip-api.com/json/%s", ip)
	resp, err := http.Get(url)
	if err != nil {
		return GeoLocation{Country: "Unknown", Region: "Unknown", City: "Unknown"}
	}
	defer resp.Body.Close()

	var location GeoLocation
	if err := json.NewDecoder(resp.Body).Decode(&location); err != nil {
		return GeoLocation{Country: "Unknown", Region: "Unknown", City: "Unknown"}
	}
	return location
}

// traceroute 执行路径追踪
func traceroute(target string, maxHops int) {
	// 解析目标地址
	addr, err := net.ResolveIPAddr("ip", target)
	if err != nil {
		fmt.Printf("无法解析目标地址: %s\n", target)
		os.Exit(1)
	}

	fmt.Printf("目标: %s [%s]\n", target, addr.String())
	fmt.Println("+-----+----------------+-----------+---------------+------------+------------+")
	fmt.Println("| Hop | IP Address     | Avg Delay | Country       | Region     | City       |")
	fmt.Println("+-----+----------------+-----------+---------------+------------+------------+")

	for ttl := 1; ttl <= maxHops; ttl++ {
		// 创建 socket
		conn, err := net.DialIP("ip4:icmp", nil, addr)
		if err != nil {
			fmt.Printf("无法创建连接: %v\n", err)
			break
		}

		// 设置 TTL
		rawConn, err := conn.SyscallConn()
		if err != nil {
			fmt.Printf("无法获取原始连接: %v\n", err)
			conn.Close()
			continue
		}
		rawConn.Control(func(fd uintptr) {
			syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
		})

		// 发送 ICMP 数据包
		msg := make([]byte, 32)
		msg[0] = 8 // ICMP Echo
		msg[1] = 0 // Code
		msg[2] = 0 // Checksum
		msg[3] = 0 // Identifier

		start := time.Now()
		_, err = conn.Write(msg)
		if err != nil {
			fmt.Printf("| %3d | Timeout        |     *     | Unknown       | Unknown    | Unknown    |\n", ttl)
			conn.Close()
			continue
		}

		// 接收响应
		buf := make([]byte, 512)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		_, addr, err := conn.ReadFrom(buf)

		elapsed := time.Since(start)
		conn.Close()

		if err != nil {
			fmt.Printf("| %3d | Timeout        |     *     | Unknown       | Unknown    | Unknown    |\n", ttl)
			continue
		}

		ip := addr.String()
		location := getGeoLocation(ip)
		fmt.Printf("| %3d | %-15s | %9s | %-13s | %-10s | %-10s |\n",
			ttl, ip, elapsed, location.Country, location.Region, location.City)

		// 如果已经到达目标地址，停止追踪
		if ip == addr.String() {
			break
		}
	}
	fmt.Println("+-----+----------------+-----------+---------------+------------+------------+")
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("使用方法: ./mtr <目标域名或IP>")
		os.Exit(1)
	}

	target := os.Args[1]
	maxHops := 30
	traceroute(target, maxHops)
}
