package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log"
	"net/http"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

type TailscaleStatus struct {
	Version      string   `json:"Version"`
	TUN          bool     `json:"TUN"`
	BackendState string   `json:"BackendState"`
	AuthURL      string   `json:"AuthURL"`
	TailscaleIPs []string `json:"TailscaleIPs"`
	Self         struct {
		ID             string                 `json:"ID"`
		PublicKey      string                 `json:"PublicKey"`
		HostName       string                 `json:"HostName"`
		DNSName        string                 `json:"DNSName"`
		OS             string                 `json:"OS"`
		UserID         int                    `json:"UserID"`
		TailscaleIPs   []string               `json:"TailscaleIPs"`
		AllowedIPs     []string               `json:"AllowedIPs"`
		Tags           []string               `json:"Tags"`
		Addrs          []string               `json:"Addrs"`
		CurAddr        string                 `json:"CurAddr"`
		Relay          string                 `json:"Relay"`
		RxBytes        int                    `json:"RxBytes"`
		TxBytes        int                    `json:"TxBytes"`
		Created        time.Time              `json:"Created"`
		LastWrite      time.Time              `json:"LastWrite"`
		LastSeen       time.Time              `json:"LastSeen"`
		LastHandshake  time.Time              `json:"LastHandshake"`
		Online         bool                   `json:"Online"`
		ExitNode       bool                   `json:"ExitNode"`
		ExitNodeOption bool                   `json:"ExitNodeOption"`
		Active         bool                   `json:"Active"`
		PeerAPIURL     []string               `json:"PeerAPIURL"`
		Capabilities   []string               `json:"Capabilities"`
		CapMap         map[string]interface{} `json:"CapMap"`
		InNetworkMap   bool                   `json:"InNetworkMap"`
		InMagicSock    bool                   `json:"InMagicSock"`
		InEngine       bool                   `json:"InEngine"`
	} `json:"Self"`
	MagicDNSSuffix string `json:"MagicDNSSuffix"`
	CurrentTailnet struct {
		Name            string `json:"Name"`
		MagicDNSSuffix  string `json:"MagicDNSSuffix"`
		MagicDNSEnabled bool   `json:"MagicDNSEnabled"`
	} `json:"CurrentTailnet"`
	Peer map[string]struct {
		ID             string    `json:"ID"`
		PublicKey      string    `json:"PublicKey"`
		HostName       string    `json:"HostName"`
		DNSName        string    `json:"DNSName"`
		OS             string    `json:"OS"`
		UserID         int       `json:"UserID"`
		TailscaleIPs   []string  `json:"TailscaleIPs"`
		AllowedIPs     []string  `json:"AllowedIPs"`
		Tags           []string  `json:"Tags"`
		CurAddr        string    `json:"CurAddr"`
		Relay          string    `json:"Relay"`
		RxBytes        int       `json:"RxBytes"`
		TxBytes        int       `json:"TxBytes"`
		Created        time.Time `json:"Created"`
		LastWrite      time.Time `json:"LastWrite"`
		LastSeen       time.Time `json:"LastSeen"`
		LastHandshake  time.Time `json:"LastHandshake"`
		Online         bool      `json:"Online"`
		ExitNode       bool      `json:"ExitNode"`
		ExitNodeOption bool      `json:"ExitNodeOption"`
		Active         bool      `json:"Active"`
		PeerAPIURL     []string  `json:"PeerAPIURL"`
		Capabilities   []string  `json:"Capabilities"`
		InNetworkMap   bool      `json:"InNetworkMap"`
		InMagicSock    bool      `json:"InMagicSock"`
		InEngine       bool      `json:"InEngine"`
		KeyExpiry      time.Time `json:"KeyExpiry"`
	} `json:"Peer"`
	User map[string]struct {
		ID            int    `json:"ID"`
		LoginName     string `json:"LoginName"`
		DisplayName   string `json:"DisplayName"`
		ProfilePicURL string `json:"ProfilePicURL"`
	} `json:"User"`
	ClientVersion interface{} `json:"ClientVersion"`
}
type Collector struct {
}

var dynLabels = []string{"id", "name", "given_name", "ip", "peer_name", "peer_given_name", "peer_ip", "peer_user_id"}
var PeerRxDesc = prometheus.NewDesc("tailscale_peer_rx", "", dynLabels, nil)
var PeerTxDesc = prometheus.NewDesc("tailscale_peer_tx", "", dynLabels, nil)

func (collector *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- PeerTxDesc
	ch <- PeerRxDesc
}

// Collect implements required collect function for all promehteus collectors
func (collector *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	status, err := TailscaleGetStatus(ctx)
	if err != nil {
		panic(err)
	}
	templateLabels := make([]string, len(dynLabels))
	templateLabels[0] = status.Self.ID
	templateLabels[1] = status.Self.HostName
	templateLabels[2] = strings.Split(status.Self.DNSName, ".")[0]
	templateLabels[3] = status.Self.TailscaleIPs[0]
	for _, peer := range status.Peer {
		labels := slices.Clone(templateLabels)
		labels[4] = peer.HostName
		labels[5] = strings.Split(peer.DNSName, ".")[0]
		labels[6] = peer.TailscaleIPs[0]
		labels[7] = strconv.Itoa(peer.UserID)

		ch <- prometheus.MustNewConstMetric(PeerRxDesc, prometheus.CounterValue, float64(peer.RxBytes), labels...)
		ch <- prometheus.MustNewConstMetric(PeerTxDesc, prometheus.CounterValue, float64(peer.TxBytes), labels...)
	}

}

func TailscaleGetStatus(ctx context.Context) (*TailscaleStatus, error) {
	stdout := bytes.NewBuffer(nil)
	stderr := bytes.NewBuffer(nil)
	cmd := exec.CommandContext(ctx, "tailscale", "status", "-json")
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error on headscale nodes list: %w. stderr: %s", err, stderr.String())
	}
	status := TailscaleStatus{}
	if err := json.Unmarshal(stdout.Bytes(), &status); err != nil {
		return nil, fmt.Errorf("error on unmarshal: %w. stdout: %s", err, stdout.String())
	}
	return &status, nil
}

func getListenAddr() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	status, err := TailscaleGetStatus(ctx)
	if err != nil {
		return "", err
	}

	ips := status.Self.TailscaleIPs
	if len(ips) < 1 {
		return "", fmt.Errorf("no ips found")
	}

	return ips[0], nil
}

func main() {
	ip, err := getListenAddr()
	if err != nil {
		panic(err)
	}
	listen := ip + ":9995"
	go func() {
		errors := 0
		for {
			newIp, err := getListenAddr()
			if err != nil {
				errors++
				if errors > 20 {
					panic(fmt.Errorf("on update ip: " + err.Error()))
				}
				continue
			}
			if newIp != ip {
				log.Fatalf("found new ip. was: %s, now: %s", ip, newIp)
			}
			time.Sleep(time.Second * 20)
		}
	}()
	prometheus.MustRegister(&Collector{})

	http.Handle("/metrics", promhttp.Handler())
	log.Println("start application! " + listen)
	log.Fatal(http.ListenAndServe(listen, nil))
}
