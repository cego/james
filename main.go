package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"log/syslog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	appName = "james"
)

var (
	fingerprint string
	home        string
	key         string
	keytype     string
	uid         string
	username    string

	hostname string
	port     uint16

	useSyslog     = true
	urls          []string
	guessRemoteIP bool
	dumpPath      string

	rootCmd = &cobra.Command{
		Use:    appName,
		PreRun: prerun,
		Short:  "A helper for OpenSSH's AuthorizedKeysCommand",
		Run:    root,
	}

	dumpWriter io.Writer
)

type keyResponse struct {
	URL     *url.URL
	Payload []byte
	Error   error
}

// fqdn will try to guess the FQDN based on the same technique used by
// hostname -f.
func fqdn() string {
	// Use Go's standard library hysteresis to determine the hostname.
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}

	// Get an IP for the hostname returned from /etc/hostname.
	ips, err := net.LookupIP(hostname)
	if err != nil {
		return hostname
	}

	for _, ip := range ips {
		// We only do the lookup on 127.0.0.0/8 IP adresses to avoid
		// depending on a resolver that might resolve one of our
		// networked IP's to something generic and non-usable for
		// our use-case.
		if ipv4 := ip.To4(); ipv4 != nil && ip.IsLoopback() {
			ip, err := ipv4.MarshalText()
			if err != nil {
				return hostname
			}

			hosts, err := net.LookupAddr(string(ip))
			if err != nil || len(hosts) == 0 {
				return hostname
			}

			return strings.TrimSuffix(hosts[0], ".")
		}
	}

	return hostname
}

func init() {
	helpFlag := false

	// Trick to use '-h' for something else than help. This works by
	// replacing the default help flag with one with no shorthand set.
	rootCmd.PersistentFlags().BoolVarP(&helpFlag, "help", "", false, "Help for "+os.Args[0])

	// Tokens supported by OpenSSH server.
	rootCmd.PersistentFlags().StringVarP(&fingerprint, "fingerprint", "f", "", "The fingerprint of the key or certificate (%f)")
	rootCmd.PersistentFlags().StringVarP(&home, "home", "h", "", "The home directory of the user (%h)")
	rootCmd.PersistentFlags().StringVarP(&key, "key", "k", "", "The base64-encoded key or certificate for authentication (%k)")
	rootCmd.PersistentFlags().StringVarP(&keytype, "keytype", "t", "", "The key or certificate type (%t)")
	rootCmd.PersistentFlags().StringVarP(&uid, "uid", "U", "", "The numeric user ID of the target user (%U)")
	rootCmd.PersistentFlags().StringVarP(&username, "username", "u", "", "The username (%u)")

	rootCmd.PersistentFlags().StringVarP(&hostname, "hostname", "", fqdn(), "The local hostname")
	rootCmd.PersistentFlags().Uint16VarP(&port, "port", "", 22, "The port SSH is listening to")

	rootCmd.PersistentFlags().StringSliceVarP(&urls, "url", "", []string{}, "URL to use - may be specified multiple times")
	rootCmd.PersistentFlags().BoolVarP(&guessRemoteIP, "guess-remote-ip", "", true, "Try to guess remote IP. Requires root")
	rootCmd.PersistentFlags().BoolVarP(&useSyslog, "use-syslog", "", useSyslog, "Log to syslog")
	rootCmd.PersistentFlags().StringVarP(&dumpPath, "dump", "", "", "Dump HTTP request/response to path")
}

func prerun(_ *cobra.Command, _ []string) {
	if useSyslog {
		writer, err := syslog.New(syslog.LOG_ERR|syslog.LOG_AUTH, appName)
		if err != nil {
			log.Fatalf("Error connecting to syslog: %s", err.Error())
		}

		log.SetOutput(writer)
	}

	if dumpPath != "" {
		w, err := os.OpenFile(dumpPath, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("Error opening %s: %s", dumpPath, err.Error())
		}
		dumpWriter = w
	}
}

// httpDo will try a http request multiple times if the server responds
// with an internal error.
func httpDo(req *http.Request) (*http.Response, error) {
	backOff := time.Millisecond * 250

	if req.Body != nil {
		panic("httpDo() only supports requests without body")
	}

	if dumpWriter != nil {
		d, _ := httputil.DumpRequestOut(req, false)
		_, _ = dumpWriter.Write(d)
	}

	for retryCount := 0; retryCount < 5; retryCount++ {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}

		if dumpWriter != nil {
			d, _ := httputil.DumpResponse(resp, false)
			_, _ = dumpWriter.Write(d)
		}

		if resp.StatusCode < 500 {
			return resp, err
		}

		err = resp.Body.Close()
		if err != nil {
			return nil, err
		}

		time.Sleep(backOff * time.Duration(retryCount))
	}

	return nil, fmt.Errorf("giving up on %s", req.URL)
}
func doKeyRequest(url *url.URL) keyResponse {
	keyResult := keyResponse{URL: url}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", url.String(), nil)
	if err != nil {
		keyResult.Error = fmt.Errorf("HTTP Error %s: %w", url, err)
		return keyResult
	}

	resp, err := httpDo(req)
	if err != nil {
		keyResult.Error = fmt.Errorf("HTTP Error %s: %w", url, err)
		return keyResult
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		keyResult.Error = fmt.Errorf("HTTP unexpected status code %s: %d", url, resp.StatusCode)
		return keyResult
	}

	// lets just say every http request does not produce more then a meg of public key material
	limit := io.LimitReader(resp.Body, 1024*1024)

	body, err := ioutil.ReadAll(limit)
	if err != nil {
		keyResult.Error = fmt.Errorf("HTTP Error %s: %w", url, err)
		return keyResult
	}

	keyResult.Payload = body
	return keyResult
}

func httpWorker(urls chan *url.URL, results chan keyResponse) {
	for url := range urls {
		keyResult := doKeyRequest(url)
		results <- keyResult
	}
}

func root(_ *cobra.Command, _ []string) {
	if len(urls) == 0 {
		urls = []string{fmt.Sprintf("https://github.com/%s.keys", username)}
	}

	q := url.Values{}

	if guessRemoteIP {
		sockets, err := getOpenSockets(os.Getppid())
		if err != nil {
			log.Fatalf("Error: %s", err.Error())
		}

		connections, err := getTCP4Connections(sockets)
		if err != nil {
			log.Fatalf("Error: %s", err.Error())
		}

		if len(connections) != 1 {
			log.Fatalf("Unable to guess remote IP. %d results returned", len(connections))
		}

		q.Add("remote_ip", connections[0].String())
	}

	q.Add("service_hostname", hostname)

	if port != 0 && port != 22 {
		q.Add("service_port", strconv.Itoa(int(port)))
	}

	if fingerprint != "" {
		q.Add("fingerprint", fingerprint)
	}

	if home != "" {
		q.Add("home", home)
	}

	if key != "" {
		q.Add("key", key)
	}

	if keytype != "" {
		q.Add("keytype", keytype)
	}

	if uid != "" {
		q.Add("uid", uid)
	}

	if username != "" {
		q.Add("username", username)
	}

	jobs := make(chan *url.URL, len(urls))
	results := make(chan keyResponse, len(urls))

	// startup some httpWorker's
	for w := 1; w <= 5; w++ {
		go httpWorker(jobs, results)
	}

	for _, u := range urls {
		reqURL, err := url.Parse(u)
		if err != nil {
			log.Fatalf("unable to parse url %s: %s", u, err)
		}

		reqURL.RawQuery = q.Encode()

		jobs <- reqURL
	}

	// output results one at a time
	counter := 0
	for k := range results {
		if k.Error != nil {
			fmt.Fprintf(os.Stdout, "# %s\n## Error: %s\n\n", k.URL, k.Error)
			log.Printf("key result error: %s", k.Error)

		} else {
			fmt.Fprintf(os.Stdout, "# %s\n%s\n", k.URL, k.Payload)
		}

		counter++
		if counter == len(urls) {
			os.Exit(0)
		}
	}
}

func getOpenSockets(pid int) ([]int, error) {
	t := regexp.MustCompile(`socket:\[([0-9]*)\]`)

	fdPath := fmt.Sprintf("/proc/%d/fd", pid)

	f, err := os.Open(fdPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	names, err := f.Readdirnames(-1)
	if err != nil {
		return nil, err
	}

	var sockets []int

	for _, name := range names {
		resolved, err := os.Readlink(fdPath + "/" + name)
		if err != nil {
			continue
		}

		// Check if it's a socket.
		matches := t.FindSubmatch([]byte(resolved))

		if len(matches) > 1 {
			i, err := strconv.Atoi(string(matches[1]))
			if err != nil {
				continue
			}

			sockets = append(sockets, i)
		}
	}

	return sockets, nil
}

func hexToIP(hex string) (*net.IPAddr, error) {
	dec, err := strconv.ParseInt(hex, 16, 64)
	if err != nil {
		return nil, err
	}

	// Convert to network order and construct net.IP.
	ip := net.IP{byte(dec & 0xff), byte(dec >> 8 & 0xff), byte(dec >> 16 & 0xff), byte(dec >> 24 & 0xff)}

	return &net.IPAddr{IP: ip}, nil
}

func getTCP4Connections(sockets []int) ([]net.Addr, error) {
	t := regexp.MustCompile(`\w[0-9]*\:\ [0-9A-F]{8}:[0-9A-F]{4} ([0-9A-F]{8}):[0-9A-F]{4} [0-9A-F]{2} [0-9A-F]{8}:[0-9A-F]{8} [0-9A-F]{2}:[0-9A-F]{8} [0-9A-F]{8} *[0-9]* *[0-9] ([0-9]*)`)

	f, err := os.Open("/proc/net/tcp")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	// Throw away the first line containing headers.
	scanner.Scan()

	var connections []net.Addr

	for scanner.Scan() {
		line := scanner.Bytes()
		matches := t.FindSubmatch(line)

		if len(matches) > 2 {
			inode, err := strconv.Atoi(string(matches[2]))
			if err != nil {
				return nil, err
			}

			for _, s := range sockets {
				if s == inode {
					ip, err := hexToIP(string(matches[1]))
					if err != nil {
						return nil, err
					}

					connections = append(connections, ip)
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return connections, nil
}

func main() {
	err := rootCmd.Execute()
	if err != nil {
		log.Fatalf("Error: %s", err.Error())
	}
}
