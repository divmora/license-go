package resolvers

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// EC2 detection must be stable. A node-locked licence compares the resolved
// fingerprint against the bound one, so a machine that is classified as
// "aws-ec2" on one call and "host" on the next (because IMDS answered slowly)
// fails licence checks at random. To prevent that:
//
//  1. Stable, local DMI signals (sys_vendor, bios_vendor, board_asset_tag,
//     product_uuid) are checked first. They identify every Nitro and Xen EC2
//     instance on Linux without any network call.
//  2. Only when DMI is inconclusive is IMDS probed, with a generous timeout
//     and a retry, instead of a single 100 ms attempt.
//  3. The answer is computed once and cached for the process lifetime.
//     ResetDetectionCache clears it (intended for tests).

const (
	ec2ProbeTimeout  = 1 * time.Second
	ec2ProbeAttempts = 2
)

var (
	// dmiDir is the Linux DMI sysfs directory (/sys/class/dmi/id is a symlink to
	// /sys/devices/virtual/dmi/id). Overridable in tests.
	dmiDir = "/sys/class/dmi/id"

	// ec2ProbeBaseURL is the IMDS endpoint used by the detection probe and by
	// AWSEC2Resolver when no base URL is configured. Overridable in tests.
	ec2ProbeBaseURL = defaultEC2BaseURL

	ec2DetectMu     sync.Mutex
	ec2DetectDone   bool
	ec2DetectResult bool
)

// IsLikelyAWSEC2 reports whether the process runs on an AWS EC2 instance.
// The result is computed once per process and cached, so every caller sees the
// same answer regardless of transient IMDS latency.
func IsLikelyAWSEC2() bool {
	ec2DetectMu.Lock()
	defer ec2DetectMu.Unlock()
	if !ec2DetectDone {
		ec2DetectResult = hasEC2DMISignal() || probeIMDS(ec2ProbeBaseURL)
		ec2DetectDone = true
	}
	return ec2DetectResult
}

// ResetDetectionCache clears the cached EC2 detection result, the cached
// default fingerprint and the cached Kubernetes cluster UIDs so the next call re-detects the environment. It is meant
// for tests that change the simulated environment within one process.
func ResetDetectionCache() {
	ec2DetectMu.Lock()
	ec2DetectDone = false
	ec2DetectResult = false
	ec2DetectMu.Unlock()
	resetDefaultFingerprintCache()
	resetK8sUIDCache()
}

func readDMI(name string) string {
	data, err := os.ReadFile(filepath.Join(dmiDir, name))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// hasEC2DMISignal checks local, network-free DMI markers that AWS sets on EC2.
//   - Nitro instances: sys_vendor / bios_vendor = "Amazon EC2",
//     board_asset_tag = the instance ID ("i-...").
//   - Xen instances: product_uuid / product_serial start with "ec2",
//     bios_version contains "amazon".
func hasEC2DMISignal() bool {
	for _, f := range []string{"sys_vendor", "bios_vendor", "board_vendor", "chassis_vendor"} {
		if strings.EqualFold(readDMI(f), "Amazon EC2") {
			return true
		}
	}
	if tag := readDMI("board_asset_tag"); strings.HasPrefix(tag, "i-") && len(tag) > 2 {
		return true
	}
	for _, f := range []string{"product_uuid", "product_serial"} {
		if strings.HasPrefix(strings.ToLower(readDMI(f)), "ec2") {
			return true
		}
	}
	return strings.Contains(strings.ToLower(readDMI("bios_version")), "amazon")
}

// probeIMDS asks IMDSv2 for a session token, retrying once so a single slow or
// dropped response does not reclassify the machine.
func probeIMDS(baseURL string) bool {
	client := &http.Client{Timeout: ec2ProbeTimeout}
	url := strings.TrimRight(baseURL, "/") + "/latest/api/token"
	for attempt := 0; attempt < ec2ProbeAttempts; attempt++ {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, url, nil)
		if err != nil {
			return false
		}
		req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "10")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
		// A definitive non-OK answer (e.g. 403 when IMDS is disabled, 404 from
		// an unrelated listener) is not a transient failure.
		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return false
		}
	}
	return false
}

// Process-wide cache for the default composite resolver's result.
var (
	defaultFPMu sync.Mutex
	defaultFP   *MachineFingerprint
)

func loadDefaultFingerprint() *MachineFingerprint {
	defaultFPMu.Lock()
	defer defaultFPMu.Unlock()
	return defaultFP.clone()
}

func storeDefaultFingerprint(fp *MachineFingerprint) {
	defaultFPMu.Lock()
	defaultFP = fp.clone()
	defaultFPMu.Unlock()
}

func resetDefaultFingerprintCache() {
	defaultFPMu.Lock()
	defaultFP = nil
	defaultFPMu.Unlock()
}
