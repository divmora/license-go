package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	license "github.com/divmora/license-go/pkg/license"
)

func runBSLEval(args []string) error {
	fs := flag.NewFlagSet("bsl-eval", flag.ExitOnError)
	releaseDateFlag := fs.String("release-date", "", "Software compilation/release date (YYYY-MM-DD or RFC3339)")
	changeDateFlag := fs.String("change-date", "", "Explicit open-source Change Date override (YYYY-MM-DD or RFC3339)")
	yearsFlag := fs.Int("years", 3, "BSL change period in years (default: 3)")
	changeLicFlag := fs.String("change-license", "Apache-2.0", "Target open-source license upon conversion (default: Apache-2.0)")
	productFlag := fs.String("product", "divmora-product", "Product name")
	envFlag := fs.String("env", "", "Current deployment environment (e.g. production, staging, development)")
	usageFlag := fs.String("usage", "", "Active runtime consumption counts (e.g. 'max_nodes=6,max_runners=15')")
	featuresFlag := fs.String("features", "", "Comma-separated feature flags requested (e.g. 'basic-ingest,metrics')")
	freeLimitsFlag := fs.String("free-limits", "", "Free community quota limits in key=val format (e.g. 'max_nodes=10,max_runners=25')")
	exemptEnvsFlag := fs.String("exempt-envs", "", "Comma-separated non-production exempt environments (default: standard non-prod envs; 'none' to disable)")
	excludedFeatsFlag := fs.String("excluded-features", "", "Features strictly excluded from free tier / requiring commercial license (e.g. 'sso,audit-logs')")
	timeFlag := fs.String("time", "", "Reference evaluation timestamp (default: current time)")
	dryRunFlag := fs.Bool("dry-run", false, "Execution in non-destructive dry-run / simulation mode")
	simFlag := fs.Bool("simulation", false, "Execution in testing / simulation mode")
	jsonOutput := fs.Bool("json", false, "Output evaluation result in JSON format")

	if err := fs.Parse(args); err != nil {
		return err
	}

	var releaseDate time.Time
	if *releaseDateFlag != "" {
		t, err := time.Parse(time.RFC3339, *releaseDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *releaseDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -release-date %q: expected RFC3339 or YYYY-MM-DD", *releaseDateFlag)
			}
		}
		releaseDate = t
	}

	var explicitChangeDate time.Time
	if *changeDateFlag != "" {
		t, err := time.Parse(time.RFC3339, *changeDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *changeDateFlag)
			if err != nil {
				return fmt.Errorf("invalid -change-date %q: expected RFC3339 or YYYY-MM-DD", *changeDateFlag)
			}
		}
		explicitChangeDate = t
	}

	if releaseDate.IsZero() && explicitChangeDate.IsZero() {
		return errors.New("-release-date or -change-date is required for BSL entitlement evaluation")
	}

	policy := license.BSLPolicy{
		ReleaseDate:        releaseDate,
		ExplicitChangeDate: explicitChangeDate,
		ChangePeriodYears:  *yearsFlag,
		ChangeLicense:      *changeLicFlag,
		Product:            *productFlag,
	}

	parseList := func(val string) []string {
		if strings.TrimSpace(val) == "" {
			return nil
		}
		var list []string
		for _, s := range strings.Split(val, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				list = append(list, s)
			}
		}
		return list
	}

	// 1. Non-production exemption grant
	if strings.ToLower(strings.TrimSpace(*exemptEnvsFlag)) != "none" {
		var exemptEnvs []string
		if *exemptEnvsFlag != "" {
			exemptEnvs = parseList(*exemptEnvsFlag)
		}
		policy.AddGrant(license.NewNonProductionGrant("Non-Production Exemption", exemptEnvs...))
	}

	// 2. Free community tier grant
	if strings.TrimSpace(*freeLimitsFlag) != "" {
		limits := make(map[string]int64)
		for _, item := range strings.Split(*freeLimitsFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid free limit in %q: %w", item, err)
				}
				limits[k] = v
			}
		}
		var excludedFeats []string
		if *excludedFeatsFlag != "" {
			excludedFeats = parseList(*excludedFeatsFlag)
		}
		policy.AddGrant(license.NewFreeTierGrant("Community Free Tier", limits, excludedFeats...))
	}

	// 3. Resolve evaluation reference timestamp
	evalTime := time.Now()
	if *timeFlag != "" {
		t, err := time.Parse(time.RFC3339, *timeFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02", *timeFlag)
			if err != nil {
				return fmt.Errorf("invalid -time %q: expected RFC3339 or YYYY-MM-DD", *timeFlag)
			}
		}
		evalTime = t
	}

	// 4. Resolve environment
	env := strings.TrimSpace(*envFlag)
	if env == "" {
		for _, envVar := range []string{"ENV", "ENVIRONMENT", "APP_ENV", "NODE_ENV"} {
			if v := os.Getenv(envVar); v != "" {
				env = v
				break
			}
		}
	}

	// 5. Parse runtime usage metrics
	usage := make(map[string]int64)
	if strings.TrimSpace(*usageFlag) != "" {
		for _, item := range strings.Split(*usageFlag, ",") {
			parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
			if len(parts) == 2 {
				k := strings.TrimSpace(parts[0])
				v, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
				if err != nil {
					return fmt.Errorf("invalid usage value in %q: %w", item, err)
				}
				usage[k] = v
			}
		}
	}

	// 6. Parse features
	features := parseList(*featuresFlag)

	// 7. Evaluate entitlement
	req := license.BSLUsageRequest{
		Environment: env,
		Usage:       usage,
		Features:    features,
		Time:        evalTime,
		DryRun:      *dryRunFlag,
		Simulation:  *simFlag,
	}

	result := policy.EvaluateEntitlement(req)

	if *jsonOutput {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(result); err != nil {
			return err
		}
		if !result.Authorized {
			return fmt.Errorf("commercial license required under BSL 1.1 terms: %s", result.Reason)
		}
		return nil
	}

	// Terminal Formatted Output
	fmt.Println(strings.Repeat("=", 72))
	fmt.Println("                 DIVMORA BSL 1.1 ENTITLEMENT EVALUATION")
	fmt.Println(strings.Repeat("=", 72))

	var decisionLabel string
	if result.GrantType == license.BSLGrantTypeConverted {
		decisionLabel = fmt.Sprintf("OPEN SOURCE [✓ Converted to %s]", result.EffectiveLicense)
	} else if result.Authorized {
		decisionLabel = fmt.Sprintf("AUTHORIZED [✓ Additional Use Grant: %s]", result.MatchingGrant)
	} else {
		decisionLabel = "COMMERCIAL LICENSE REQUIRED [❌ Exceeds Free Tier Bounds]"
	}
	fmt.Printf("%-24s %s\n", "Decision:", decisionLabel)
	fmt.Printf("%-24s %s\n", "Effective License:", result.EffectiveLicense)
	if env != "" {
		fmt.Printf("%-24s %s\n", "Environment:", env)
	}
	if !result.ChangeDate.IsZero() {
		targetLic := policy.ChangeLicense
		if targetLic == "" {
			targetLic = license.DefaultBSLChangeLicense
		}
		if result.DaysUntilConversion > 0 {
			fmt.Printf("%-24s %s (converts to %s in %d days)\n",
				"BSL Change Date:", result.ChangeDate.Format("2006-01-02"), targetLic, result.DaysUntilConversion)
		} else {
			fmt.Printf("%-24s %s (converted to %s)\n",
				"BSL Change Date:", result.ChangeDate.Format("2006-01-02"), targetLic)
		}
	}
	fmt.Printf("%-24s %s\n", "Status Summary:", result.Reason)

	if len(result.Evaluations) > 0 {
		fmt.Println("\nEVALUATED ADDITIONAL USE GRANTS:")
		fmt.Printf("  %-28s %-12s %s\n", "Grant Name", "Status", "Details")
		fmt.Println("  " + strings.Repeat("─", 68))
		for _, ev := range result.Evaluations {
			statusStr := "Matched"
			if !ev.Matched {
				statusStr = "Excluded"
			}
			fmt.Printf("  %-28s %-12s %s\n", ev.GrantName, statusStr, ev.Reason)
		}
	}
	fmt.Println(strings.Repeat("=", 72))

	if !result.Authorized {
		return fmt.Errorf("commercial license required under BSL 1.1 terms: %s", result.Reason)
	}
	return nil
}
