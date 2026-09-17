package main

import (
	"strings"
)

func parseSlice(val string) []string {
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

func parseCustomScope(raw string) map[string][]string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	result := make(map[string][]string)

	var entries []string
	if strings.Contains(raw, ";") {
		entries = strings.Split(raw, ";")
	} else if strings.Count(raw, "=") > 1 && strings.Contains(raw, ",") {
		entries = strings.Split(raw, ",")
	} else {
		entries = []string{raw}
	}

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) != 2 {
			continue
		}
		dim := strings.TrimSpace(parts[0])
		valsPart := strings.TrimSpace(parts[1])
		if dim == "" {
			continue
		}

		valFields := strings.FieldsFunc(valsPart, func(r rune) bool {
			return r == ',' || r == '|'
		})
		for _, v := range valFields {
			v = strings.TrimSpace(v)
			if v != "" {
				result[dim] = append(result[dim], v)
			}
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}

func parseMetadata(raw string) map[string]string {
	meta := make(map[string]string)
	if strings.TrimSpace(raw) == "" {
		return meta
	}
	for _, item := range strings.Split(raw, ",") {
		parts := strings.SplitN(strings.TrimSpace(item), "=", 2)
		if len(parts) == 2 {
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			if k != "" {
				meta[k] = v
			}
		}
	}
	return meta
}
