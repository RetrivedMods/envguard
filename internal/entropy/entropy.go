package entropy

import "math"

func Shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := range s {
		counts[s[i]]++
	}
	var h float64
	n := float64(len(s))
	for _, count := range counts {
		if count == 0 {
			continue
		}
		p := float64(count) / n
		h -= p * math.Log2(p)
	}
	return h
}
