package shaper

import (
	"math"
	"sort"
	"time"
)

type observation struct {
	at time.Time
	ms float64
	id string
}
type Estimator struct {
	window      []observation
	value       float64
	initialized bool
}

// Minimum observed SRTT per connection in a rolling minute suppresses queuing;
// the 20th percentile across connections resists a few unusually slow clients.
// Using SRTT windows avoids TCP_INFO min_rtt's connection-lifetime stale minima.
func (e *Estimator) Update(now time.Time, samples map[string]float64, fallback float64) (float64, bool) {
	for id, ms := range samples {
		if ms > 0 && !math.IsNaN(ms) && !math.IsInf(ms, 0) {
			e.window = append(e.window, observation{now, ms, id})
		}
	}
	live := e.window[:0]
	mins := map[string]float64{}
	for _, s := range e.window {
		if now.Sub(s.at) <= 60*time.Second {
			live = append(live, s)
			v, ok := mins[s.id]
			if !ok || s.ms < v {
				mins[s.id] = s.ms
			}
		}
	}
	e.window = live
	if len(mins) == 0 {
		e.initialized = false
		e.value = fallback
		return fallback, false
	}
	a := make([]float64, 0, len(mins))
	for _, v := range mins {
		a = append(a, v)
	}
	sort.Float64s(a)
	target := a[int(float64(len(a)-1)*.2)]
	if !e.initialized {
		e.value = target
		e.initialized = true
	} else {
		e.value = .8*e.value + .2*target
	}
	return e.value, true
}
