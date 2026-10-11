package shaper

import (
	"testing"
	"time"
)

func TestEstimatorWindow(t *testing.T) {
	var e Estimator
	now := time.Now()
	v, ok := e.Update(now, map[string]float64{"a": 160, "b": 180, "c": 900, "d": 170, "e": 165}, 42)
	if !ok || v != 160 {
		t.Fatal(v, ok)
	}
	v, ok = e.Update(now.Add(61*time.Second), nil, 42)
	if ok || v != 42 {
		t.Fatal(v, ok)
	}
}
