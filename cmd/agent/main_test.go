package main

import (
	"reflect"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	got := splitCSV("br0, br-dev,,")
	want := []string{"br0", "br-dev"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCSV() = %#v, want %#v", got, want)
	}
}
