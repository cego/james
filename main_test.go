package main

import (
	"reflect"
	"testing"
)

func Test_hexToIP6(t *testing.T) {
	tests := []struct {
		name    string
		hexStr  string
		want    string
		wantErr bool
	}{
		{name: "Localhost ipv6", hexStr: "0000000000000000FFFF00000100007F", want: "::1", wantErr: false},
		{name: "ipv6", hexStr: "00470626018F10019E444EDD6FB5D22E", want: "2606:4700:110:8f01:dd4e:449e:2ed2:b56f", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToIP6(tt.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("hexToIP6() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.String(), tt.want) {
				t.Errorf("hexToIP6() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_hexToIP(t *testing.T) {
	tests := []struct {
		name    string
		hexStr  string
		want    string
		wantErr bool
	}{
		{name: "Localhost ipv4", hexStr: "00000000", want: "127.0.0.1", wantErr: false},
		{name: "ipv4", hexStr: "057EA8C0", want: "", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := hexToIP(tt.hexStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("hexToIP() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.String(), tt.want) {
				t.Errorf("hexToIP() got = %v, want %v", got, tt.want)
			}
		})
	}
}
