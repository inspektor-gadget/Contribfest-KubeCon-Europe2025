package main

import (
	"strings"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

var flagNames = []string{
	"O_CREAT",
	"O_EXCL",
	"O_NOCTTY",
	"O_TRUNC",
	"O_APPEND",
	"O_NONBLOCK",
	"O_DSYNC",
	"O_FASYNC",
	"O_DIRECT",
	"O_LARGEFILE",
	"O_DIRECTORY",
	"O_NOFOLLOW",
	"O_NOATIME",
	"O_CLOEXEC",
}

func decodeFlags(flags int32) []string {
	flagsStr := []string{}

	// We first need to deal with the first 3 bits which indicates access mode.
	switch flags & 0b11 {
	case 0:
		flagsStr = append(flagsStr, "O_RDONLY")
	case 1:
		flagsStr = append(flagsStr, "O_WRONLY")
	case 2:
		flagsStr = append(flagsStr, "O_RDWR")
	}

	// Then, we need to remove the last 6 bits and we can deal with the other
	// flags.
	// Indeed, O_CREAT is defined as 00000100, see:
	// https://github.com/torvalds/linux/blob/9d646009f65d/include/uapi/asm-generic/fcntl.h#L24
	flags >>= 6
	for i, val := range flagNames {
		if (1<<i)&flags != 0 {
			flagsStr = append(flagsStr, val)
		}
	}

	return flagsStr
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	// We named our datasource "open" in the eBPF programs when specifying "open" as the
	// first parameter in     GADGET_TRACER(open, events, event);
	// All events originated from there are then under the "open" datasource.
	ds, err := api.GetDataSource("open")
	if err != nil {
		api.Errorf("failed to get datasource: %s", err)
		return 1
	}

	// We need to read the "flags" field which is published in the "open" datasource
	// and therefore we need access to the field.
	flagsField, err := ds.GetField("flags")
	if err != nil {
		api.Errorf("failed to get field: %s", err)
		return 1
	}

	// We are going to put our decoded flags in a new field called "flags_decoded"
	// which is going to be a string.
	// Since we want it to be in the same datasource "open", lets add it there
	flagsDecodedField, err := ds.AddField("flags_decoded", api.Kind_String)
	if err != nil {
		api.Errorf("failed to add field: %s", err)
		return 1
	}

	// We subscribe to the datasource and we are going to decode the flags
	// and put them in the new field.
	// The callback is going to be called for each event in the datasource.
	ds.Subscribe(func(source api.DataSource, data api.Data) {
		flagsRaw, err := flagsField.Int32(data)
		if err != nil {
			api.Warnf("failed to get flags: %s", err)
			return
		}

		flagsStrArr := decodeFlags(flagsRaw)
		flagsDecodedField.SetString(data, strings.Join(flagsStrArr, " | "))
	}, 0)

	return 0
}

func main() {}
