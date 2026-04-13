package monitor

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang bpf ../../ebpf/execve.c

type Event struct {
	PID  uint32
	Comm [16]byte
}

type KernelAlert struct {
	PID     uint32
	Command string
}

var Alerts = make(chan KernelAlert, 100)

func isContainerProcess(pid uint32) bool {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return false
	}
	content := string(data)
	return strings.Contains(content, "docker") || strings.Contains(content, "containerd")
}

func StartEBPF() {
	var objs bpfObjects
	loadBpfObjects(&objs, nil)
	defer objs.Close()

	kp, _ := link.Kprobe("sys_execve", objs.BpfProg, nil)
	defer kp.Close()

	rd, _ := ringbuf.NewReader(objs.Events)
	defer rd.Close()

	for {
		record, err := rd.Read()
		if err != nil {
			continue
		}

		var event Event
		binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event)

		if isContainerProcess(event.PID) {
			comm := string(bytes.TrimRight(event.Comm[:], "\x00"))

			if comm != "containerd-shim" && comm != "containerd" && !strings.HasPrefix(comm, "runc") && comm != "dockerd" && comm != "bash" && comm != "sh" {
				Alerts <- KernelAlert{PID: event.PID, Command: comm}
			}
		}
	}
}
