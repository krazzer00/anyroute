package engine

import (
	"path/filepath"

	"github.com/sagernet/sing-box/common/trafficcontrol"
)

// ConnInfo — соединение, прошедшее через sing-box.
type ConnInfo struct {
	ID       string
	Process  string
	Path     string
	PID      uint32
	Network  string
	Dest     string
	Domain   string
	Outbound string
	Rule     string
	Up, Down int64
	Start    int64 // unix ms
	Closed   bool
}

// Connections — активные и недавно закрытые соединения.
func (e *Engine) Connections() []ConnInfo {
	e.mu.Lock()
	tm := e.traffic
	e.mu.Unlock()
	if tm == nil {
		return nil
	}
	var out []ConnInfo
	add := func(m *trafficcontrol.TrackerMetadata, closed bool) {
		ci := ConnInfo{
			ID:       m.ID.String(),
			Network:  m.Metadata.Network,
			Dest:     m.Metadata.Destination.String(),
			Domain:   m.Metadata.Domain,
			Outbound: m.Outbound,
			Up:       m.Upload.Load(),
			Down:     m.Download.Load(),
			Start:    m.CreatedAt.UnixMilli(),
			Closed:   closed,
		}
		if m.Metadata.OriginDestination.IsValid() {
			ci.Dest = m.Metadata.OriginDestination.String()
		}
		if m.Rule != nil {
			ci.Rule = m.Rule.String()
		}
		if p := m.Metadata.ProcessInfo; p != nil {
			ci.PID = p.ProcessID
			ci.Path = p.ProcessPath
			ci.Process = filepath.Base(p.ProcessPath)
		}
		out = append(out, ci)
	}
	for _, m := range tm.Connections() {
		add(m, false)
	}
	for _, m := range tm.ClosedConnections() {
		add(m, true)
	}
	return out
}
