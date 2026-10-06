package main

import (
	"golang.org/x/sys/windows"

	"github.com/krazzer00/anyroute/internal/service"
)

// setServiceSDDL выставляет права на объект службы.
func setServiceSDDL() error {
	sd, err := windows.SecurityDescriptorFromString(serviceSDDL)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(scm)
	name, _ := windows.UTF16PtrFromString(service.Name)
	h, err := windows.OpenService(scm, name, windows.READ_CONTROL|windows.WRITE_DAC)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(h)
	return windows.SetSecurityInfo(h, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}
