// Package anyconnect — нативный клиент Cisco AnyConnect (SSL/TLS + DTLS).
//
// Основа — форк github.com/tlslink/sslcon (MIT, © 2022 TLSLink), прошедший
// через DualVPN: глобальное состояние убрано целиком, протокольные правки под
// живую Cisco ASA сохранены (тело <device-id>, форма ответа на 2FA-challenge,
// дословный <opaque>, подстановка param1 в сообщения, редиректы). Пакет не
// знает про TUN и маршруты: наружу отдаётся поток IP-пакетов (Tunnel).
//
// API синхронный: InitAuth → PasswordAuth → (Submit2FA)* → Connect. Ожиданием
// кода второго фактора управляет вызывающий (ядро службы), а не горутина
// внутри клиента.
package anyconnect

import "encoding/xml"

// DTD — XML aggregate-auth (draft-mavrogiannopoulos-openconnect-03, прил. C.1).
// Перенесено из sslcon/proto.
type DTD struct {
	XMLName              xml.Name       `xml:"config-auth"`
	Client               string         `xml:"client,attr"`
	Type                 string         `xml:"type,attr"`
	AggregateAuthVersion string         `xml:"aggregate-auth-version,attr"`
	Version              string         `xml:"version"`
	GroupAccess          string         `xml:"group-access"`
	GroupSelect          string         `xml:"group-select"`
	SessionToken         string         `xml:"session-token"`
	Auth                 dtdAuth        `xml:"auth"`
	Opaque               dtdOpaque      `xml:"opaque"`
	Config               dtdConfig      `xml:"config"`
	MacAddressList       dtdMacAddrList `xml:"mac-address-list"`
}

type dtdAuth struct {
	ID       string       `xml:"id,attr"`
	Username string       `xml:"username"`
	Password string       `xml:"password"`
	Message  string       `xml:"message"`
	Banner   string       `xml:"banner"`
	Error    dtdAuthError `xml:"error"`
	Form     dtdForm      `xml:"form"`
}

type dtdForm struct {
	Action string   `xml:"action,attr"`
	Groups []string `xml:"select>option"`
}

type dtdAuthError struct {
	ID     string `xml:"id,attr"`
	Param1 string `xml:"param1,attr"`
	Param2 string `xml:"param2,attr"`
	Value  string `xml:",chardata"`
}

type dtdOpaque struct {
	TunnelGroup string `xml:"tunnel-group"`
	GroupAlias  string `xml:"group-alias"`
	ConfigHash  string `xml:"config-hash"`
}

type dtdMacAddrList struct {
	MacAddress string `xml:"mac-address"`
}

type dtdConfig struct {
	Opaque struct {
		CustomAttr struct {
			DynamicSplitExcludeDomains string `xml:"dynamic-split-exclude-domains"`
			DynamicSplitIncludeDomains string `xml:"dynamic-split-include-domains"`
		} `xml:"custom-attr"`
	} `xml:"opaque"`
}

// Типы STF-фреймов CSTP (draft-mavrogiannopoulos-openconnect-03, табл. 3).
const (
	pktData       byte = 0x00
	pktDPDReq     byte = 0x03
	pktDPDResp    byte = 0x04
	pktDisconnect byte = 0x05
	pktKeepalive  byte = 0x07
	pktCompressed byte = 0x08
	pktTerminate  byte = 0x09
)

// stfHeaderLen — длина заголовка STF-фрейма (TLS-канал).
const stfHeaderLen = 8

// stfMagic — первые 4 байта заголовка: 'S' 'T' 'F' 0x01.
var stfMagic = [4]byte{0x53, 0x54, 0x46, 0x01}
