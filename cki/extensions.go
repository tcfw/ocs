package cki

//ExtensionType extension type reference
type ExtensionType uint16

//Extension certificate extensions
type Extension struct {
	Type ExtensionType `msgpack:"t"`
	Data []byte        `msgpack:"d"`
}

const (
	UnknownExtensionType ExtensionType = iota
	AdditionalSubject
	Serial
)

func (et ExtensionType) String() string {
	switch et {
	case AdditionalSubject:
		return "additional subject"
	case Serial:
		return "serial"
	default:
		return "unknown"
	}
}
