package cki

//ExtensionType extension type reference
type ExtensionType uint16

//Extension certificate extensions
type Extension struct {
	Type ExtensionType `msgpack:"t"`
	Data []byte        `msgpack:"d"`
}
