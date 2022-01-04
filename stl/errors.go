package stl

import "io"

type ErrorFrame struct {
	Code ErrorCode
}

type ErrorCode uint8

const (
	ErrorCode_Unknown ErrorCode = iota
	ErrorCode_Internal
	ErrorCode_Unauthorised
	ErrorCode_UnexpectedFrame
	ErrorCode_BadCertificate
	ErrorCode_BadParameters
	ErrorCode_Closed
)

func (ef *ErrorFrame) Error() string {
	switch ef.Code {
	default:
		return "unknown"
	case ErrorCode_Unauthorised:
		return "unauthorised"
	case ErrorCode_UnexpectedFrame:
		return "unexpectedFrame"
	case ErrorCode_BadCertificate:
		return "bad_certificate"
	case ErrorCode_BadParameters:
		return "bad_Parameters"
	case ErrorCode_Closed:
		return "closed"
	}
}

func (ef *ErrorFrame) Unmarshal(d []byte) error {
	ef.Code = ErrorCode(d[0])
	return nil
}

func (ef *ErrorFrame) Marshal() ([]byte, error) {
	return []byte{byte(ef.Code)}, nil
}

func (ef *ErrorFrame) WriteTo(w io.Writer) {
	w.Write([]byte{byte(ef.Code)})
}
