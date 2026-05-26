package crypto

import "errors"

// pkcs7Pad 使用 PKCS#7 填充方案对数据进行填充，使其长度成为 blockSize 的倍数。
func pkcs7Pad(data []byte, blockSize int) []byte {
	if blockSize <= 0 {
		return append([]byte(nil), data...)
	}
	pad := blockSize - len(data)%blockSize
	if pad == 0 {
		pad = blockSize
	}
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// pkcs7Unpad 从数据中移除 PKCS#7 填充，返回原始数据。如果填充无效，则返回错误。
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padding length")
	}
	pad := int(data[len(data)-1])
	if pad < 1 || pad > blockSize || pad > len(data) {
		return nil, errors.New("invalid padding value")
	}
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, errors.New("invalid padding content")
		}
	}
	return append([]byte(nil), data[:len(data)-pad]...), nil
}
