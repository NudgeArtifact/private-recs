package multdpf

// BytesToKB converts a byte count to kilobytes.
func BytesToKB(bytes uint64) float64 {
	return float64(bytes) / 1024
}

// DPFSizeBytes returns the serialized size of a DPF key in bytes.
func DPFSizeBytes(key DPFkey) uint64 {
	return uint64(len(key))
}

// DPFSizeKB returns the serialized size of a DPF key in kilobytes.
func DPFSizeKB(key DPFkey) float64 {
	return BytesToKB(DPFSizeBytes(key))
}
