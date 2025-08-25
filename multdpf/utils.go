package multdpf

func BytesToMB(bytes uint64) float64 {
  return float64(bytes)/(1024*1024)
}

func BytesToKB(bytes uint64) float64 {
  return float64(bytes)/1024
}

func DPFSizeBytes(key DPFkey) uint64 {
  return uint64(len(key))
}

func DPFSizeMB(key DPFkey) float64 {
  return BytesToMB(DPFSizeBytes(key))
}

func DPFSizeKB(key DPFkey) float64 {
  return BytesToKB(DPFSizeBytes(key))
}
