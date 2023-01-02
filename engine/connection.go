package engine

// This a copy of the original bytes.Join with separator removed. https://stackoverflow.com/a/32371421/12932866
func Join(s ...[]byte) []byte {
	n := 0
	for _, v := range s {
		n += len(v)
	}

	b, i := make([]byte, n), 0
	for _, v := range s {
		i += copy(b[i:], v)
	}
	return b
}
func calculateCommandLen(commandMessage *[]byte) []byte {
	commandLength := make([]byte, 2)
	if len(*commandMessage) > 255 {
		commandLength[0] = byte(len(*commandMessage) / 256)
		commandLength[1] = byte(len(*commandMessage) % 256)
	} else {
		commandLength[0] = byte(0)
		commandLength[1] = byte(len(*commandMessage))
	}
	return commandLength
}
