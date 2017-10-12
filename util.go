package cbmgr

import (
	"strconv"
)

func BoolToInt(b bool) int {
	return map[bool]int{false: 0, true: 1}[b]
}

func BoolToStr(b bool) string {
	return strconv.Itoa(BoolToInt(b))
}

func BoolAsStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func IntToStr(i int) string {
	return strconv.Itoa(i)
}
