package client

type Meta map[string]any

// Get ...
func (m Meta) Get(key string) (v any, ok bool) {
	v, ok = m[key]
	return
}

func (m Meta) GetInt(key string) int {
	if v, ok := m[key]; ok {
		switch z := v.(type) {
		case float64:
			return int(z)
		case int:
			return z
		}
	}
	return 0
}

func (m Meta) GetStr(key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
