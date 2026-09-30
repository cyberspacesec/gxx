package types

// ReverseConfig 反连查询配置。配置按值属于扫描实例，不包含可共享的可变引用。
type ReverseConfig struct {
	CeyeAPIKey string
	CeyeDomain string
	JNDIHost   string
	LDAPPort   string
	APIPort    string
}
