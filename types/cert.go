package types

// CertName 标准化名称结构（CN/O/OU/C/ST/L/Street/PostalCode/SerialNumber 等）
type CertName struct {
	CommonName         string   `json:"common_name,omitempty"`         // 主体通用名（CN）
	Organization       []string `json:"organization,omitempty"`        // 组织名称（O）
	OrganizationalUnit []string `json:"organizational_unit,omitempty"` // 组织单位（OU）
	Country            []string `json:"country,omitempty"`             // 国家代码（C）
	Province           []string `json:"province,omitempty"`            // 省/州（ST）
	Locality           []string `json:"locality,omitempty"`            // 城市/地区（L）
	StreetAddress      []string `json:"street_address,omitempty"`      // 街道地址
	PostalCode         []string `json:"postal_code,omitempty"`         // 邮政编码
	SerialNumber       string   `json:"serial_number_dn,omitempty"`    // DN 中的序列号
}

// CertInfo 证书信息（用于 JSON 与输出层传递）
type CertInfo struct {
	Subject               CertName `json:"subject"`                           // 证书主体
	Issuer                CertName `json:"issuer"`                            // 颁发者
	NotBefore             string   `json:"not_before"`                        // 生效时间（UTC）
	NotAfter              string   `json:"not_after"`                         // 到期时间（UTC）
	Valid                 bool     `json:"valid"`                             // 当前是否有效（UTC）
	SerialNumber          string   `json:"serial_number"`                     // 证书序列号
	PublicKeyAlgorithm    string   `json:"public_key_algorithm"`              // 公钥算法
	PublicKey             string   `json:"public_key"`                        // 公钥指纹（SubjectPublicKeyInfo 的 SHA1 十六进制）
	SignatureAlgorithm    string   `json:"signature_algorithm"`               // 签名算法
	Version               int      `json:"version"`                           // 证书版本
	OCSPServer            []string `json:"ocsp_server,omitempty"`             // OCSP 服务地址
	DNSNames              []string `json:"dns_names,omitempty"`               // DNS 名称（SAN）
	EmailAddresses        []string `json:"email_addresses,omitempty"`         // 邮件地址（SAN）
	IPAddresses           []string `json:"ip_addresses,omitempty"`            // IP 地址（SAN）
	URIs                  []string `json:"uris,omitempty"`                    // URI（SAN）
	CRLDistributionPoints []string `json:"crl_distribution_points,omitempty"` // CRL 分发点
	IssuingCertificateURL []string `json:"issuing_certificate_url,omitempty"` // 中间/根证书下载地址
}
