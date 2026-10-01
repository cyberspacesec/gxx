/*
  - Package fingerYaml
    @Author: zhizhuo
    @IDE：GoLand
    @File: cert.go
    @Date: 2025/9/1 下午4:00*
*/
package finger

import (
	"crypto/sha1"
	"encoding/hex"
	"github.com/cyberspacesec/gxx/v2/types"
	"net/http"
	"strings"
	"time"
)

// GetCertInfos 返回完整证书信息数组，用于结构化输出
func GetCertInfos(resp *http.Response) []*types.CertInfo {
	if resp == nil || resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	results := make([]*types.CertInfo, 0, len(resp.TLS.PeerCertificates))
	for _, c := range resp.TLS.PeerCertificates {
		if c == nil {
			continue
		}
		info := &types.CertInfo{
			Subject: types.CertName{
				CommonName:         c.Subject.CommonName,
				Organization:       append([]string{}, c.Subject.Organization...),
				OrganizationalUnit: append([]string{}, c.Subject.OrganizationalUnit...),
				Country:            append([]string{}, c.Subject.Country...),
				Province:           append([]string{}, c.Subject.Province...),
				Locality:           append([]string{}, c.Subject.Locality...),
				StreetAddress:      append([]string{}, c.Subject.StreetAddress...),
				PostalCode:         append([]string{}, c.Subject.PostalCode...),
				SerialNumber:       c.Subject.SerialNumber,
			},
			Issuer: types.CertName{
				CommonName:         c.Issuer.CommonName,
				Organization:       append([]string{}, c.Issuer.Organization...),
				OrganizationalUnit: append([]string{}, c.Issuer.OrganizationalUnit...),
				Country:            append([]string{}, c.Issuer.Country...),
				Province:           append([]string{}, c.Issuer.Province...),
				Locality:           append([]string{}, c.Issuer.Locality...),
				StreetAddress:      append([]string{}, c.Issuer.StreetAddress...),
				PostalCode:         append([]string{}, c.Issuer.PostalCode...),
				SerialNumber:       c.Issuer.SerialNumber,
			},
			NotBefore:             c.NotBefore.UTC().Format("2006-01-02 15:04:05"),
			NotAfter:              c.NotAfter.UTC().Format("2006-01-02 15:04:05"),
			SerialNumber:          c.SerialNumber.String(),
			PublicKeyAlgorithm:    c.PublicKeyAlgorithm.String(),
			SignatureAlgorithm:    c.SignatureAlgorithm.String(),
			Version:               c.Version,
			OCSPServer:            append([]string{}, c.OCSPServer...),
			DNSNames:              append([]string{}, c.DNSNames...),
			EmailAddresses:        append([]string{}, c.EmailAddresses...),
			CRLDistributionPoints: append([]string{}, c.CRLDistributionPoints...),
			IssuingCertificateURL: append([]string{}, c.IssuingCertificateURL...),
		}
		// 有效性
		now := time.Now().UTC()
		info.Valid = !(now.Before(c.NotBefore.UTC()) || now.After(c.NotAfter.UTC()))
		if len(c.IPAddresses) > 0 {
			ips := make([]string, 0, len(c.IPAddresses))
			for _, ip := range c.IPAddresses {
				ips = append(ips, ip.String())
			}
			info.IPAddresses = ips
		}
		if len(c.URIs) > 0 {
			uris := make([]string, 0, len(c.URIs))
			for _, u := range c.URIs {
				if u != nil {
					uris = append(uris, u.String())
				}
			}
			info.URIs = uris
		}
		if len(c.RawSubjectPublicKeyInfo) > 0 {
			sum := sha1.Sum(c.RawSubjectPublicKeyInfo)
			info.PublicKey = strings.ToUpper(hex.EncodeToString(sum[:]))
		}
		results = append(results, info)
	}
	return results
}
