package sdk

import "testing"

// cloneTargetResult 必须深拷贝嵌套的切片与 map：异步 Writer 序列化快照期间，
// 调用方修改自己持有的返回结果不得影响快照（否则并发访问会触发数据竞争/脏数据）。
func TestCloneTargetResultDeepCopiesNestedFields(t *testing.T) {
	verified := true
	confidence := 0.9
	orig := &TargetResult{
		URL: "http://a",
		Matches: []FingerMatch{{
			Info: FingerInfo{ID: "a", Tags: []string{"tag"}, References: []string{"ref"},
				Verified: &verified, Confidence: &confidence,
				Product: &ProductInfo{ID: "p", Tags: []string{"pt"}, CPE: []string{"cpe:2.3:a:v:p:*:*:*:*:*:*:*:*"}}},
			ProductVersions: []string{"1.0"},
			MatchedRules:    []SubRuleMatch{{Key: "r0", Outputs: map[string]string{"k": "v"}, Evidence: []MatchEvidence{{}}}},
		}},
		Products:  []ProductMatch{{ProductInfo: ProductInfo{ID: "p", Tags: []string{"pt"}}, Versions: []string{"1.0"}, RuleIDs: []string{"a"}}},
		TechStack: &TechStack{CMS: []string{"WordPress"}, Databases: []string{"MySQL"}},
		Certs:     []CertInfo{{Subject: CertName{Organization: []string{"org"}}, DNSNames: []string{"a.com"}}},
	}
	clone := cloneTargetResult(orig)

	// 修改原始结果的全部嵌套字段。
	orig.Matches[0].MatchedRules[0].Outputs["k"] = "changed"
	orig.Matches[0].ProductVersions[0] = "changed"
	orig.Matches[0].Info.Tags[0] = "changed"
	orig.Matches[0].Info.References[0] = "changed"
	orig.Matches[0].Info.Product.Tags[0] = "changed"
	*orig.Matches[0].Info.Verified = false
	*orig.Matches[0].Info.Confidence = 0.1
	orig.Products[0].Versions[0] = "changed"
	orig.Products[0].RuleIDs[0] = "changed"
	orig.TechStack.CMS[0] = "changed"
	orig.TechStack.Databases[0] = "changed"
	orig.Certs[0].Subject.Organization[0] = "changed"
	orig.Certs[0].DNSNames[0] = "changed"

	checks := []struct {
		name string
		got  string
		want string
	}{
		{"MatchedRules.Outputs", clone.Matches[0].MatchedRules[0].Outputs["k"], "v"},
		{"ProductVersions", clone.Matches[0].ProductVersions[0], "1.0"},
		{"Info.Tags", clone.Matches[0].Info.Tags[0], "tag"},
		{"Info.References", clone.Matches[0].Info.References[0], "ref"},
		{"Info.Product.Tags", clone.Matches[0].Info.Product.Tags[0], "pt"},
		{"Products.Versions", clone.Products[0].Versions[0], "1.0"},
		{"Products.RuleIDs", clone.Products[0].RuleIDs[0], "a"},
		{"TechStack.CMS", clone.TechStack.CMS[0], "WordPress"},
		{"TechStack.Databases", clone.TechStack.Databases[0], "MySQL"},
		{"Certs.Subject.Organization", clone.Certs[0].Subject.Organization[0], "org"},
		{"Certs.DNSNames", clone.Certs[0].DNSNames[0], "a.com"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s 被原始结果的修改污染: got %q want %q", c.name, c.got, c.want)
		}
	}
	if *clone.Matches[0].Info.Verified != true || *clone.Matches[0].Info.Confidence != 0.9 {
		t.Error("Info 指针字段未深拷贝")
	}
	if len(clone.Matches[0].MatchedRules[0].Evidence) != 1 {
		t.Error("Evidence 未克隆")
	}
}
