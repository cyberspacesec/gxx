package cel

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/cyberspacesec/gxx/v2/utils/proto"
	"github.com/dlclark/regexp2"
)

func TestRegexRuneCachePreservesMatchingSemantics(t *testing.T) {
	patterns := []string{`marker`, `(?<=前缀)marker`, `(?i)MARKER`, `(?<m>marker)`, `(mark)\1`, `^.*marker`, `[\u4e00-\u9fff]+`, `\uFFFD`, `missing`}
	bodies := []string{"marker", "前缀marker后缀", "MARKER", "markmark", "\xffmarker\xfe", "line\nmarker", strings.Repeat("x", 1024) + "前缀marker后缀"}
	ctx := WithResponseCache(context.Background())
	for _, body := range bodies {
		data := []byte(body)
		for _, pattern := range patterns {
			re, err := getCachedRegexp2(pattern, 0)
			if err != nil {
				t.Fatal(err)
			}
			want, wantErr := re.MatchString(body)
			for _, details := range []bool{false, true} {
				lib := NewCustomLib()
				lib.SetContext(ctx)
				lib.SetEvidenceEnabled(details)
				value, err := lib.Evaluate(strconv.Quote(pattern)+".bmatches(response.body)", map[string]any{"response": &proto.Response{Body: data}})
				if (err != nil) != (wantErr != nil) || err == nil && value.Value() != want {
					t.Fatalf("正则语义改变: pattern=%q body=%q got=%v err=%v want=%v err=%v", pattern, body, value, err, want, wantErr)
				}
			}
		}
	}
}

func TestRegexRuneCacheSharesBudgetAndConcurrentBuffer(t *testing.T) {
	ctx := WithResponseCache(context.Background())
	data := []byte(strings.Repeat("前缀marker", 10000))
	want := regexResponseRunes(ctx, data)
	var group sync.WaitGroup
	for index := 0; index < 16; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got := regexResponseRunes(ctx, data)
			if &got[0] != &want[0] {
				t.Error("同一只读响应没有共用字符缓冲")
			}
		}()
	}
	group.Wait()
	for index := 0; index < 24; index++ {
		value := []byte(strings.Repeat("x", 128<<10))
		regexResponseRunes(ctx, value)
		lowerResponse(ctx, value)
	}
	cache := ctx.Value(responseCacheKey{}).(*responseCache)
	if cache.bytes > responseCacheBudget {
		t.Fatalf("响应归一化缓存超出共享预算: %d", cache.bytes)
	}
}

func TestRegexCaptureRuneCachePreservesGroups(t *testing.T) {
	for _, body := range []string{"前缀version/1.2.3", "\xffversion/1.2.3", strings.Repeat("x", 1024) + "version/1.2.3", "not a version"} {
		pattern := `version/(?<version>[0-9.]+)(?<optional>-extra)?`
		re, err := getCachedRegexp2(pattern, regexp2.RE2)
		if err != nil {
			t.Fatal(err)
		}
		want := map[string]string{}
		if match, _ := re.FindStringMatch(body); match != nil {
			for index, group := range match.Groups() {
				if index != 0 {
					want[group.Name] = group.String()
				}
			}
		}
		lib := NewCustomLib()
		lib.SetContext(WithResponseCache(context.Background()))
		value, err := lib.Evaluate(strconv.Quote(pattern)+".bsubmatch(response.body)", map[string]any{"response": &proto.Response{Body: []byte(body)}})
		if err != nil {
			t.Fatal(err)
		}
		got, err := value.ConvertToNative(reflect.TypeOf(want))
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("命名分组语义改变: got=%v want=%v error=%v", got, want, err)
		}
	}
}
