package casefold

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"unicode"
	"unicode/utf8"
)

// 跳过查表的区间必须确实没有大小写映射；Unicode 表更新后若新增映射，这里会失败。
func TestCaselessRangesHaveNoCaseMapping(t *testing.T) {
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if !caseless(r) {
			continue
		}
		if unicode.ToLower(r) != r || unicode.ToUpper(r) != r || unicode.ToTitle(r) != r {
			t.Fatalf("U+%04X 位于免查表区间却存在大小写映射", r)
		}
	}
}

// 每个码位单独转换的结果都必须与标准库一致。
func TestLowerMatchesStandardLibraryForEveryRune(t *testing.T) {
	var buffer [utf8.UTFMax]byte
	for r := rune(0); r <= unicode.MaxRune; r++ {
		if r >= 0xD800 && r <= 0xDFFF {
			continue
		}
		encoded := buffer[:utf8.EncodeRune(buffer[:], r)]
		if got, want := Lower(encoded), bytes.ToLower(encoded); !bytes.Equal(got, want) {
			t.Fatalf("U+%04X: got=%x want=%x", r, got, want)
		}
	}
}

func TestLowerMatchesStandardLibrary(t *testing.T) {
	cases := []string{
		"",
		"already lower",
		"MiXeD Case 123",
		"中文页面 Title 标题",
		"Kelvin K 与长 ſ",
		"İstanbul ȺȾ Straße",
		"ＦＵＬＬＷＩＤＴＨ ｌａｔｉｎ",
		"한국어 PAGE かな カナ",
		"Ꙁꙁ Ꜣꜣ ꭰ",
		"\xff<B>\xc0\xaf",
		"tail\xe4\xb8",
		"\xed\xa0\x80 surrogate",
		"ok\uFFFDvalid replacement",
		strings.Repeat("A", 4096) + "中" + strings.Repeat("b", 4096),
	}
	for _, input := range cases {
		if got, want := Lower([]byte(input)), bytes.ToLower([]byte(input)); !bytes.Equal(got, want) {
			t.Errorf("input=%q got=%q want=%q", input, got, want)
		}
		if got, want := LowerString([]byte(input)), strings.ToLower(input); got != want {
			t.Errorf("LowerString input=%q got=%q want=%q", input, got, want)
		}
	}
}

func TestLowerMatchesStandardLibraryRandom(t *testing.T) {
	rng := rand.New(rand.NewSource(20261112))
	alphabet := []string{"A", "z", "É", "ß", "İ", "K", "ſ", "Σ", "中", "한", "あ", "Ａ", "𝒜", "\xff", "\xc3", "\xe4\xb8", " ", "<", "Ⱥ", "Ω"}
	for i := 0; i < 20000; i++ {
		var input []byte
		for n := rng.Intn(24); n > 0; n-- {
			if rng.Intn(8) == 0 {
				input = append(input, byte(rng.Intn(256)))
			} else {
				input = append(input, alphabet[rng.Intn(len(alphabet))]...)
			}
		}
		if got, want := Lower(input), bytes.ToLower(input); !bytes.Equal(got, want) {
			t.Fatalf("input=%q got=%q want=%q", input, got, want)
		}
	}
}

func TestLowerReturnsInputWhenUnchanged(t *testing.T) {
	input := []byte("全小写 lower 文本 1234")
	if got := Lower(input); &got[0] != &input[0] {
		t.Fatal("无需改写的输入不应复制")
	}
}

func BenchmarkLower(b *testing.B) {
	inputs := map[string][]byte{
		"ascii": []byte(strings.Repeat(`<div class="Item"><A HREF="/News/1.html">Title</A></div>`, 4096)),
		"cjk":   []byte(strings.Repeat(`<div class="Item">新闻标题：关于系统升级的通知</div>`, 4096)),
	}
	for name, input := range inputs {
		b.Run("casefold/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			for i := 0; i < b.N; i++ {
				Lower(input)
			}
		})
		b.Run("stdlib/"+name, func(b *testing.B) {
			b.SetBytes(int64(len(input)))
			for i := 0; i < b.N; i++ {
				bytes.ToLower(input)
			}
		})
	}
}
