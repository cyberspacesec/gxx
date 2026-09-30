package finger

import (
	"bytes"
	"errors"
	"io"

	"github.com/spaolacci/murmur3"
)

var errNotIcon = errors.New("资源内容不是图标")

// hashIconReader 读取到真实 EOF；超时、提前断流等错误不能产生前缀哈希。
// 原始块是 57 的整数倍，编码的分行与最终换行不受 Reader 分块影响。
func hashIconReader(reader io.Reader, probe *iconContentProbe) (int32, error) {
	h := murmur3.New32()
	var raw [57 * 32]byte
	var encoded [77*32 + 1]byte
	total := int64(0)
	for {
		read, emptyReads := 0, 0
		var err error
		for read < len(raw) && err == nil {
			var n int
			n, err = reader.Read(raw[read:])
			read += n
			if n == 0 {
				emptyReads++
				if emptyReads == 100 && err == nil {
					err = io.ErrNoProgress
				}
			} else {
				emptyReads = 0
			}
		}
		if err != nil && err != io.EOF {
			return 0, err
		}
		total += int64(read)
		if probe != nil {
			probe.feed(raw[:read])
			if probe.invalid() {
				return 0, errNotIcon
			}
		}
		n := encodeIconBase64(encoded[:], raw[:read])
		if err == io.EOF {
			if total == 0 {
				return 0, nil
			}
			encoded[n] = '\n'
			_, _ = h.Write(encoded[:n+1])
			return int32(h.Sum32()), nil
		}
		_, _ = h.Write(encoded[:n])
	}
}

// iconContentProbe 只保存文件签名和首个元素名。XML 声明、注释和空白
// 可以跨任意读取块，长前导内容不会要求保留完整图片或整个 XML token。
type iconContentProbe struct {
	validate  bool
	imageMIME bool
	prefix    [12]byte
	prefixN   int
	started   bool
	binary    bool
	state     uint8
	dashes    uint8
	quote     byte
	brackets  int
	name      [4]byte
	nameN     int
}

// invalid 只在文件签名或首个元素已确定时作判断；长 XML 前导不能误判 SVG。
func (p *iconContentProbe) invalid() bool {
	if !p.validate || p.state != 7 || p.binary {
		return false
	}
	return p.html() || !p.imageMIME && !p.elementIs("svg")
}

func (p *iconContentProbe) feed(data []byte) {
	if !p.started {
		n := copy(p.prefix[p.prefixN:], data)
		p.prefixN += n
		data = data[n:]
		if p.prefixN < len(p.prefix) {
			return
		}
		p.start()
	}
	p.feedMarkup(data)
}

func (p *iconContentProbe) start() {
	p.started = true
	prefix := p.prefix[:p.prefixN]
	p.binary = bytes.HasPrefix(prefix, []byte("\x89PNG\r\n\x1a\n")) || bytes.HasPrefix(prefix, []byte("\x00\x00\x01\x00")) || bytes.HasPrefix(prefix, []byte("\xff\xd8\xff")) || bytes.HasPrefix(prefix, []byte("GIF87a")) || bytes.HasPrefix(prefix, []byte("GIF89a")) || len(prefix) >= 12 && string(prefix[:4]) == "RIFF" && string(prefix[8:12]) == "WEBP"
	if p.binary {
		p.state = 7
		return
	}
	p.feedMarkup(bytes.TrimPrefix(prefix, []byte("\xef\xbb\xbf")))
}

func (p *iconContentProbe) finish() {
	if !p.started {
		p.start()
	}
}

func (p *iconContentProbe) feedMarkup(data []byte) {
	for _, b := range data {
		switch p.state {
		case 0:
			if b == '<' {
				p.state = 1
			} else if !metadataSpace(b) {
				p.state = 7
			}
		case 1:
			switch b {
			case '!':
				p.state, p.dashes = 2, 0
			case '?':
				p.state = 5
			default:
				p.state = 6
				p.addName(b)
			}
		case 2:
			if b == '-' {
				p.dashes++
				if p.dashes == 2 {
					p.state, p.dashes = 3, 0
				}
			} else {
				p.state = 4
				p.declaration(b)
			}
		case 3:
			if b == '>' && p.dashes >= 2 {
				p.state, p.dashes = 0, 0
			} else if b == '-' {
				p.dashes = min(p.dashes+1, 2)
			} else {
				p.dashes = 0
			}
		case 4:
			p.declaration(b)
		case 5:
			if b == '>' {
				p.state = 0
			}
		case 6:
			if metadataSpace(b) || b == '>' || b == '/' {
				p.state = 7
			} else {
				p.addName(b)
			}
		case 7:
			return
		}
	}
}

func (p *iconContentProbe) addName(b byte) {
	if p.nameN < len(p.name) {
		p.name[p.nameN] = b
	}
	p.nameN++
}

func (p *iconContentProbe) declaration(b byte) {
	if p.quote != 0 {
		if b == p.quote {
			p.quote = 0
		}
		return
	}
	switch b {
	case '\'', '"':
		p.quote = b
	case '[':
		p.brackets++
	case ']':
		if p.brackets > 0 {
			p.brackets--
		}
	case '>':
		if p.brackets == 0 {
			p.state = 0
		}
	}
}

func (p *iconContentProbe) elementIs(name string) bool {
	return p.state == 7 && p.nameN == len(name) && p.nameN <= len(p.name) && metadataEqualFold(p.name[:p.nameN], name)
}

func (p *iconContentProbe) html() bool {
	return p.elementIs("html") || p.elementIs("head") || p.elementIs("body")
}
