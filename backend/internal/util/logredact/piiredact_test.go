package logredact

import (
	"strings"
	"testing"
)

func TestRedactPII(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "email",
			input: "我的邮箱是 alice@example.com，请联系我",
			want:  "我的邮箱是 ***，请联系我",
		},
		{
			name:  "mobile",
			input: "手机号 13800138000 请查收",
			want:  "手机号 *** 请查收",
		},
		{
			name:  "id card",
			input: "身份证 11010519491231002X",
			want:  "身份证 ***",
		},
		{
			name:  "bank card 16 digits",
			input: "卡号 6222021234567890",
			want:  "卡号 ***",
		},
		{
			name:  "bank card 19 digits",
			input: "6222021234567890123",
			want:  "***",
		},
		{
			name:  "openai key",
			input: "sk-abcdefghijklmnopqrstuvwxyz123456",
			want:  "***",
		},
		{
			name:  "github pat",
			input: "ghp_0123456789abcdefghijklmnop",
			want:  "***",
		},
		{
			name:  "no pii passes through",
			input: "你好，今天的天气不错",
			want:  "你好，今天的天气不错",
		},
		{
			name:  "short number not redacted",
			input: "订单号 20231107001",
			want:  "订单号 20231107001",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RedactPII(tt.input); got != tt.want {
				t.Fatalf("RedactPII(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestRedactPIIJSON(t *testing.T) {
	input := []byte(`{
		"model":"gpt-4o",
		"stream":true,
		"messages":[
			{"role":"user","content":"我的手机 13800138000，邮箱 bob@example.com"}
		]
	}`)
	out, changed := RedactPIIJSON(input)
	if !changed {
		t.Fatal("expected content to change")
	}
	s := string(out)
	if strings.Contains(s, "13800138000") || strings.Contains(s, "bob@example.com") {
		t.Fatalf("PII not redacted: %s", s)
	}
	// 关键字段必须保留
	for _, keep := range []string{`"model":"gpt-4o"`, `"stream":true`, `"role":"user"`, `"content"`} {
		if !strings.Contains(s, keep) {
			t.Fatalf("missing key field %q in %s", keep, s)
		}
	}
}

func TestRedactPIIJSONNoChange(t *testing.T) {
	input := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"hello world"}]}`)
	out, changed := RedactPIIJSON(input)
	if changed {
		t.Fatal("expected no change")
	}
	// 未变化时应返回原始字节（零拷贝）
	if string(out) != string(input) {
		t.Fatalf("expected bytes preserved, got %q", out)
	}
}

func TestRedactPIIJSONNonJSON(t *testing.T) {
	input := []byte(`not-json`)
	out, changed := RedactPIIJSON(input)
	if changed {
		t.Fatal("expected no change for non-JSON")
	}
	if string(out) != string(input) {
		t.Fatalf("expected raw bytes preserved, got %q", out)
	}
}