package logredact

import (
	"bytes"
	"encoding/json"
	"regexp"
)

// 以下正则用于对「发往上游大模型的出站内容」做明文隐私脱敏。
//
// 设计约束：
//   - Go 的 regexp 采用 RE2 语法，不支持 lookahead/lookbehind，因此使用
//     \b 词边界，并依靠「先长后短、先具体后宽泛」的替换顺序降低误伤。
//   - 这里只匹配自由文本中的 PII/密钥片段，键名在 RedactPIIJSON 中被保留。
var (
	// 中国大陆手机号：1 开头、第二位 3-9、共 11 位数字。
	rePIIMobile = regexp.MustCompile(`\b1[3-9]\d{9}\b`)
	// 18 位身份证号：17 位数字 + 1 位数字或 X/x。
	// 必须放在银行卡规则之前，避免 18 位身份证被银行卡（16-19 位）规则吞掉。
	rePIIIIDCard = regexp.MustCompile(`\b\d{17}[\dXx]\b`)
	// 银行卡号：16-19 位连续数字。
	rePIIBankCard = regexp.MustCompile(`\b\d{16,19}\b`)
	// 邮箱地址。
	rePIIEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	// OpenAI 风格密钥 / GitHub Personal Access Token 等常见令牌形态。
	rePIIOpenAIKey = regexp.MustCompile(`\bsk-[A-Za-z0-9]{16,}\b`)
	rePIIGitHubPAT = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b`)
)

// RedactPII 对一段自由文本做隐私脱敏，替换为 ***。
// 覆盖：邮箱、大陆手机号、18 位身份证、银行卡号、常见密钥令牌形态。
// 无命中时原样返回（调用方可用返回值是否相等判断是否发生变化）。
func RedactPII(text string) string {
	if text == "" {
		return text
	}
	out := text
	// 顺序敏感：身份证先于银行卡；手机号独立于两者；密钥片段最后处理。
	out = rePIIIIDCard.ReplaceAllString(out, "***")
	out = rePIIMobile.ReplaceAllString(out, "***")
	out = rePIIBankCard.ReplaceAllString(out, "***")
	out = rePIIEmail.ReplaceAllString(out, "***")
	out = rePIIOpenAIKey.ReplaceAllString(out, "***")
	out = rePIIGitHubPAT.ReplaceAllString(out, "***")
	return out
}

// RedactPIIJSON 对一段 JSON 中所有字符串值做隐私脱敏，保留键名、结构、
// 数字、布尔与 null。仅当实际发生替换时才返回 changed=true，否则原样返回
// 原始字节（零拷贝），避免对无 PII 的请求体做无谓的重新序列化。
//
// 解析失败（非 JSON）时原样返回，由调用方决定是否放行。
func RedactPIIJSON(raw []byte) ([]byte, bool) {
	if len(raw) == 0 {
		return raw, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	// 保留大整数精度：直接 json.Unmarshal 到 any 会把 int64 转成 float64，
	// 重新序列化时会改写为科学计数法、破坏请求体。UseNumber 让数字以原文保留。
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return raw, false
	}
	changed := false
	redacted := redactPIIValue(value, &changed)
	if !changed {
		return raw, false
	}
	encoded, err := json.Marshal(redacted)
	if err != nil {
		return raw, false
	}
	return encoded, true
}

// redactPIIValue 递归遍历 JSON 值，仅对字符串值调用 RedactPII。
// 键名永不被修改；数字、布尔、null 及其它类型原样保留。
func redactPIIValue(value any, changed *bool) any {
	switch v := value.(type) {
	case string:
		if v == "" {
			return v
		}
		out := RedactPII(v)
		if out != v {
			*changed = true
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			out[k] = redactPIIValue(item, changed)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = redactPIIValue(item, changed)
		}
		return out
	default:
		return value
	}
}