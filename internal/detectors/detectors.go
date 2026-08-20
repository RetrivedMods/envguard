package detectors

import (
	"math"
	"regexp"
	"strings"
)

type Rule struct {
	ID          string
	Name        string
	Severity    string
	Pattern     *regexp.Regexp
	Description string
	Validate    func(string) bool
}

var Rules = []Rule{
	{
		ID:          "github-token",
		Name:        "GitHub Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9_]{20,}\b`),
		Description: "Possible GitHub authentication token",
	},
	{
		ID:          "github-fine-grained-token",
		Name:        "GitHub Fine-Grained Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`),
		Description: "Possible GitHub fine-grained access token",
	},
	{
		ID:          "gitlab-pat",
		Name:        "GitLab Personal Access Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible GitLab personal access token",
	},
	{
		ID:          "gitlab-runner-token",
		Name:        "GitLab Runner Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bglrt-[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible GitLab runner token",
	},
	{
		ID:          "aws-access-key",
		Name:        "AWS Access Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`),
		Description: "Possible AWS access key",
	},
	{
		ID:          "alibaba-access-key",
		Name:        "Alibaba Cloud Access Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\b(?:LTAI|LTAY)[A-Za-z0-9]{16,20}\b`),
		Description: "Possible Alibaba Cloud access key",
	},
	{
		ID:          "tencent-secret-id",
		Name:        "Tencent Cloud Secret ID",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bAKID[A-Za-z0-9]{32,}\b`),
		Description: "Possible Tencent Cloud secret ID",
	},
	{
		ID:          "digitalocean-token",
		Name:        "DigitalOcean Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`),
		Description: "Possible DigitalOcean personal access token",
	},
	{
		ID:          "stripe-secret",
		Name:        "Stripe Secret Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bsk_(?:live|test)_[A-Za-z0-9]{16,}\b`),
		Description: "Possible Stripe secret key",
	},
	{
		ID:          "stripe-restricted",
		Name:        "Stripe Restricted Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\brk_(?:live|test)_[A-Za-z0-9]{16,}\b`),
		Description: "Possible Stripe restricted key",
	},
	{
		ID:          "slack-token",
		Name:        "Slack Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{20,}\b`),
		Description: "Possible Slack token",
	},
	{
		ID:          "sendgrid-key",
		Name:        "SendGrid API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`),
		Description: "Possible SendGrid API key",
	},
	{
		ID:          "mailgun-key",
		Name:        "Mailgun API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bkey-[a-f0-9]{32}\b`),
		Description: "Possible Mailgun private API key",
	},
	{
		ID:          "brevo-key",
		Name:        "Brevo API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bxkeysib-[A-Za-z0-9]{40}\b`),
		Description: "Possible Brevo API key",
	},
	{
		ID:          "postmark-token",
		Name:        "Postmark Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bpostmark-[a-f0-9]{32}\b`),
		Description: "Possible Postmark API token",
	},
	{
		ID:          "twilio-account-sid",
		Name:        "Twilio Account SID",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bAC[A-Za-z0-9]{32}\b`),
		Description: "Possible Twilio account SID",
	},
	{
		ID:          "twilio-api-key",
		Name:        "Twilio API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bSK[A-Za-z0-9]{32}\b`),
		Description: "Possible Twilio API key",
	},
	{
		ID:          "npm-token",
		Name:        "NPM Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bnpm_[A-Za-z0-9]{20,}\b`),
		Description: "Possible NPM access token",
	},
	{
		ID:          "telegram-bot-token",
		Name:        "Telegram Bot Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\b\d{8,12}:[A-Za-z0-9_-]{35}\b`),
		Description: "Possible Telegram bot token",
	},
	{
		ID:          "discord-bot-token",
		Name:        "Discord Bot Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\b[\w-]{24,28}\.[\w-]{6}\.[\w-]{27,}\b`),
		Description: "Possible Discord bot token",
	},
	{
		ID:          "openai-api-key",
		Name:        "OpenAI API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible OpenAI API key",
	},
	{
		ID:          "anthropic-api-key",
		Name:        "Anthropic API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Anthropic API key",
	},
	{
		ID:          "xai-api-key",
		Name:        "xAI API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bxai-[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible xAI API key",
	},
	{
		ID:          "groq-api-key",
		Name:        "Groq API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bgsk_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Groq API key",
	},
	{
		ID:          "openrouter-api-key",
		Name:        "OpenRouter API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bsk-or-v1-[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible OpenRouter API key",
	},
	{
		ID:          "huggingface-token",
		Name:        "Hugging Face Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bhf_[A-Za-z0-9]{20,}\b`),
		Description: "Possible Hugging Face access token",
	},
	{
		ID:          "mistral-api-key",
		Name:        "Mistral API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bmistral_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Mistral API key",
	},
	{
		ID:          "replicate-api-token",
		Name:        "Replicate API Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\br8_[A-Za-z0-9]{20,}\b`),
		Description: "Possible Replicate API token",
	},
	{
		ID:          "cohere-api-key",
		Name:        "Cohere API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bcohere-[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Cohere API key",
	},
	{
		ID:          "elevenlabs-api-key",
		Name:        "ElevenLabs API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\beleven_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible ElevenLabs API key",
	},
	{
		ID:          "newrelic-api-key",
		Name:        "New Relic API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bNRAK-[A-Za-z0-9]{27}\b`),
		Description: "Possible New Relic API key",
	},
	{
		ID:          "sentry-token",
		Name:        "Sentry Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bsntrys_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Sentry authentication token",
	},
	{
		ID:          "supabase-service-key",
		Name:        "Supabase Service Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bsbp_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Supabase service key",
	},
	{
		ID:          "shopify-access-token",
		Name:        "Shopify Access Token",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bshp(?:at|ca|ss)_[A-Za-z0-9]{32}\b`),
		Description: "Possible Shopify access token",
	},
	{
		ID:          "paddle-api-key",
		Name:        "Paddle API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bpaddle_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Paddle API key",
	},
	{
		ID:          "alchemy-api-key",
		Name:        "Alchemy API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\balch_[A-Za-z0-9_-]{20,}\b`),
		Description: "Possible Alchemy API key",
	},
	{
		ID:          "private-key",
		Name:        "Private Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY-----`),
		Description: "Private key material",
	},
	{
		ID:          "jwt",
		Name:        "JWT",
		Severity:    "MEDIUM",
		Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`),
		Description: "Possible JSON Web Token",
	},
	{
		ID:          "database-url",
		Name:        "Database URL",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqp)://[^[:space:]"'<>]+`),
		Description: "Database connection string",
	},
	{
		ID:          "google-api-key",
		Name:        "Google API Key",
		Severity:    "HIGH",
		Pattern:     regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`),
		Description: "Possible Google API key",
	},
	{
		ID:          "generic-secret",
		Name:        "Generic Secret Assignment",
		Severity:    "MEDIUM",
		Pattern:     regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|password|passwd|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key)\b\s*[:=]\s*["']([^"']{8,})["']`),
		Description: "Secret-like value assigned to a sensitive variable",
		Validate:    IsGenericSecretCandidate,
	},
}

var placeholderValues = map[string]struct{}{
	"":                    {},
	"example":             {},
	"sample":              {},
	"dummy":               {},
	"placeholder":         {},
	"changeme":            {},
	"change-me":           {},
	"replace-me":          {},
	"replace_me":          {},
	"your-api-key":        {},
	"your_api_key":        {},
	"your-token":          {},
	"your_token":          {},
	"your-secret":         {},
	"your_secret":         {},
	"insert-key-here":     {},
	"insert_key_here":     {},
	"insert-token-here":   {},
	"insert_token_here":   {},
	"test-key":            {},
	"test_key":            {},
	"test-token":          {},
	"test_token":          {},
	"fake-key":            {},
	"fake_key":            {},
	"fake-token":          {},
	"fake_token":          {},
	"foobar":              {},
	"lorem":               {},
}

func IsPlaceholder(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))

	if _, ok := placeholderValues[value]; ok {
		return true
	}

	return repeatedCharacters(value)
}

func repeatedCharacters(value string) bool {
	if len(value) < 6 {
		return false
	}

	for i := 1; i < len(value); i++ {
		if value[i] != value[0] {
			return false
		}
	}

	return true
}

func ShannonEntropy(value string) float64 {
	if len(value) == 0 {
		return 0
	}

	var counts [256]int

	for i := 0; i < len(value); i++ {
		counts[value[i]]++
	}

	length := float64(len(value))
	var result float64

	for _, count := range counts {
		if count == 0 {
			continue
		}

		probability := float64(count) / length
		result -= probability * math.Log2(probability)
	}

	return result
}

func IsHighEntropy(value string, threshold float64) bool {
	return len(value) >= 12 && ShannonEntropy(value) >= threshold
}

func IsGenericSecretCandidate(value string) bool {
	value = strings.TrimSpace(value)

	if IsPlaceholder(value) {
		return false
	}

	if len(value) < 12 {
		return false
	}

	if isCommonValue(value) {
		return false
	}

	return IsHighEntropy(value, 3.2)
}

func isCommonValue(value string) bool {
	switch strings.ToLower(value) {
	case "password123",
		"password1234",
		"admin123",
		"administrator",
		"letmein",
		"welcome123",
		"qwerty123",
		"secret123",
		"test123",
		"testpassword",
		"mypassword":
		return true
	default:
		return false
	}
}