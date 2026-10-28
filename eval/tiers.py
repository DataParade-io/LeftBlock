"""The critical tier: which labelled categories count as critical secrets.

The tier is an explicit mapping from CredData category names (and the names
the generated corpus uses) to a group. A labelled line is in the tier when
ANY of its categories maps to a critical group. Everything is spelled out so a
reviewer can disagree with a single line.

Groups (all of them are "critical"):

  cloud_keys      AWS, Google Cloud, Azure and Alibaba keys and tokens
  private_keys    PEM, base64-encoded PEM and JWK private keys
  provider_tokens API keys and tokens issued by a named provider
  passwords       passwords, including SQL, command-line and URL credentials
  auth_headers    Basic and Bearer (and NTLM) authorization values, and JWTs

Not critical, on purpose:

  generic         "Key", "Token", "API", "Secret", "Auth", "Credential": the
                  labellers could not name a provider, so these mix real keys
                  with config noise. Reported as the "broad" tier together
                  with the critical groups, never in the headline.
  everything else UUIDs, nonces, salts, bucket names, app ids, activation keys,
                  OTP seeds and tokens of unusual protocols (NKEY, PASERK,
                  PASETO), which are real but are not account-takeover
                  credentials in the sense of the question.
"""

CRITICAL_GROUPS = {
    "cloud_keys": (
        "AWS Client ID", "AWS Multi", "Azure Access Token",
        "Google API Key", "Google Multi", "Google OAuth Access Token", "Google OAuth Refresh Token",
        "Alibaba Access Key ID", "Alibaba Multi",
        # generated corpus
        "AWS access key", "AWS secret key", "Google API key",
    ),
    "private_keys": (
        "PEM Private Key", "BASE64 Private Key", "BASE64 encoded PEM Private Key", "JWK",
        # generated corpus
        "PEM private key",
    ),
    "provider_tokens": (
        "Slack Token", "Twilio Credentials", "Twilio Multi", "Stripe Credentials",
        "MailGun API Key", "Perplexity API Key", "Anthropic API Key", "Github Classic Token",
        "Grafana Provisioned API Key", "Grafana Service Account Token", "Grafana Access Policy Token",
        "Dropbox App secret", "Salesforce Credentials", "Akamai Credentials", "PostHog Credentials",
        "Postman Credentials", "Jira / Confluence PAT token", "Facebook Access Token",
        "WunderGraph API Key", "Docker Swarm Token",
        # generated corpus: every provider rule LeftBlock ships, plus the common platforms
        "OpenAI key", "OpenAI admin key", "Anthropic key", "Groq key", "xAI key", "Replicate key",
        "Together AI key", "OpenRouter key", "Fireworks key", "Cerebras key", "LangSmith key",
        "ElevenLabs key", "Voyage AI key", "Pinecone key",
        "Mistral key", "Cohere key", "Azure OpenAI key", "Deepgram key", "Together AI legacy key",
        "GitHub token", "Slack token", "Stripe key",
    ),
    "passwords": (
        "Password", "SQL Password", "CMD Password", "CMD Secret", "CMD Token",
        "CMD ConvertTo-SecureString", "URL Credentials", "CURL User Password",
        # generated corpus
        "Database URL password", "Password assignment",
    ),
    "auth_headers": (
        "Basic Authorization", "Bearer Authorization", "NTLM Token", "JSON Web Token",
        # generated corpus
        "JWT",
    ),
}

GENERIC = ("Key", "Token", "API", "Secret", "Auth", "Credential")

GROUP_OF = {name: group for group, names in CRITICAL_GROUPS.items() for name in names}

CRITICAL = "critical"
BROAD = "broad"  # critical plus the generic credential categories
OTHER = "other"


def group_of(category):
    """The critical group a category belongs to, or None."""
    return GROUP_OF.get(category)


def tier_of(categories):
    """``"critical"``, ``"broad"`` (generic credential only) or ``"other"``."""
    if any(c in GROUP_OF for c in categories):
        return CRITICAL
    if any(c in GENERIC for c in categories):
        return BROAD
    return OTHER


def in_tier(categories, tier):
    """True when a line with these categories belongs to ``tier``.

    ``critical`` is nested inside ``broad``: broad = critical + generic.
    """
    actual = tier_of(categories)
    if tier == CRITICAL:
        return actual == CRITICAL
    if tier == BROAD:
        return actual in (CRITICAL, BROAD)
    return True
