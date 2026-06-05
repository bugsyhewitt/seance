// séance — listening to what the dead repos whisper.
// Public-commit secret scanner. Watches the GitHub public event stream and
// surfaces leaked credentials as fast as the source API allows.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/bugsyhewitt/seance/pkg/config"
)

var cfg = config.Defaults()

// configPath is the optional path to a TOML config file (--config). When set,
// the file is loaded as the base configuration and any flag the operator passes
// explicitly overrides the corresponding file value (precedence: defaults <
// file < flags/env).
var configPath string

var rootCmd = &cobra.Command{
	Use:   "seance",
	Short: "séance — listening to what the dead repos whisper",
	Long: `séance watches the GitHub public commit stream and surfaces leaked
credentials (API keys, tokens, private keys, .env files).

Findings are redacted: séance shows you where to look and what to rotate,
not the full secret. It does not verify credentials — that is your call.

Configuration precedence (lowest to highest): built-in defaults, then a TOML
file passed with --config, then explicitly-set flags and environment variables.
A flag you pass always wins over the same field in the config file, so you can
keep a stable file and override one value on the command line.`,
	PersistentPreRunE: applyConfigFile,
	RunE:              runScan,
}

// applyConfigFile implements the defaults < file < flags precedence. cobra has
// already parsed the command line into cfg by the time PersistentPreRunE runs,
// so cfg holds (defaults overlaid with explicitly-set flags). We load the file
// as a fresh base, then re-apply only the flags the operator actually changed on
// top of it — leaving file values in place for every flag left at its default.
func applyConfigFile(cmd *cobra.Command, _ []string) error {
	if configPath == "" {
		return nil // no file: cfg already holds defaults+flags, nothing to merge
	}

	// Snapshot the post-parse cfg so we can recover explicitly-set flag values
	// after we overwrite cfg with the file layer.
	parsed := cfg

	fileCfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	changed := make(map[string]bool)
	cmd.Flags().Visit(func(f *pflag.Flag) { changed[f.Name] = true })

	cfg = mergeConfig(fileCfg, parsed, changed)
	return nil
}

// mergeConfig applies séance's defaults < file < flags precedence. fileCfg is
// the configuration loaded from --config (already overlaid on defaults); parsed
// is the cfg cobra produced from defaults+flags; changed names the flags the
// operator set explicitly. The result is fileCfg with every explicitly-set
// flag's value copied over from parsed, so a flag always beats the file while
// file values survive for flags left at their default.
//
// It is a pure function of its inputs (no globals, no I/O) so the precedence
// rules can be tested directly.
func mergeConfig(fileCfg, parsed config.Config, changed map[string]bool) config.Config {
	out := fileCfg
	for name := range changed {
		switch name {
		case "token":
			out.GitHubToken = parsed.GitHubToken
		case "signatures":
			out.SignaturesPath = parsed.SignaturesPath
		case "enable-rule":
			out.EnableRules = parsed.EnableRules
		case "disable-rule":
			out.DisableRules = parsed.DisableRules
		case "output":
			out.OutputFormat = parsed.OutputFormat
		case "output-file":
			out.OutputPath = parsed.OutputPath
		case "output-max-bytes":
			out.OutputMaxBytes = parsed.OutputMaxBytes
		case "output-limit":
			out.OutputLimit = parsed.OutputLimit
		case "sarif-file":
			out.SarifPath = parsed.SarifPath
		case "csv-file":
			out.CSVPath = parsed.CSVPath
		case "state-dir":
			out.StateDir = parsed.StateDir
		case "poll-interval":
			out.PollIntervalSec = parsed.PollIntervalSec
		case "watch":
			out.Watch = parsed.Watch
		case "watch-since":
			out.WatchSince = parsed.WatchSince
		case "watch-until":
			out.WatchUntil = parsed.WatchUntil
		case "watch-interval":
			out.WatchIntervalSec = parsed.WatchIntervalSec
		case "force-push":
			out.ForcePush = parsed.ForcePush
		case "suppress-file":
			out.SuppressFile = parsed.SuppressFile
		case "min-confidence":
			out.MinConfidence = parsed.MinConfidence
		case "tag":
			out.IncludeTags = parsed.IncludeTags
		case "exclude-tag":
			out.ExcludeTags = parsed.ExcludeTags
		case "webhook-url":
			out.WebhookURL = parsed.WebhookURL
		case "webhook-header":
			out.WebhookHeaders = parsed.WebhookHeaders
		case "webhook-min-confidence":
			out.WebhookMinConfidence = parsed.WebhookMinConfidence
		case "webhook-format":
			out.WebhookFormat = parsed.WebhookFormat
		case "tui":
			out.TUI = parsed.TUI
		case "webhook-listen":
			out.WebhookListenAddr = parsed.WebhookListenAddr
		case "webhook-listen-secret":
			out.WebhookListenSecret = parsed.WebhookListenSecret
		case "rate-limit":
			out.RateLimit = parsed.RateLimit
		case "dedupe-window":
			out.DedupeWindowDays = parsed.DedupeWindowDays
		case "syslog-sink":
			out.SyslogSink = parsed.SyslogSink
		case "syslog-network":
			out.SyslogNetwork = parsed.SyslogNetwork
		case "syslog-addr":
			out.SyslogAddr = parsed.SyslogAddr
		case "syslog-tag":
			out.SyslogTag = parsed.SyslogTag
		case "syslog-facility":
			out.SyslogFacility = parsed.SyslogFacility
		case "syslog-severity":
			out.SyslogSeverity = parsed.SyslogSeverity
		case "syslog-min-confidence":
			out.SyslogMinConfidence = parsed.SyslogMinConfidence
		case "splunk-hec-url":
			out.SplunkHECURL = parsed.SplunkHECURL
		case "splunk-hec-token":
			out.SplunkHECToken = parsed.SplunkHECToken
		case "splunk-hec-index":
			out.SplunkHECIndex = parsed.SplunkHECIndex
		case "splunk-hec-source":
			out.SplunkHECSource = parsed.SplunkHECSource
		case "splunk-hec-sourcetype":
			out.SplunkHECSourceType = parsed.SplunkHECSourceType
		case "splunk-hec-host":
			out.SplunkHECHost = parsed.SplunkHECHost
		case "splunk-hec-min-confidence":
			out.SplunkHECMinConfidence = parsed.SplunkHECMinConfidence
		case "splunk-hec-insecure":
			out.SplunkHECInsecure = parsed.SplunkHECInsecure
		case "s3-bucket":
			out.S3Bucket = parsed.S3Bucket
		case "s3-region":
			out.S3Region = parsed.S3Region
		case "s3-prefix":
			out.S3Prefix = parsed.S3Prefix
		case "s3-access-key-id":
			out.S3AccessKeyID = parsed.S3AccessKeyID
		case "s3-secret-access-key":
			out.S3SecretAccessKey = parsed.S3SecretAccessKey
		case "s3-session-token":
			out.S3SessionToken = parsed.S3SessionToken
		case "s3-endpoint":
			out.S3Endpoint = parsed.S3Endpoint
		case "s3-force-path-style":
			out.S3ForcePathStyle = parsed.S3ForcePathStyle
		case "s3-min-confidence":
			out.S3MinConfidence = parsed.S3MinConfidence
		case "s3-batch-size":
			out.S3BatchSize = parsed.S3BatchSize
		case "s3-batch-bytes":
			out.S3BatchBytes = parsed.S3BatchBytes
		case "s3-flush-interval":
			out.S3FlushInterval = parsed.S3FlushInterval
		case "s3-insecure":
			out.S3Insecure = parsed.S3Insecure
		case "elasticsearch-url":
			out.ElasticsearchURL = parsed.ElasticsearchURL
		case "elasticsearch-index":
			out.ElasticsearchIndex = parsed.ElasticsearchIndex
		case "elasticsearch-api-key":
			out.ElasticsearchApiKey = parsed.ElasticsearchApiKey
		case "elasticsearch-username":
			out.ElasticsearchUsername = parsed.ElasticsearchUsername
		case "elasticsearch-password":
			out.ElasticsearchPassword = parsed.ElasticsearchPassword
		case "elasticsearch-min-confidence":
			out.ElasticsearchMinConfidence = parsed.ElasticsearchMinConfidence
		case "elasticsearch-insecure":
			out.ElasticsearchInsecure = parsed.ElasticsearchInsecure
		}
	}
	return out
}

func init() {
	rootCmd.PersistentFlags().StringVar(&configPath, "config", "", "path to a TOML config file holding any of the flags below; built-in defaults are the base, the file overlays them, and any flag you also pass on the command line overrides the file (defaults < file < flags); empty means flags-only")
	rootCmd.PersistentFlags().StringVar(&cfg.GitHubToken, "token", cfg.GitHubToken, "GitHub personal access token")
	rootCmd.PersistentFlags().StringVar(&cfg.SignaturesPath, "signatures", cfg.SignaturesPath, "path to TOML signatures file")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.EnableRules, "enable-rule", cfg.EnableRules, "rule ID to enable — when set (repeatable), ONLY the listed rules run and every other loaded rule is dropped (allowlist); empty runs all rules; the gitleaks --enable-rule analogue, applied on top of --signatures without editing it")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.DisableRules, "disable-rule", cfg.DisableRules, "rule ID to disable (repeatable) — the listed rules are dropped from the loaded ruleset; applied after --enable-rule and always wins over it; silence a noisy rule without editing --signatures")
	rootCmd.PersistentFlags().StringVar(&cfg.OutputFormat, "output", cfg.OutputFormat, "stdout streaming format: 'json' (newline-delimited JSON, the default) or 'text' (one compact human-readable line per finding, grep-friendly); for a SARIF report use --sarif-file; ignored when --tui takes over an interactive stdout")
	rootCmd.PersistentFlags().StringVar(&cfg.OutputPath, "output-file", cfg.OutputPath, "also append redacted NDJSON findings to this file (created with its parent dir; append mode); '-' or empty means stdout only — pairs with --tui to keep a machine-readable record while watching the live feed")
	rootCmd.PersistentFlags().Int64Var(&cfg.OutputMaxBytes, "output-max-bytes", cfg.OutputMaxBytes, "rotate the --output-file when it would exceed this many bytes: the active file is renamed to <file>.1 (older generations shift up, a few are kept) and a fresh file is opened, bounding total disk for a run-forever monitor; 0 (default) appends forever; ignored unless --output-file names a real file")
	rootCmd.PersistentFlags().IntVar(&cfg.OutputLimit, "output-limit", cfg.OutputLimit, "stop the run after this many findings have been emitted across all sinks; in-flight scan completes and every sink is closed cleanly (SARIF written, webhook queue drained, state persisted) — the same exit path as SIGINT; 0 (default) imposes no cap; useful for CI gates, bounded research runs, and demos")
	rootCmd.PersistentFlags().StringVar(&cfg.SarifPath, "sarif-file", cfg.SarifPath, "also write a SARIF 2.1.0 report of all findings to this file (ingestible by GitHub code scanning and other SARIF tools); written once on shutdown; empty disables it")
	rootCmd.PersistentFlags().StringVar(&cfg.CSVPath, "csv-file", cfg.CSVPath, "also write a CSV export of all findings (one header row + one row per redacted Finding) to this file for spreadsheets, BI tools, and ticketing imports; written once on shutdown (a clean run still produces a valid header-only file); empty disables it")
	rootCmd.PersistentFlags().StringVar(&cfg.StateDir, "state-dir", cfg.StateDir, "directory for persistent state")
	rootCmd.PersistentFlags().IntVar(&cfg.PollIntervalSec, "poll-interval", cfg.PollIntervalSec, "poll interval in seconds")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.Watch, "watch", cfg.Watch, "keyword to monitor via the GitHub commit Search API for targeted/org-scoped coverage, e.g. --watch acme-corp (repeatable); runs alongside the global events stream, empty disables it")
	rootCmd.PersistentFlags().StringVar(&cfg.WatchSince, "watch-since", cfg.WatchSince, "scope --watch search results to commits with a committer-date on or after this date (YYYY-MM-DD); applies only to the search provider; empty leaves the search corpus unscoped")
	rootCmd.PersistentFlags().StringVar(&cfg.WatchUntil, "watch-until", cfg.WatchUntil, "scope --watch search results to commits with a committer-date on or before this date (YYYY-MM-DD); applies only to the search provider; empty leaves the search corpus unscoped")
	rootCmd.PersistentFlags().IntVar(&cfg.WatchIntervalSec, "watch-interval", cfg.WatchIntervalSec, "poll cadence in seconds for the --watch Search-API provider (the targeted/org-scoped axis); applies only to --watch, not the global events stream (--poll-interval); 0 keeps the conservative 90s default; values below 10s are clamped up to protect the 30 req/min Search-API quota")
	rootCmd.PersistentFlags().BoolVar(&cfg.ForcePush, "force-push", cfg.ForcePush, "detect force-push history rewrites and scan the orphaned diff (one extra compare request per force-push)")
	rootCmd.PersistentFlags().StringVar(&cfg.SuppressFile, "suppress-file", cfg.SuppressFile, "path to a newline-delimited list of finding fingerprints to always ignore (the .gitleaksignore analogue); '#' comments allowed")
	rootCmd.PersistentFlags().Float64Var(&cfg.MinConfidence, "min-confidence", cfg.MinConfidence, "global confidence floor (0.0-1.0): drop findings below this score before they reach ANY sink (stdout, --output-file, --sarif-file, --tui, webhook); 0 emits everything; raise it to surface only high-confidence findings")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.IncludeTags, "tag", cfg.IncludeTags, "include only findings whose rule carries this tag (repeatable, case-insensitive), e.g. --tag aws --tag gcp; when set, every finding without a listed tag is dropped before it reaches ANY sink; the categorical complement to --min-confidence; empty includes all classes")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.ExcludeTags, "exclude-tag", cfg.ExcludeTags, "drop findings whose rule carries this tag (repeatable, case-insensitive), e.g. --exclude-tag generic; applied across ANY sink; wins over --tag when a tag is on both lists; empty excludes nothing")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookURL, "webhook-url", cfg.WebhookURL, "POST each finding (redacted) as JSON to this URL; empty disables the webhook sink")
	rootCmd.PersistentFlags().StringArrayVar(&cfg.WebhookHeaders, "webhook-header", cfg.WebhookHeaders, "header added to every webhook POST as KEY:VALUE (repeatable, e.g. Authorization:Bearer xyz)")
	rootCmd.PersistentFlags().Float64Var(&cfg.WebhookMinConfidence, "webhook-min-confidence", cfg.WebhookMinConfidence, "only POST findings with confidence at or above this threshold (0.0-1.0)")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookFormat, "webhook-format", cfg.WebhookFormat, "webhook POST body shape: 'json' (redacted Finding object, default), 'slack' ({\"text\":...} envelope), 'discord' ({\"content\":...} envelope), or 'teams' (Microsoft Teams MessageCard); slack/discord/teams let --webhook-url point straight at an incoming webhook with no relay")
	rootCmd.PersistentFlags().BoolVar(&cfg.TUI, "tui", cfg.TUI, "render a live, confidence-colored terminal feed of findings instead of raw NDJSON on stdout; falls back to NDJSON automatically when stdout is not a TTY")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookListenAddr, "webhook-listen", cfg.WebhookListenAddr, "TCP address on which séance listens for inbound GitHub push webhooks (e.g. ':8099' or '127.0.0.1:8099'); when set, every push delivery is scanned immediately with no polling or rate-limit cost — additive alongside the global events stream and --watch; empty disables the receiver")
	rootCmd.PersistentFlags().StringVar(&cfg.WebhookListenSecret, "webhook-listen-secret", cfg.WebhookListenSecret, "HMAC-SHA256 secret configured on the GitHub webhook 'Secret' field; when set, every delivery's X-Hub-Signature-256 is verified before the body is parsed; running without a secret is allowed but séance logs a warning")
	rootCmd.PersistentFlags().IntVar(&cfg.DedupeWindowDays, "dedupe-window", cfg.DedupeWindowDays, "retention window in DAYS for the cross-run finding seen-set (re-leak suppression); 0 (default) inherits --seen-ttl-days, so commit dedup and finding dedup share one window — byte-for-byte the prior behaviour; a non-zero value tunes finding suppression independently of the commit-side bound (e.g. --dedupe-window 30 keeps a re-pushed secret quiet for a month even though commit dedup expires at the SeenTTL); a negative value is rejected at startup")
	rootCmd.PersistentFlags().Float64Var(&cfg.RateLimit, "rate-limit", cfg.RateLimit, "cap the AGGREGATE outbound request rate (requests/second) across every séance HTTP surface — events poller, --watch Search-API provider, and diff fetcher — with a single shared token bucket; burst is capped at ceil(rate-limit); 0 (default) disables the cap entirely; useful when sharing a GitHub token, sitting behind a rate-limited proxy, or running in a tight budget; throttled requests are counted on the metrics line as rate_limit_throttled_total")
	rootCmd.PersistentFlags().BoolVar(&cfg.SyslogSink, "syslog-sink", cfg.SyslogSink, "ship each redacted finding as a JSON message to a syslog endpoint in addition to stdout — the SIEM-friendly path into rsyslog/syslog-ng/journald/Splunk/ELK/Datadog with no relay; with --syslog-network and --syslog-addr both empty the local syslog socket is used, otherwise dial the given remote collector; delivery is non-blocking and fail-open; unsupported on Windows/Plan 9 (séance refuses to start with this flag on those platforms)")
	rootCmd.PersistentFlags().StringVar(&cfg.SyslogNetwork, "syslog-network", cfg.SyslogNetwork, "transport for --syslog-sink: '' (local syslog socket, default), 'udp', 'tcp', 'unixgram', or 'unix'; empty means local — paired with --syslog-addr empty; non-empty requires --syslog-addr to also be set")
	rootCmd.PersistentFlags().StringVar(&cfg.SyslogAddr, "syslog-addr", cfg.SyslogAddr, "address of a remote syslog collector (e.g. 'logs.example.com:514') or path to a unix-domain socket; empty (the default) uses the local syslog socket; paired with --syslog-network")
	rootCmd.PersistentFlags().StringVar(&cfg.SyslogTag, "syslog-tag", cfg.SyslogTag, "syslog tag / program name (RFC3164 header field); empty uses 'seance'")
	rootCmd.PersistentFlags().StringVar(&cfg.SyslogFacility, "syslog-facility", cfg.SyslogFacility, "syslog facility for every message: 'user' (default), 'daemon', 'auth', 'authpriv', or 'local0'..'local7' (case-insensitive); security teams typically route séance to a dedicated local channel so findings are easy to ship onward without crossing into other user-facility traffic")
	rootCmd.PersistentFlags().StringVar(&cfg.SyslogSeverity, "syslog-severity", cfg.SyslogSeverity, "pin every message to this severity ('emerg','alert','crit','err','warning','notice','info','debug', case-insensitive); empty (default) derives severity from finding confidence (>=0.95 alert, >=0.85 crit, >=0.70 err, >=0.50 warning, >=0.30 notice, else info) so SIEM rules can fire on severity alone")
	rootCmd.PersistentFlags().Float64Var(&cfg.SyslogMinConfidence, "syslog-min-confidence", cfg.SyslogMinConfidence, "only ship findings with confidence at or above this threshold to syslog (0.0-1.0); the per-sink complement to --min-confidence; 0 ships everything that reached the syslog sink")
	rootCmd.PersistentFlags().StringVar(&cfg.SplunkHECURL, "splunk-hec-url", cfg.SplunkHECURL, "ship each redacted finding to a Splunk HTTP Event Collector endpoint (e.g. 'https://splunk.example.com:8088/services/collector/event') as a JSON HEC envelope in addition to stdout — the SIEM-native path into Splunk with no relay or forwarder needed; delivery is non-blocking and fail-open; pair with --splunk-hec-token; empty disables the sink")
	rootCmd.PersistentFlags().StringVar(&cfg.SplunkHECToken, "splunk-hec-token", cfg.SplunkHECToken, "Splunk HEC token, sent as 'Authorization: Splunk <token>'; required when --splunk-hec-url is set; SEANCE_SPLUNK_HEC_TOKEN env var is the Docker-friendly fallback")
	rootCmd.PersistentFlags().StringVar(&cfg.SplunkHECIndex, "splunk-hec-index", cfg.SplunkHECIndex, "pin every HEC event to this Splunk index; empty (default) uses the HEC token's default index — set it when the token is shared across uses and the security team wants seance events routed to a dedicated index")
	rootCmd.PersistentFlags().StringVar(&cfg.SplunkHECSource, "splunk-hec-source", cfg.SplunkHECSource, "HEC envelope 'source' field; empty uses 'seance'")
	rootCmd.PersistentFlags().StringVar(&cfg.SplunkHECSourceType, "splunk-hec-sourcetype", cfg.SplunkHECSourceType, "HEC envelope 'sourcetype' field — the hook Splunk admins target with a props.conf entry for field extraction; empty uses 'seance:finding'")
	rootCmd.PersistentFlags().StringVar(&cfg.SplunkHECHost, "splunk-hec-host", cfg.SplunkHECHost, "HEC envelope 'host' field; empty omits it and lets the HEC indexer pick (usually the sender's IP)")
	rootCmd.PersistentFlags().Float64Var(&cfg.SplunkHECMinConfidence, "splunk-hec-min-confidence", cfg.SplunkHECMinConfidence, "only ship findings at or above this confidence to Splunk HEC (0.0-1.0); per-sink complement to --min-confidence; 0 ships everything")
	rootCmd.PersistentFlags().BoolVar(&cfg.SplunkHECInsecure, "splunk-hec-insecure", cfg.SplunkHECInsecure, "skip TLS certificate verification on the HEC endpoint — enterprise HEC deployments routinely sit behind a self-signed or internal-CA certificate; default false (verify like any HTTPS client)")
	rootCmd.PersistentFlags().StringVar(&cfg.S3Bucket, "s3-bucket", cfg.S3Bucket, "ship each redacted finding to an S3 (or S3-compatible) bucket as a batched NDJSON object in addition to stdout — the data-lake-native path that Athena/Glue/EMR/OpenSearch can query directly with no forwarder or relay; objects land under Hive-style prefix/YYYY/MM/DD/HH/ partitions so partition pruning Just Works; delivery is non-blocking and fail-open; pair with --s3-access-key-id and --s3-secret-access-key; empty disables the sink")
	rootCmd.PersistentFlags().StringVar(&cfg.S3Region, "s3-region", cfg.S3Region, "AWS region for the S3 sink (e.g. 'us-east-1', 'eu-west-2'); required for SigV4 signing; empty defaults to 'us-east-1'")
	rootCmd.PersistentFlags().StringVar(&cfg.S3Prefix, "s3-prefix", cfg.S3Prefix, "object key prefix for the S3 sink (e.g. 'seance/prod'); a trailing slash is added if absent; empty puts objects at the bucket root which works but is messy at scale")
	rootCmd.PersistentFlags().StringVar(&cfg.S3AccessKeyID, "s3-access-key-id", cfg.S3AccessKeyID, "AWS access key id for the S3 sink; required when --s3-bucket is set; SEANCE_S3_ACCESS_KEY_ID env var is the Docker-friendly fallback")
	rootCmd.PersistentFlags().StringVar(&cfg.S3SecretAccessKey, "s3-secret-access-key", cfg.S3SecretAccessKey, "AWS secret access key for the S3 sink; required when --s3-bucket is set; SEANCE_S3_SECRET_ACCESS_KEY env var is the Docker-friendly fallback")
	rootCmd.PersistentFlags().StringVar(&cfg.S3SessionToken, "s3-session-token", cfg.S3SessionToken, "AWS STS session token for the S3 sink (sent as X-Amz-Security-Token); leave empty for long-lived IAM-user credentials; SEANCE_S3_SESSION_TOKEN env var is the Docker-friendly fallback")
	rootCmd.PersistentFlags().StringVar(&cfg.S3Endpoint, "s3-endpoint", cfg.S3Endpoint, "S3 endpoint URL override (e.g. 'https://minio.acme:9000' or 'http://localhost:4566'); empty defaults to the public AWS endpoint for --s3-region; set to point at MinIO, LocalStack, Ceph RGW, or any S3-compatible API")
	rootCmd.PersistentFlags().BoolVar(&cfg.S3ForcePathStyle, "s3-force-path-style", cfg.S3ForcePathStyle, "use path-style addressing (https://endpoint/bucket/key) instead of virtual-hosted style (https://bucket.endpoint/key); required for most S3-compatible servers and bucket names containing dots; default false (virtual-hosted, like real AWS)")
	rootCmd.PersistentFlags().Float64Var(&cfg.S3MinConfidence, "s3-min-confidence", cfg.S3MinConfidence, "only ship findings at or above this confidence to S3 (0.0-1.0); per-sink complement to --min-confidence; 0 ships everything")
	rootCmd.PersistentFlags().IntVar(&cfg.S3BatchSize, "s3-batch-size", cfg.S3BatchSize, "max findings per S3 object; bigger batches mean fewer PUTs (lower cost) and fatter files Athena/Glue can scan more efficiently; 0 uses 500")
	rootCmd.PersistentFlags().IntVar(&cfg.S3BatchBytes, "s3-batch-bytes", cfg.S3BatchBytes, "max NDJSON body size per S3 object in bytes; reaching this caps the object before --s3-batch-size does; 0 uses 4 MiB")
	rootCmd.PersistentFlags().DurationVar(&cfg.S3FlushInterval, "s3-flush-interval", cfg.S3FlushInterval, "max wall-clock time a finding may sit in the S3 buffer before being flushed (e.g. '60s', '5m'); bounds how stale the freshest object can be on a low-throughput run; 0 uses 60s")
	rootCmd.PersistentFlags().BoolVar(&cfg.S3Insecure, "s3-insecure", cfg.S3Insecure, "skip TLS certificate verification on the S3 endpoint — common for MinIO/LocalStack with self-signed certs; default false (verify like any HTTPS client)")
	rootCmd.PersistentFlags().StringVar(&cfg.ElasticsearchURL, "elasticsearch-url", cfg.ElasticsearchURL, "index each redacted finding into an Elasticsearch (or OpenSearch) cluster via the REST Index API (POST /<index>/_doc) in addition to stdout — the ELK/OpenSearch-native path that doesn't need Logstash or a Beats agent; delivery is non-blocking and fail-open; e.g. 'https://elastic.example.com:9200'; empty disables the sink")
	rootCmd.PersistentFlags().StringVar(&cfg.ElasticsearchIndex, "elasticsearch-index", cfg.ElasticsearchIndex, "Elasticsearch index to write documents into; empty uses 'seance-findings'; a static name or an ILM alias — date-suffix patterns are not expanded")
	rootCmd.PersistentFlags().StringVar(&cfg.ElasticsearchApiKey, "elasticsearch-api-key", cfg.ElasticsearchApiKey, "Elasticsearch API key for authentication, sent as 'Authorization: ApiKey <key>'; takes precedence over --elasticsearch-username/--elasticsearch-password; SEANCE_ELASTICSEARCH_API_KEY env var is the Docker-friendly fallback")
	rootCmd.PersistentFlags().StringVar(&cfg.ElasticsearchUsername, "elasticsearch-username", cfg.ElasticsearchUsername, "username for Elasticsearch HTTP Basic auth; pair with --elasticsearch-password; ignored when --elasticsearch-api-key is set")
	rootCmd.PersistentFlags().StringVar(&cfg.ElasticsearchPassword, "elasticsearch-password", cfg.ElasticsearchPassword, "password for Elasticsearch HTTP Basic auth; pair with --elasticsearch-username; SEANCE_ELASTICSEARCH_PASSWORD env var is the Docker-friendly fallback")
	rootCmd.PersistentFlags().Float64Var(&cfg.ElasticsearchMinConfidence, "elasticsearch-min-confidence", cfg.ElasticsearchMinConfidence, "only index findings at or above this confidence (0.0-1.0); per-sink complement to --min-confidence; 0 ships everything")
	rootCmd.PersistentFlags().BoolVar(&cfg.ElasticsearchInsecure, "elasticsearch-insecure", cfg.ElasticsearchInsecure, "skip TLS certificate verification on the Elasticsearch endpoint — self-managed clusters routinely use self-signed or internal-CA certificates; default false (verify)")
}

func runScan(_ *cobra.Command, _ []string) error {
	// --token takes precedence; GITHUB_TOKEN env var is the Docker-friendly fallback.
	if cfg.GitHubToken == "" {
		cfg.GitHubToken = os.Getenv("GITHUB_TOKEN")
	}
	// Same Docker-friendly env fallback for the Splunk HEC token so an operator
	// can pass it as a secret without baking it into a config file or flag.
	if cfg.SplunkHECToken == "" {
		cfg.SplunkHECToken = os.Getenv("SEANCE_SPLUNK_HEC_TOKEN")
	}
	// Same Docker-friendly env fallbacks for the S3 sink — the standard way
	// IAM credentials reach a containerized monitor without baking them into
	// a config file.
	if cfg.S3AccessKeyID == "" {
		cfg.S3AccessKeyID = os.Getenv("SEANCE_S3_ACCESS_KEY_ID")
	}
	if cfg.S3SecretAccessKey == "" {
		cfg.S3SecretAccessKey = os.Getenv("SEANCE_S3_SECRET_ACCESS_KEY")
	}
	if cfg.S3SessionToken == "" {
		cfg.S3SessionToken = os.Getenv("SEANCE_S3_SESSION_TOKEN")
	}
	// Docker-friendly env fallbacks for the Elasticsearch sink credentials.
	if cfg.ElasticsearchApiKey == "" {
		cfg.ElasticsearchApiKey = os.Getenv("SEANCE_ELASTICSEARCH_API_KEY")
	}
	if cfg.ElasticsearchPassword == "" {
		cfg.ElasticsearchPassword = os.Getenv("SEANCE_ELASTICSEARCH_PASSWORD")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	fmt.Fprintf(os.Stderr, "séance %s — listening to what the dead repos whisper\n", cfg.Version)

	return runPipeline(ctx, cfg)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
