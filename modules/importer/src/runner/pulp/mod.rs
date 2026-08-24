use crate::model::{PulpAuth, PulpImporter};
use crate::runner::{
    RunOutput,
    context::RunContext,
    progress::{Progress, ProgressInstance},
    report::{Phase, ReportBuilder, ScannerError},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use reqwest::header;
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::SystemTime};
use tokio::sync::Mutex;
use tracing::instrument;
use trustify_entity::labels::Labels;
use trustify_module_ingestor::{
    graph::Graph,
    service::{Cache, IngestorService},
};

struct ManifestEntry {
    file: String,
    sha256: String,
    size: u64,
}

fn parse_manifest(data: &[u8]) -> Result<Vec<ManifestEntry>, anyhow::Error> {
    let text = std::str::from_utf8(data)?;
    let mut entries = Vec::new();

    for (line_num, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        let parts: Vec<&str> = line.splitn(3, ',').collect();
        if parts.len() != 3 {
            anyhow::bail!(
                "PULP_MANIFEST line {}: expected 3 comma-separated fields, got {}",
                line_num + 1,
                parts.len()
            );
        }

        entries.push(ManifestEntry {
            file: parts[0].to_string(),
            sha256: parts[1].to_string(),
            size: parts[2].parse().map_err(|e| {
                anyhow::anyhow!("PULP_MANIFEST line {}: invalid size: {e}", line_num + 1)
            })?,
        });
    }

    Ok(entries)
}

fn build_client(auth: &Option<PulpAuth>) -> Result<reqwest::Client, anyhow::Error> {
    let mut headers = header::HeaderMap::new();

    if let Some(auth) = auth {
        let value = match auth {
            PulpAuth::Basic { username, password } => {
                format!("Basic {}", BASE64.encode(format!("{username}:{password}")))
            }
            PulpAuth::Bearer { token } => format!("Bearer {token}"),
        };
        let mut auth_value = header::HeaderValue::from_str(&value)?;
        auth_value.set_sensitive(true);
        headers.insert(header::AUTHORIZATION, auth_value);
    }

    Ok(reqwest::Client::builder()
        .default_headers(headers)
        .build()?)
}

fn matches_patterns(file: &str, patterns: &[String]) -> bool {
    if patterns.is_empty() {
        return true;
    }
    patterns.iter().any(|p| {
        if p.contains('*') || p.contains('?') {
            glob_match(p, file)
        } else {
            file.contains(p.as_str())
        }
    })
}

fn glob_match(pattern: &str, text: &str) -> bool {
    let mut p = pattern.chars().peekable();
    let mut t = text.chars().peekable();

    fn inner(
        p: &mut std::iter::Peekable<std::str::Chars>,
        t: &mut std::iter::Peekable<std::str::Chars>,
    ) -> bool {
        loop {
            match (p.peek(), t.peek()) {
                (Some('*'), _) => {
                    p.next();
                    if p.peek().is_none() {
                        return true;
                    }
                    while t.peek().is_some() {
                        let mut p_clone = p.clone();
                        let mut t_clone = t.clone();
                        if inner(&mut p_clone, &mut t_clone) {
                            return true;
                        }
                        t.next();
                    }
                    return false;
                }
                (Some('?'), Some(_)) => {
                    p.next();
                    t.next();
                }
                (Some(pc), Some(tc)) if *pc == *tc => {
                    p.next();
                    t.next();
                }
                (None, None) => return true,
                _ => return false,
            }
        }
    }

    inner(&mut p, &mut t)
}

fn verify_sha256(data: &[u8], expected: &str) -> bool {
    let hash = hex::encode(Sha256::digest(data));
    hash == expected
}

impl super::ImportRunner {
    #[instrument(skip_all, err(level=tracing::Level::INFO))]
    pub async fn run_once_pulp(
        &self,
        context: impl RunContext + 'static,
        importer: PulpImporter,
        _last_success: Option<SystemTime>,
    ) -> Result<RunOutput, ScannerError> {
        let report = Arc::new(Mutex::new(ReportBuilder::new()));

        let result = self
            .run_pulp_inner(&context, &importer, report.clone())
            .await;

        let report = match Arc::try_unwrap(report) {
            Ok(report) => report.into_inner(),
            Err(report) => report.lock().await.clone(),
        }
        .build();

        match result {
            Ok(()) => Ok(report.into()),
            Err(err) => Err(ScannerError::Normal {
                err,
                output: report.into(),
            }),
        }
    }

    async fn run_pulp_inner(
        &self,
        context: &(impl RunContext + 'static),
        importer: &PulpImporter,
        report: Arc<Mutex<ReportBuilder>>,
    ) -> Result<(), anyhow::Error> {
        let progress = context.progress(format!("Import Pulp: {}", importer.source));
        let client = build_client(&importer.auth)?;

        let source = importer.source.trim_end_matches('/');
        let manifest_url = format!("{source}/PULP_MANIFEST");

        progress
            .message(format!("Fetching PULP_MANIFEST from {source}"))
            .await;
        let response = client.get(&manifest_url).send().await?.error_for_status()?;
        let manifest_bytes = response.bytes().await?;

        let mut entries = parse_manifest(&manifest_bytes)?;

        if !importer.only_patterns.is_empty() {
            entries.retain(|e| matches_patterns(&e.file, &importer.only_patterns));
        }

        let total = entries.len();
        let mut progress_instance = progress.start(total);

        let ingestor =
            IngestorService::new(Graph::new(), self.storage.clone(), self.analysis.clone());
        let retries = importer.fetch_retries.unwrap_or(3);

        for (idx, entry) in entries.iter().enumerate() {
            context
                .check_canceled(|| anyhow::anyhow!("import canceled"))
                .await?;

            let file_url = format!("{source}/{}", entry.file);
            progress
                .message(format!("Fetching {}/{}: {}", idx + 1, total, entry.file))
                .await;

            let body = match fetch_with_retries(&client, &file_url, retries).await {
                Ok(bytes) => bytes,
                Err(e) => {
                    report.lock().await.add_error(
                        Phase::Retrieval,
                        &entry.file,
                        format!("Failed to fetch {file_url}: {e}"),
                    );
                    progress_instance.tick().await;
                    continue;
                }
            };

            if body.len() as u64 != entry.size {
                report.lock().await.add_error(
                    Phase::Retrieval,
                    &entry.file,
                    format!(
                        "Size mismatch for {}: expected {} bytes, got {}",
                        entry.file,
                        entry.size,
                        body.len()
                    ),
                );
                progress_instance.tick().await;
                continue;
            }

            if !verify_sha256(&body, &entry.sha256) {
                report.lock().await.add_error(
                    Phase::Retrieval,
                    &entry.file,
                    format!(
                        "SHA256 mismatch for {}: expected {}",
                        entry.file, entry.sha256
                    ),
                );
                progress_instance.tick().await;
                continue;
            }

            let labels = Labels::new()
                .add("source", &file_url)
                .add("importer", context.name())
                .add("file", &entry.file)
                .extend(importer.common.labels.0.clone());

            match self
                .db
                .transaction(async |tx| {
                    ingestor
                        .ingest(&body, importer.format, labels, None, Cache::Skip, tx)
                        .await
                })
                .await
            {
                Ok(_) => {
                    report.lock().await.tick();
                }
                Err(e) => {
                    report.lock().await.add_error(
                        Phase::Upload,
                        &entry.file,
                        format!("Ingestion failed: {e}"),
                    );
                }
            }

            progress_instance.tick().await;
        }

        progress_instance.finish().await;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_manifest_valid() {
        let data = b"file1.json,abc123,100\nfile2.json,def456,200\n";
        let entries = parse_manifest(data).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].file, "file1.json");
        assert_eq!(entries[0].sha256, "abc123");
        assert_eq!(entries[0].size, 100);
        assert_eq!(entries[1].file, "file2.json");
    }

    #[test]
    fn parse_manifest_skips_blank_lines() {
        let data = b"\nfile1.json,abc123,100\n\n";
        let entries = parse_manifest(data).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn parse_manifest_rejects_malformed_line() {
        let data = b"file1.json,abc123";
        assert!(parse_manifest(data).is_err());
    }

    #[test]
    fn parse_manifest_rejects_invalid_size() {
        let data = b"file1.json,abc123,notanumber";
        assert!(parse_manifest(data).is_err());
    }

    #[test]
    fn matches_patterns_empty_matches_all() {
        assert!(matches_patterns("anything.json", &[]));
    }

    #[test]
    fn matches_patterns_glob() {
        let patterns = vec!["*.json".to_string()];
        assert!(matches_patterns("file.json", &patterns));
        assert!(!matches_patterns("file.xml", &patterns));
    }

    #[test]
    fn matches_patterns_substring() {
        let patterns = vec!["advisory".to_string()];
        assert!(matches_patterns("path/to/advisory-001.json", &patterns));
        assert!(!matches_patterns("path/to/sbom.json", &patterns));
    }

    #[test]
    fn glob_match_star() {
        assert!(glob_match("*.json", "test.json"));
        assert!(!glob_match("*.json", "test.xml"));
        assert!(glob_match("dir/*", "dir/file.txt"));
    }

    #[test]
    fn glob_match_question_mark() {
        assert!(glob_match("file?.json", "file1.json"));
        assert!(!glob_match("file?.json", "file12.json"));
    }

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("exact", "exact"));
        assert!(!glob_match("exact", "other"));
    }

    #[test]
    fn verify_sha256_valid() {
        let data = b"hello world";
        let expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert!(verify_sha256(data, expected));
    }

    #[test]
    fn verify_sha256_mismatch() {
        assert!(!verify_sha256(b"hello world", "0000000000000000"));
    }
}

async fn fetch_with_retries(
    client: &reqwest::Client,
    url: &str,
    max_retries: usize,
) -> Result<Vec<u8>, anyhow::Error> {
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(500 * attempt as u64)).await;
        }
        match client.get(url).send().await?.error_for_status() {
            Ok(resp) => return Ok(resp.bytes().await?.to_vec()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("fetch failed with no attempts")))
}
