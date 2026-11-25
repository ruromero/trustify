use anyhow::{Context, anyhow, bail};
use clap::Parser;
use serde::Deserialize;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    process::Command,
};

/// Fail when an SBOM does not describe the dependency graph of the built binary.
///
/// The release workflow builds with `--no-default-features [--features pm]`, so the SBOM must be
/// generated with the same flags against the same target. Otherwise it describes a binary that
/// was never built: `Cargo.lock` is feature-blind and contains every optional dependency.
#[derive(Debug, Parser)]
pub struct SbomGate {
    /// The CycloneDX SBOM to check.
    #[arg(long)]
    pub sbom: PathBuf,

    /// The package the SBOM describes.
    #[arg(long, default_value = "trustify-trustd")]
    pub package: String,

    /// The target triple the binary was built for.
    #[arg(long)]
    pub target: Option<String>,

    /// Mirror `cargo build --no-default-features`.
    #[arg(long)]
    pub no_default_features: bool,

    /// Mirror `cargo build --features`.
    #[arg(long)]
    pub features: Vec<String>,

    /// Remove components the build did not produce before checking.
    ///
    /// `cargo cyclonedx` resolves the dependency graph, not the build, so it can still report
    /// optional dependencies that no enabled feature reaches (for example `arrow`, via
    /// `sea-orm/with-arrow`). Pruning makes the published SBOM match the build graph. Components
    /// the build does produce are never pruned, and a missing component is always fatal.
    #[arg(long)]
    pub prune: bool,

    /// How many entries to list per category.
    #[arg(long, default_value_t = 25)]
    pub limit: usize,
}

impl SbomGate {
    pub async fn run(self) -> anyhow::Result<()> {
        // `cargo tree` resolves features, `cargo metadata` resolves per platform. Neither is
        // sufficient alone: the former reports platform specific dependencies of crates built for
        // other platforms, the latter is unable to see which optional dependencies are enabled.
        let metadata = self.metadata(true)?;
        let resolved = self.cargo_tree()?;
        // `--filter-platform` also filters the package list, so ask the unfiltered resolver which
        // packages `cargo metadata` knows about at all.
        let known = self.metadata(false)?.packages();

        let mut expected = expected_components(&resolved, &metadata.closure(&self.package), &known);
        expected.remove(&metadata.root(&self.package)?);
        let tree_only = resolved.difference(&known).count();

        if self.prune {
            let pruned = self.prune_components(&expected)?;
            if pruned > 0 {
                println!("pruned {pruned} component(s) that no build produces");
            }
        }

        let bom = Bom::read(&self.sbom)?;
        let (actual, extra) = bom.cargo_components();

        let absent = expected
            .difference(&actual)
            .cloned()
            .collect::<BTreeSet<_>>();
        // `cargo cyclonedx` describes the resolver rather than the build and never emits
        // build-dependencies, so a compiled crate the metadata graph has never seen (a vendored
        // native library such as `openssl-src`) cannot be produced yet. Report it without failing
        // the release: dropping it would be worse, because it does ship in the binary.
        let (unresolved, missing) = absent
            .into_iter()
            .partition::<BTreeSet<_>, _>(|component| !known.contains(component));
        let listed = actual
            .difference(&expected)
            .cloned()
            .collect::<BTreeSet<_>>();

        if !extra.is_empty() {
            println!(
                "note: {} component(s) are not Cargo packages and are not checked: {}",
                extra.len(),
                summarise(&extra, self.limit)
            );
        }

        if tree_only > 0 {
            println!(
                "note: {tree_only} package(s) are resolved by `cargo tree` only and are still checked"
            );
        }

        if !unresolved.is_empty() {
            report(
                "compiled but not described by the generator",
                &unresolved,
                self.limit,
            );
            println!(
                "  note: `cargo cyclonedx` does not describe build-dependencies, so these ship in \
                 the binary but cannot be listed yet"
            );
        }

        if missing.is_empty() && listed.is_empty() {
            println!(
                "ok: {} describes {} component(s) of {}",
                self.sbom.display(),
                actual.len(),
                self.package
            );
            return Ok(());
        }

        report("built but missing from the SBOM", &missing, self.limit);
        report("listed but not built", &listed, self.limit);

        bail!(
            "{0} does not describe `{1}` for {2}: {3} missing, {4} listed but not built",
            self.sbom.display(),
            self.package,
            self.target.as_deref().unwrap_or("the host"),
            missing.len(),
            listed.len()
        )
    }

    fn cargo_tree(&self) -> anyhow::Result<BTreeSet<(String, String)>> {
        let mut command = Command::new("cargo");
        command.args([
            "tree",
            "--package",
            &self.package,
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ]);

        if self.no_default_features {
            command.arg("--no-default-features");
        }
        if !self.features.is_empty() {
            command.args(["--features", &self.features.join(",")]);
        }
        if let Some(target) = &self.target {
            command.args(["--target", target]);
        }

        let output = command.output().context("unable to run `cargo tree`")?;
        if !output.status.success() {
            bail!(
                "`cargo tree` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        Ok(parse_tree(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Drop Cargo components that are not part of the build graph, keeping the rest of the
    /// document (hashes, licenses, native and OS packages) untouched.
    fn prune_components(&self, expected: &BTreeSet<(String, String)>) -> anyhow::Result<usize> {
        let raw = std::fs::read_to_string(&self.sbom)
            .with_context(|| format!("unable to read {}", self.sbom.display()))?;
        let mut bom: serde_json::Value =
            serde_json::from_str(&raw).context("unable to parse the SBOM")?;

        // The root component describes the binary itself and is not listed in `components`.
        let mut referenced = bom
            .pointer("/metadata/component/bom-ref")
            .and_then(|value| value.as_str())
            .map(|value| BTreeSet::from([value.to_string()]))
            .unwrap_or_default();

        let mut pruned = 0;
        if let Some(components) = bom
            .get_mut("components")
            .and_then(|value| value.as_array_mut())
        {
            components.retain(|component| {
                let keep = match component.get("purl").and_then(|value| value.as_str()) {
                    Some(purl) if purl.starts_with("pkg:cargo/") => {
                        let name = component
                            .get("name")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default();
                        let version = component
                            .get("version")
                            .and_then(|value| value.as_str())
                            .unwrap_or_default();

                        expected.contains(&(name.to_string(), version.to_string()))
                    }
                    // Native libraries and OS packages cannot appear in the build graph.
                    _ => true,
                };

                if !keep {
                    pruned += 1;
                    return false;
                }

                if let Some(reference) = component.get("bom-ref").and_then(|value| value.as_str()) {
                    referenced.insert(reference.to_string());
                }

                true
            });
        }

        if pruned == 0 {
            return Ok(0);
        }

        if let Some(dependencies) = bom
            .get_mut("dependencies")
            .and_then(|value| value.as_array_mut())
        {
            dependencies.retain(|entry| {
                entry
                    .get("ref")
                    .and_then(|value| value.as_str())
                    .map(|reference| referenced.contains(reference))
                    .unwrap_or(true)
            });

            for entry in dependencies.iter_mut() {
                if let Some(refs) = entry
                    .get_mut("dependsOn")
                    .and_then(|value| value.as_array_mut())
                {
                    refs.retain(|reference| {
                        reference
                            .as_str()
                            .map(|reference| referenced.contains(reference))
                            .unwrap_or(true)
                    });
                }
            }
        }

        std::fs::write(&self.sbom, serde_json::to_vec_pretty(&bom)?)
            .with_context(|| format!("unable to write {}", self.sbom.display()))?;

        Ok(pruned)
    }

    fn metadata(&self, filter_platform: bool) -> anyhow::Result<Metadata> {
        let mut command = Command::new("cargo");
        command.args(["metadata", "--format-version", "1", "--locked"]);

        if filter_platform && let Some(target) = &self.target {
            command.args(["--filter-platform", target]);
        }

        let output = command.output().context("unable to run `cargo metadata`")?;
        if !output.status.success() {
            bail!(
                "`cargo metadata` failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        serde_json::from_slice(&output.stdout).context("unable to parse `cargo metadata`")
    }
}

/// The packages the build is expected to produce.
///
/// Neither resolver is authoritative, so combine them:
///
/// * start from `cargo tree`, which honours features but reports dependencies of crates that are
///   built for a different platform;
/// * keep only what `cargo metadata --filter-platform` also reaches, which drops those;
/// * but keep everything `cargo metadata` has never heard of. It does not resolve optional
///   build-dependencies, so a vendored native library such as `openssl-src` (behind
///   `openssl-sys/vendored`) is compiled and reported by the tree while being absent from the
///   metadata graph. Dropping it here would silently accept an SBOM that omits it.
///
/// `known` must be the unfiltered resolver: `--filter-platform` also removes packages from the
/// package list, which would make every platform specific crate look unknown.
fn expected_components(
    resolved: &BTreeSet<(String, String)>,
    platform: &BTreeSet<(String, String)>,
    known: &BTreeSet<(String, String)>,
) -> BTreeSet<(String, String)> {
    let platform_reachable = resolved
        .intersection(platform)
        .cloned()
        .collect::<BTreeSet<_>>();

    let unknown_to_metadata = resolved.difference(known).cloned().collect::<BTreeSet<_>>();

    platform_reachable
        .union(&unknown_to_metadata)
        .cloned()
        .collect()
}

fn report(title: &str, entries: &BTreeSet<(String, String)>, limit: usize) {
    if entries.is_empty() {
        return;
    }

    println!("\n{title} ({}):", entries.len());
    for (name, version) in entries.iter().take(limit) {
        println!("  {name}@{version}");
    }
    if entries.len() > limit {
        println!("  ... and {} more", entries.len() - limit);
    }
}

fn summarise(entries: &[String], limit: usize) -> String {
    let mut sorted = entries.to_vec();
    sorted.sort();

    if sorted.len() > limit {
        format!(
            "{} ... and {} more",
            sorted[..limit].join(", "),
            sorted.len() - limit
        )
    } else {
        sorted.join(", ")
    }
}

fn parse_tree(output: &str) -> BTreeSet<(String, String)> {
    output
        .lines()
        .filter_map(|line| {
            // `{p}` renders as `name v1.2.3`, optionally followed by ` (proc-macro)` or a path.
            let (name, rest) = line.trim().split_once(" v")?;
            let version = rest.split_whitespace().next()?;

            Some((name.to_string(), version.to_string()))
        })
        .collect()
}

#[derive(Debug, Deserialize)]
struct Bom {
    #[serde(default)]
    components: Vec<Component>,
}

impl Bom {
    fn read(path: &PathBuf) -> anyhow::Result<Self> {
        let file = std::fs::File::open(path)
            .with_context(|| format!("unable to open {}", path.display()))?;

        serde_json::from_reader(file).with_context(|| format!("unable to parse {}", path.display()))
    }

    /// Split the components into Cargo packages, which must match the build graph, and everything
    /// else (native libraries, OS packages), which the build graph cannot know about.
    fn cargo_components(&self) -> (BTreeSet<(String, String)>, Vec<String>) {
        self.components.iter().fold(
            (BTreeSet::new(), Vec::new()),
            |(mut cargo, mut extra), component| {
                match component.purl.as_deref() {
                    Some(purl) if purl.starts_with("pkg:cargo/") => {
                        cargo.insert((component.name.clone(), component.version.clone()));
                    }
                    Some(purl) => extra.push(purl.to_string()),
                    None => extra.push(component.name.clone()),
                }

                (cargo, extra)
            },
        )
    }
}

#[derive(Debug, Deserialize)]
struct Component {
    name: String,
    #[serde(default)]
    version: String,
    purl: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Metadata {
    packages: Vec<Package>,
    resolve: Resolve,
}

impl Metadata {
    /// The package the SBOM describes.
    fn root(&self, name: &str) -> anyhow::Result<(String, String)> {
        self.packages
            .iter()
            .find(|package| package.name == name)
            .map(|package| (package.name.clone(), package.version.clone()))
            .ok_or_else(|| anyhow!("unable to find package `{name}` in the workspace"))
    }

    /// Every package the resolver knows about, on any platform and with any feature.
    fn packages(&self) -> BTreeSet<(String, String)> {
        self.packages
            .iter()
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect()
    }

    /// Every package reachable from `name`, ignoring both features and dev-dependencies.
    fn closure(&self, name: &str) -> BTreeSet<(String, String)> {
        let nodes = self
            .resolve
            .nodes
            .iter()
            .map(|node| (node.id.as_str(), node))
            .collect::<BTreeMap<_, _>>();

        let packages = self
            .packages
            .iter()
            .map(|package| (package.id.as_str(), package))
            .collect::<BTreeMap<_, _>>();

        let mut seen = BTreeSet::new();
        let mut queue = self
            .packages
            .iter()
            .filter(|package| package.name == name)
            .map(|package| package.id.clone())
            .collect::<Vec<_>>();

        while let Some(id) = queue.pop() {
            if !seen.insert(id.clone()) {
                continue;
            }

            let Some(node) = nodes.get(id.as_str()) else {
                continue;
            };

            for dep in &node.deps {
                let wanted = dep
                    .dep_kinds
                    .iter()
                    .any(|kind| kind.kind.as_deref() != Some("dev"));

                if wanted {
                    queue.push(dep.pkg.clone());
                }
            }
        }

        seen.iter()
            .filter_map(|id| packages.get(id.as_str()))
            .map(|package| (package.name.clone(), package.version.clone()))
            .collect()
    }
}

#[derive(Debug, Deserialize)]
struct Package {
    id: String,
    name: String,
    version: String,
}

#[derive(Debug, Deserialize)]
struct Resolve {
    nodes: Vec<Node>,
}

#[derive(Debug, Deserialize)]
struct Node {
    id: String,
    #[serde(default)]
    deps: Vec<Dependency>,
}

#[derive(Debug, Deserialize)]
struct Dependency {
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<DependencyKind>,
}

#[derive(Debug, Deserialize)]
struct DependencyKind {
    #[serde(default)]
    kind: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tree_ignores_suffixes() {
        let tree = parse_tree(
            "anyhow v1.0.104\nclap v4.6.7 (proc-macro)\ntrustify-trustd v0.7.2 (/src/trustd)\n",
        );

        assert_eq!(
            tree,
            [
                ("anyhow".to_string(), "1.0.104".to_string()),
                ("clap".to_string(), "4.6.7".to_string()),
                ("trustify-trustd".to_string(), "0.7.2".to_string()),
            ]
            .into_iter()
            .collect::<BTreeSet<_>>()
        );
    }

    #[test]
    fn only_cargo_components_are_checked() {
        let bom: Bom = serde_json::from_str(
            r#"{
                "components": [
                    { "name": "arrow", "version": "60.1.0", "purl": "pkg:cargo/arrow@60.1.0" },
                    { "name": "aws-lc", "version": "5.11.0", "purl": "pkg:github/aws/aws-lc@5.11.0" }
                ]
            }"#,
        )
        .unwrap();

        let (cargo, extra) = bom.cargo_components();

        assert_eq!(
            cargo,
            [("arrow".to_string(), "60.1.0".to_string())]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(extra, ["pkg:github/aws/aws-lc@5.11.0"]);
    }

    #[test]
    fn expected_keeps_crates_metadata_does_not_resolve() {
        let set = |entries: &[(&str, &str)]| {
            entries
                .iter()
                .map(|(name, version)| (name.to_string(), version.to_string()))
                .collect::<BTreeSet<_>>()
        };

        // `cargo tree` sees the vendored build-dependency; `cargo metadata` never resolves it.
        let resolved = set(&[
            ("trustify-trustd", "0.7.2"),
            ("serde", "1.0.228"),
            ("security-framework", "3.7.0"),
            ("openssl-src", "300.6.1+3.6.3"),
        ]);
        // `cargo metadata --filter-platform x86_64-unknown-linux-gnu` drops the Apple-only crate.
        let platform = set(&[("trustify-trustd", "0.7.2"), ("serde", "1.0.228")]);
        let known = set(&[
            ("trustify-trustd", "0.7.2"),
            ("serde", "1.0.228"),
            ("security-framework", "3.7.0"),
        ]);

        let expected = expected_components(&resolved, &platform, &known);

        assert!(expected.contains(&("openssl-src".to_string(), "300.6.1+3.6.3".to_string())));
        assert!(!expected.contains(&("security-framework".to_string(), "3.7.0".to_string())));
        assert_eq!(expected.len(), 3);
    }

    #[test]
    fn closure_skips_dev_dependencies() {
        let metadata: Metadata = serde_json::from_str(
            r#"{
                "packages": [
                    { "id": "root", "name": "trustify-trustd", "version": "0.7.2" },
                    { "id": "common", "name": "trustify-common", "version": "0.7.2" },
                    { "id": "temp-env", "name": "temp-env", "version": "0.3.6" }
                ],
                "resolve": {
                    "nodes": [
                        {
                            "id": "root",
                            "deps": [
                                { "pkg": "common", "dep_kinds": [ { "kind": null } ] },
                                { "pkg": "temp-env", "dep_kinds": [ { "kind": "dev" } ] }
                            ]
                        },
                        { "id": "common", "deps": [] },
                        { "id": "temp-env", "deps": [] }
                    ]
                }
            }"#,
        )
        .unwrap();

        let closure = metadata.closure("trustify-trustd");

        assert!(closure.contains(&("trustify-common".to_string(), "0.7.2".to_string())));
        assert!(!closure.contains(&("temp-env".to_string(), "0.3.6".to_string())));
    }
}
