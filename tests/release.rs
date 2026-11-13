//! The release rules (ci/release-tags.sh, ci/release-notes.sh, ci/release-plan.sh), run against fixture
//! repositories: which image tags a version gets, so a fleet's `MAJOR.MINOR` (tacplus-dev/tacplus#180) only ever
//! moves forward on its own line, which commits its notes list, which release is marked Latest, and which
//! versions a run may release from the checkout it has.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("ci").join(name)
}

fn run_script(dir: &Path, name: &str, version: &str) -> Output {
    run_args(dir, name, &[version])
}

fn run_args(dir: &Path, name: &str, args: &[&str]) -> Output {
    Command::new("bash")
        .arg(script(name))
        .args(args)
        .current_dir(dir)
        .output()
        .expect("bash")
}

/// What the script prints; the test fails when it fails.
fn run(dir: &Path, name: &str, version: &str) -> String {
    let out = run_script(dir, name, version);
    assert!(
        out.status.success(),
        "{name} {version}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap().trim().to_string()
}

fn git(dir: &Path, args: &[&str]) {
    let out = Command::new("git")
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "-c",
            "tag.gpgSign=false",
            "-c",
            "commit.gpgSign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .expect("git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// A repository at a fresh path under the target directory, removed first if a previous run left it.
fn repo(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("release")
        .join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    git(&dir, &["init", "-q", "-b", "main"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "first"]);
    dir
}

/// A repository with one commit per tag, tagged in push order; each commit's subject is "change for <tag>".
fn fixture(name: &str, tags: &[&str]) -> PathBuf {
    let dir = repo(name);
    for tag in tags {
        git(
            &dir,
            &[
                "commit",
                "-q",
                "--allow-empty",
                "-m",
                &format!("change for {tag}"),
            ],
        );
        git(&dir, &["tag", tag]);
    }
    dir
}

fn tags(name: &str, tags: &[&str], version: &str) -> String {
    run(&fixture(name, tags), "release-tags.sh", version)
}

#[test]
fn first_release_takes_its_line() {
    assert_eq!(tags("first", &["v0.1.0"], "v0.1.0"), "0.1.0 0.1");
}

#[test]
fn a_patch_moves_its_own_line_and_no_other() {
    // The issue's acceptance: v0.1.1 moves 0.1, and not an older line.
    assert_eq!(
        tags("patch", &["v0.0.3", "v0.1.0", "v0.1.1"], "v0.1.1"),
        "0.1.1 0.1"
    );
}

#[test]
fn a_patch_on_an_older_line_moves_only_that_line() {
    assert_eq!(
        tags("older-line", &["v0.1.0", "v0.2.0", "v0.1.1"], "v0.1.1"),
        "0.1.1 0.1"
    );
}

#[test]
fn an_older_patch_of_the_line_never_moves_it_back() {
    // A re-run of v0.1.1's release after v0.1.2 was pushed.
    assert_eq!(tags("backwards", &["v0.1.1", "v0.1.2"], "v0.1.1"), "0.1.1");
}

#[test]
fn versions_sort_as_numbers_not_text() {
    assert_eq!(
        tags("numeric", &["v0.1.9", "v0.1.10"], "v0.1.10"),
        "0.1.10 0.1"
    );
}

#[test]
fn a_pre_release_gets_only_its_own_tag() {
    assert_eq!(
        tags("pre", &["v0.1.1", "v0.1.2-rc.1"], "v0.1.2-rc.1"),
        "0.1.2-rc.1"
    );
}

#[test]
fn a_pre_release_does_not_hold_back_the_line() {
    assert_eq!(
        tags("pre-behind", &["v0.1.2-rc.1", "v0.1.1"], "v0.1.1"),
        "0.1.1 0.1"
    );
}

#[test]
fn a_version_that_is_not_major_minor_patch_is_refused() {
    let dir = fixture("refused", &["v0.1"]);
    assert!(!run_script(&dir, "release-tags.sh", "v0.1").status.success());
    assert!(!run_script(&dir, "release-notes.sh", "v0.1")
        .status
        .success());
}

/// The change lines of the notes, in order.
fn changes(notes: &str) -> Vec<&str> {
    notes
        .lines()
        .filter_map(|l| l.strip_prefix("- "))
        .map(|l| l.rsplit_once(" (").expect("a commit line ends in (hash)").0)
        .collect()
}

#[test]
fn first_release_notes_list_every_commit() {
    let notes = run(
        &fixture("notes-first", &["v0.1.0"]),
        "release-notes.sh",
        "v0.1.0",
    );
    assert_eq!(changes(&notes), ["change for v0.1.0", "first"]);
}

#[test]
fn notes_list_the_commits_since_the_previous_release() {
    let dir = fixture("notes-since", &["v0.1.0", "v0.1.1"]);
    let notes = run(&dir, "release-notes.sh", "v0.1.1");
    assert!(notes.starts_with("Changes since v0.1.0:"), "{notes}");
    assert_eq!(changes(&notes), ["change for v0.1.1"]);
}

#[test]
fn a_pre_release_is_not_a_previous_release() {
    let dir = fixture("notes-pre", &["v0.1.0", "v0.1.1-rc.1", "v0.1.1"]);
    let notes = run(&dir, "release-notes.sh", "v0.1.1");
    assert_eq!(
        changes(&notes),
        ["change for v0.1.1", "change for v0.1.1-rc.1"]
    );
}

#[test]
fn a_patch_on_an_older_line_is_noted_against_that_line() {
    let dir = repo("notes-older-line");
    git(&dir, &["tag", "v0.1.0"]);
    git(&dir, &["checkout", "-q", "-b", "release/0.1"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "fix on 0.1"]);
    git(&dir, &["checkout", "-q", "main"]);
    git(
        &dir,
        &["commit", "-q", "--allow-empty", "-m", "feature on main"],
    );
    git(&dir, &["tag", "v0.2.0"]);
    git(&dir, &["tag", "v0.1.1", "release/0.1"]);
    let notes = run(&dir, "release-notes.sh", "v0.1.1");
    assert_eq!(changes(&notes), ["fix on 0.1"]);
}

/// release-plan.sh's verdict in `dir`, checked out where the run would be: its `tags=` and `flag=`, and the notes.
fn plan(dir: &Path, version: &str, mode: &str) -> (String, String, String) {
    let notes = dir.join(".notes.md");
    let out = run_args(dir, "release-plan.sh", &[version, mode, notes.to_str().unwrap()]);
    assert!(
        out.status.success(),
        "release-plan.sh {version} {mode}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    let field = |k: &str| {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .unwrap_or_else(|| panic!("no {k}= in {stdout}"))
            .to_string()
    };
    (
        field("tags"),
        field("flag"),
        std::fs::read_to_string(notes).unwrap(),
    )
}

fn plan_refused(dir: &Path, version: &str, mode: &str) -> bool {
    let notes = dir.join(".notes.md");
    !run_args(dir, "release-plan.sh", &[version, mode, notes.to_str().unwrap()])
        .status
        .success()
}

#[test]
fn a_pushed_tag_is_released_and_the_highest_is_latest() {
    let dir = fixture("plan-push", &["v0.1.0", "v0.1.1"]);
    let (tags, flag, notes) = plan(&dir, "v0.1.1", "push");
    assert_eq!((tags.as_str(), flag.as_str()), ("0.1.1 0.1", "--latest"));
    assert_eq!(changes(&notes), ["change for v0.1.1"]);
}

#[test]
fn a_patch_on_an_older_line_is_never_latest() {
    let dir = repo("plan-older-line");
    git(&dir, &["tag", "v0.1.0"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "feature on main"]);
    git(&dir, &["tag", "v0.2.0"]);
    git(&dir, &["checkout", "-q", "-b", "release/0.1", "v0.1.0"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "fix on 0.1"]);
    git(&dir, &["tag", "v0.1.1"]);
    let (tags, flag, _) = plan(&dir, "v0.1.1", "push");
    assert_eq!((tags.as_str(), flag.as_str()), ("0.1.1 0.1", "--latest=false"));
}

#[test]
fn a_pre_release_is_marked_one() {
    let dir = fixture("plan-pre", &["v0.1.0", "v0.1.1-rc.1"]);
    let (tags, flag, _) = plan(&dir, "v0.1.1-rc.1", "push");
    assert_eq!((tags.as_str(), flag.as_str()), ("0.1.1-rc.1", "--prerelease"));
}

#[test]
fn an_existing_tag_is_published_from_its_own_commit() {
    // Publishing v0.1.1, tagged before the workflow existed, with main moved on since.
    let dir = fixture("plan-publish", &["v0.1.0", "v0.1.1"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "after v0.1.1"]);
    assert!(
        plan_refused(&dir, "v0.1.1", "publish"),
        "main is not v0.1.1's commit"
    );
    git(&dir, &["checkout", "-q", "v0.1.1"]);
    let (tags, flag, notes) = plan(&dir, "v0.1.1", "publish");
    assert_eq!((tags.as_str(), flag.as_str()), ("0.1.1 0.1", "--latest"));
    assert_eq!(changes(&notes), ["change for v0.1.1"]);
}

#[test]
fn only_an_existing_tag_is_published() {
    let dir = fixture("plan-publish-missing", &["v0.1.0"]);
    assert!(plan_refused(&dir, "v0.1.1", "publish"));
    assert!(plan_refused(&dir, "v0.1.1", "push"));
}

#[test]
fn a_dry_run_of_the_next_patch_moves_its_line_and_no_older_one() {
    // The issue's acceptance, as a dry run: v0.1.2 at HEAD moves 0.1, and not 0.0.
    let dir = fixture("plan-dry-run", &["v0.0.3", "v0.1.0", "v0.1.1"]);
    git(&dir, &["commit", "-q", "--allow-empty", "-m", "a fix"]);
    let (tags, flag, notes) = plan(&dir, "v0.1.2", "dry-run");
    assert_eq!((tags.as_str(), flag.as_str()), ("0.1.2 0.1", "--latest"));
    assert_eq!(changes(&notes), ["a fix"]);
}

#[test]
fn a_dry_run_of_a_released_version_is_refused() {
    let dir = fixture("plan-dry-run-released", &["v0.1.0"]);
    assert!(plan_refused(&dir, "v0.1.0", "dry-run"));
}

#[test]
fn an_unknown_mode_is_refused() {
    let dir = fixture("plan-mode", &["v0.1.0"]);
    assert!(plan_refused(&dir, "v0.1.0", "release"));
}
