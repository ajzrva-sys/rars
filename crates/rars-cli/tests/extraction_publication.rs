#[path = "support/scratch.rs"]
mod scratch;

use rars::{ArchiveVersion, Builder};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn write_archive(path: &Path, version: ArchiveVersion, entries: &[(&[u8], &[u8])]) -> Vec<u8> {
    let mut builder = Builder::new(version).store(true);
    for &(name, data) in entries {
        builder
            .add_bytes(name.to_vec(), data.to_vec(), None, None)
            .unwrap();
    }
    let bytes = builder.to_bytes().unwrap();
    fs::write(path, &bytes).unwrap();
    bytes
}

fn extract(archive: &Path, destination: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_rars"))
        .args(["x", "--overwrite=always"])
        .args(extra)
        .arg(archive)
        .arg(destination)
        .output()
        .unwrap()
}

#[cfg(unix)]
#[test]
fn overwriting_an_output_hard_link_preserves_its_outside_target() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let root = scratch::case("extraction-hardlink-publication");
        let archive = root.join("archive.rar");
        write_archive(&archive, version, &[(b"file.txt", b"new archive contents")]);
        let destination = root.join("out");
        fs::create_dir(&destination).unwrap();
        let outside = root.join("outside.txt");
        fs::write(&outside, b"original outside contents").unwrap();
        fs::hard_link(&outside, destination.join("file.txt")).unwrap();
        let result = extract(&archive, &destination, &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(fs::read(&outside).unwrap(), b"original outside contents");
        assert_eq!(
            fs::read(destination.join("file.txt")).unwrap(),
            b"new archive contents"
        );
        assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
    }
}

#[test]
fn checksum_failure_preserves_existing_files_and_cleans_staging() {
    for version in [
        ArchiveVersion::Rar14,
        ArchiveVersion::Rar29,
        ArchiveVersion::Rar50,
    ] {
        let root = scratch::case("extraction-checksum-publication");
        let archive = root.join("archive.rar");
        let payload = b"unique nonzero payload for corrupt checksum";
        let mut bytes = write_archive(
            &archive,
            version,
            &[
                (b"earlier.txt", b"valid earlier member"),
                (b"file.txt", payload),
            ],
        );
        let offset = bytes
            .windows(payload.len())
            .position(|window| window == payload)
            .unwrap();
        bytes[offset] ^= 1;
        fs::write(&archive, bytes).unwrap();
        let destination = root.join("out");
        fs::create_dir(&destination).unwrap();
        fs::write(destination.join("file.txt"), b"keep existing contents").unwrap();
        let result = extract(&archive, &destination, &[]);
        assert!(!result.status.success());
        assert_eq!(
            fs::read(destination.join("file.txt")).unwrap(),
            b"keep existing contents"
        );
        assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
    }
}

#[test]
fn limit_failure_preserves_existing_files_and_cleans_staging() {
    let root = scratch::case("extraction-limit-publication");
    let archive = root.join("archive.rar");
    write_archive(
        &archive,
        ArchiveVersion::Rar50,
        &[(b"file.txt", b"new contents")],
    );
    let destination = root.join("out");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("file.txt"), b"keep existing contents").unwrap();
    let result = extract(&archive, &destination, &["--max-member-output-bytes", "1"]);
    assert!(!result.status.success());
    assert_eq!(
        fs::read(destination.join("file.txt")).unwrap(),
        b"keep existing contents"
    );
    assert_eq!(fs::read_dir(destination).unwrap().count(), 1);
}

#[test]
fn case_aliases_are_refused_on_insensitive_filesystems_and_kept_on_sensitive_ones() {
    let root = scratch::case("extraction-case-collision");
    let probe = root.join("CaseProbe");
    fs::write(&probe, []).unwrap();
    let insensitive = root.join("caseprobe").exists();
    fs::remove_file(probe).unwrap();
    let archive = root.join("archive.rar");
    write_archive(
        &archive,
        ArchiveVersion::Rar50,
        &[
            (b"A.txt", b"first contents"),
            (b"a.txt", b"second contents"),
        ],
    );
    let destination = root.join("out");
    let result = extract(&archive, &destination, &[]);
    if insensitive {
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("same output path"));
        assert_eq!(fs::read_dir(destination).unwrap().count(), 0);
    } else {
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(
            fs::read(destination.join("A.txt")).unwrap(),
            b"first contents"
        );
        assert_eq!(
            fs::read(destination.join("a.txt")).unwrap(),
            b"second contents"
        );
    }
}
