//! `install.sh` must install the binary cargo actually built, wherever cargo put it.
//!
//! The script is run in a scratch copy of the repository layout with stand-ins for `cargo` and
//! the desktop-integration tools, so nothing is built and nothing outside the temp dir changes.

use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command;

fn script(path: &Path, body: &str) {
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
}

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    /// A checkout with an old `./target/release/bastion` lying around.
    fn new(fake_cargo: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo with space");
        std::fs::create_dir_all(repo.join("packaging")).unwrap();
        let real = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
        std::fs::copy(real, repo.join("install.sh")).unwrap();
        for f in ["bastion.desktop", "bastion.svg", "bastion-rdp.xml"] {
            std::fs::write(repo.join("packaging").join(f), f).unwrap();
        }
        script(&repo.join("target/release/bastion"), "echo STALE");

        let bin = dir.path().join("fakebin");
        script(&bin.join("cargo"), fake_cargo);
        // Never touch the real desktop/MIME databases from a test.
        for tool in ["update-mime-database", "update-desktop-database", "xdg-mime", "kbuildsycoca6"] {
            script(&bin.join(tool), "exit 0");
        }
        Self { dir }
    }

    fn run(&self) -> std::process::Output {
        let root = self.dir.path();
        Command::new("bash")
            .arg(root.join("repo with space/install.sh"))
            .env("PATH", format!("{}:/usr/bin:/bin", root.join("fakebin").display()))
            .env("HOME", root.join("home"))
            .env("XDG_CONFIG_HOME", root.join("home/.config"))
            .env("XDG_DATA_HOME", root.join("home/.local/share"))
            .env("PREFIX", root.join("prefix"))
            .env("FAKE_TARGET", root.join("shared target"))
            .env_remove("CARGO_TARGET_DIR")
            .output()
            .expect("run install.sh with bash")
    }

    fn installed(&self) -> Option<String> {
        std::fs::read_to_string(self.dir.path().join("prefix/bin/bastion")).ok()
    }
}

#[test]
fn installs_the_binary_from_cargos_real_target_directory() {
    // Like CARGO_TARGET_DIR / build.target-dir: the build lands outside ./target.
    let sandbox = Sandbox::new(
        r#"case "$1" in
  build) mkdir -p "$FAKE_TARGET/release" && printf '#!/bin/sh\necho FRESH\n' > "$FAKE_TARGET/release/bastion" && chmod +x "$FAKE_TARGET/release/bastion" ;;
  metadata) printf '{"packages":[],"target_directory":"%s","version":1}\n' "$FAKE_TARGET" ;;
  *) exit 2 ;;
esac"#,
    );
    let out = sandbox.run();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let installed = sandbox.installed().expect("binary installed");
    assert!(installed.contains("FRESH"), "installed the wrong binary: {installed}");
    let mode = std::fs::metadata(sandbox.dir.path().join("prefix/bin/bastion")).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o755);
    assert!(sandbox.dir.path().join("prefix/share/applications/bastion.desktop").exists());
}

#[test]
fn refuses_to_install_when_the_built_binary_cannot_be_found() {
    // The build "succeeds" but the binary is not where cargo says: fail, don't fall back to
    // the old ./target/release/bastion.
    let sandbox = Sandbox::new(
        r#"case "$1" in
  build) exit 0 ;;
  metadata) printf '{"packages":[],"target_directory":"%s","version":1}\n' "$FAKE_TARGET" ;;
esac"#,
    );
    let out = sandbox.run();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("nothing was installed"));
    assert_eq!(sandbox.installed(), None);

    // Same when cargo cannot say where it builds.
    let sandbox = Sandbox::new(r#"[ "$1" = build ] && exit 0; exit 101"#);
    assert!(!sandbox.run().status.success());
    assert_eq!(sandbox.installed(), None);
}
