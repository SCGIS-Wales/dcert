fn main() {
    // Version is determined solely by Cargo.toml (set by CI auto-tag job).
    // We no longer use `git describe` because in CI the build commit is
    // often not the tagged commit, producing dirty versions like
    // "3.0.6-2-g6fa5dd5" instead of the intended "3.0.7".
}
