use cap_std::{
    ambient_authority,
    fs::{Dir, File, OpenOptions},
};
use std::{io, path::Path};

pub(crate) fn open_destination(path: &Path) -> io::Result<Dir> {
    Dir::create_ambient_dir_all(path, ambient_authority())?;
    Dir::open_ambient_dir(path, ambient_authority())
}

pub(crate) fn create_file(destination: &Dir, path: &Path) -> io::Result<File> {
    match destination.remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    destination.open_with(path, &options)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn opening_a_file_rejects_a_parent_replaced_with_an_outside_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let root_path = tmp.path().join("destination");
        let outside = tmp.path().join("outside");
        std::fs::create_dir(&outside).unwrap();
        let root = open_destination(&root_path).unwrap();
        root.create_dir_all("nested").unwrap();

        std::fs::remove_dir(root_path.join("nested")).unwrap();
        symlink(&outside, root_path.join("nested")).unwrap();

        let error = create_file(&root, Path::new("nested/escaped.txt")).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(!outside.join("escaped.txt").exists());
    }
}
