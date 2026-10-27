//@ compiles: safe
// CWE-626, poison null byte. The extension check sees "shell.php\0.jpg" as a
// .jpg, but the downstream component stops at the NUL and opens shell.php.
// std::fs and Command reject interior NULs; c_style_open stands in for a
// NUL-terminated consumer (a C library, a wire protocol).
pub fn c_style_open(path: &[u8]) -> Vec<u8> {
    let end = path.iter().position(|&b| b == 0).unwrap_or(path.len());
    path[..end].to_vec()
}
pub fn serve_image(name: &str) -> Option<Vec<u8>> {
    if !name.ends_with(".jpg") {
        return None;
    }
    Some(c_style_open(name.as_bytes()))
}
