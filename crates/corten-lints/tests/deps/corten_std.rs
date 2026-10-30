// A stand-in for corten-std: a sink whose macro calls `from_template`.
pub mod html {
    pub struct Html(pub &'static str);
    impl Html {
        pub fn from_template(text: &'static str) -> Html {
            Html(text)
        }
    }
}
#[macro_export]
macro_rules! html {
    ($t:literal) => {
        $crate::html::Html::from_template($t)
    };
}
// A stand-in for corten-std's `Secret`.
pub mod secret {
    pub struct Secret(pub Vec<u8>);
    impl Secret {
        pub fn new(bytes: Vec<u8>) -> Result<Secret, ()> {
            Ok(Secret(bytes))
        }
        pub fn from_string(text: String) -> Result<Secret, ()> {
            Ok(Secret(text.into_bytes()))
        }
    }
}
