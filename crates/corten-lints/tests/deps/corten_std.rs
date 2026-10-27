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
