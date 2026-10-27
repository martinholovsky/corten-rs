//@ compiles: safe
// CWE-1336, template engine injection. The user's name becomes part of the
// template source, so "{{ config.secret }}" is evaluated by the engine.
// render stands in for a template engine such as Tera or Handlebars.
pub fn render(_template_src: &str) -> String {
    String::new()
}
pub fn welcome(name: &str) -> String {
    render(&format!("<h1>Welcome {name}</h1>"))
}
