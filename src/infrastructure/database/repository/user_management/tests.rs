use super::escape_like;

#[test]
fn search_terms_treat_sql_wildcards_literally() {
    assert_eq!(escape_like("100%_done"), "100\\%\\_done");
    assert_eq!(escape_like("a\\b"), "a\\\\b");
    assert_eq!(escape_like("ada"), "ada");
}
