use std::future::Future;

use async_graphql::{Context, Result, SimpleObject};
use identity_application::error::codes::graphql;
use identity_domain::pagination::{
    DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE, PaginationError, RawPageArgs, ValidatedPage,
    validate_page_arguments,
};

use super::error::app_error;
pub(crate) use crate::graphql::cursor::OpaqueCursor;

/// Full cardinality of an already-authorized collection after filtering.
/// Page cursors and limits do not change this value.
#[derive(SimpleObject)]
pub(crate) struct ConnectionTotal {
    pub total_count: u64,
}

pub(crate) async fn connection_total(
    ctx: &Context<'_>,
    count: impl Future<Output = Result<u64>>,
) -> Result<ConnectionTotal> {
    let total_count = if ctx.look_ahead().field("totalCount").exists() {
        count.await?
    } else {
        0
    };
    Ok(ConnectionTotal { total_count })
}

/// Validated Relay pagination arguments forwarded from GraphQL resolvers to application services.
#[derive(Debug, Clone, Default)]
pub(crate) struct PageArgs {
    pub(crate) first: Option<u32>,
    pub(crate) after: Option<String>,
    pub(crate) last: Option<u32>,
    pub(crate) before: Option<String>,
}

/// Validate Relay connection arguments consistently across every GraphQL connection field.
pub(crate) fn page_args(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<String>,
    last: Option<i32>,
    before: Option<String>,
) -> Result<PageArgs> {
    let max_page_size = ctx.data_opt::<usize>().copied().unwrap_or(MAX_PAGE_SIZE);
    validate_page_with_max(
        ctx,
        first,
        after.as_deref(),
        last,
        before.as_deref(),
        max_page_size,
    )?;
    Ok(PageArgs {
        first: first.map(|value| value as u32),
        after,
        last: last.map(|value| value as u32),
        before,
    })
}

/// Validate Relay connection arguments against `max_page_size`, returning the
/// resolved traversal direction, effective limit, and active boundary cursor.
pub(crate) fn validate_page_with_max<'a>(
    ctx: &Context<'_>,
    first: Option<i32>,
    after: Option<&'a str>,
    last: Option<i32>,
    before: Option<&'a str>,
    max_page_size: usize,
) -> Result<ValidatedPage<'a>> {
    validate_page_arguments(
        RawPageArgs::from_i32(first, after, last, before),
        DEFAULT_PAGE_SIZE,
        max_page_size,
    )
    .map_err(|error| map_pagination_error(ctx, error))
}

fn map_pagination_error(ctx: &Context<'_>, error: PaginationError) -> async_graphql::Error {
    match error {
        PaginationError::ConflictingArguments { .. } => {
            app_error(ctx, graphql::error::PageArgumentsConflict)
        }
        PaginationError::InvalidPageSize { field, max } => app_error(
            ctx,
            graphql::error::PageSizeInvalid::new(max).with_field(field),
        ),
    }
}

/// Standard Relay connection complexity multiplier: `1 + page_size * child_complexity`.
#[must_use]
pub(crate) fn page_complexity(
    first: Option<i32>,
    last: Option<i32>,
    child_complexity: usize,
) -> usize {
    let size = first
        .or(last)
        .unwrap_or(DEFAULT_PAGE_SIZE as i32)
        .clamp(1, MAX_PAGE_SIZE as i32) as usize;
    1 + size * child_complexity
}

/// Connection complexity multiplier for custom connections whose edge/node cost
/// stays linear per row even when child fields declare `complexity = 0`:
/// `1 + page_size * (1 + child_complexity)`.
#[must_use]
pub(crate) fn nested_page_complexity(
    first: Option<i32>,
    last: Option<i32>,
    child_complexity: usize,
) -> usize {
    let size = first
        .or(last)
        .unwrap_or(DEFAULT_PAGE_SIZE as i32)
        .clamp(1, MAX_PAGE_SIZE as i32) as usize;
    1 + size * (1 + child_complexity)
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, BTreeSet, HashMap, VecDeque},
        fs,
        path::Path,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use async_graphql::{
        EmptyMutation, EmptySubscription, Object, Request, Schema, Value,
        connection::{Connection, Edge},
        parser::{
            parse_schema,
            types::{
                BaseType, FieldDefinition, ObjectType, Type, TypeDefinition, TypeKind,
                TypeSystemDefinition,
            },
        },
    };
    use identity_application::error::{
        code::AppErrorCode,
        codes::{graphql::GraphqlErrorCode, graphql_transport::GraphqlTransportErrorCode},
    };
    use identity_domain::pagination::PageDirection;

    use super::*;

    #[derive(SimpleObject)]
    struct Item {
        id: i32,
    }

    struct Query {
        reads: Arc<AtomicUsize>,
    }

    #[Object]
    impl Query {
        async fn items(
            &self,
            ctx: &Context<'_>,
        ) -> Result<Connection<usize, Item, ConnectionTotal>> {
            let additional = connection_total(ctx, async {
                self.reads.fetch_add(1, Ordering::SeqCst);
                Ok(7)
            })
            .await?;
            let mut connection = Connection::with_additional_fields(false, true, additional);
            connection.edges.push(Edge::new(0, Item { id: 1 }));
            Ok(connection)
        }

        async fn check_page(
            &self,
            ctx: &Context<'_>,
            first: Option<i32>,
            after: Option<String>,
            last: Option<i32>,
            before: Option<String>,
        ) -> Result<String> {
            let validated =
                validate_page_with_max(ctx, first, after.as_deref(), last, before.as_deref(), 100)?;
            let dir = match validated.direction {
                PageDirection::Forward => "forward",
                PageDirection::Backward => "backward",
            };
            Ok(format!(
                "{dir}:{}:{:?}:{:?}",
                validated.limit, validated.after, validated.before
            ))
        }
    }

    #[tokio::test]
    async fn row_only_selection_does_not_run_a_count_query() {
        let reads = Arc::new(AtomicUsize::new(0));
        let schema = Schema::new(
            Query {
                reads: reads.clone(),
            },
            EmptyMutation,
            EmptySubscription,
        );
        let response = schema.execute("{ items { edges { node { id } } } }").await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        assert_eq!(reads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn count_selection_in_a_named_fragment_honors_aliases_and_uses_full_cardinality() {
        let reads = Arc::new(AtomicUsize::new(0));
        let schema = Schema::new(
            Query {
                reads: reads.clone(),
            },
            EmptyMutation,
            EmptySubscription,
        );
        let response = schema.execute("query { items { ...Totals edges { node { id } } } } fragment Totals on ItemConnection { matching: totalCount }").await;
        assert!(response.errors.is_empty(), "{:?}", response.errors);
        let data = response.data.into_json().unwrap();
        assert_eq!(data["items"]["matching"], 7);
        assert_eq!(data["items"]["edges"].as_array().unwrap().len(), 1);
        assert_eq!(reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn validate_page_with_max_rejects_conflicts_and_resolves_before_only_as_backward() {
        let schema = Schema::new(
            Query {
                reads: Arc::new(AtomicUsize::new(0)),
            },
            EmptyMutation,
            EmptySubscription,
        );

        for args in [
            "first: 10, last: 10",
            "after: \"a\", before: \"b\"",
            "first: 10, before: \"b\"",
            "last: 10, after: \"a\"",
        ] {
            let response = schema.execute(format!("{{ checkPage({args}) }}")).await;
            let code = response.errors[0]
                .extensions
                .as_ref()
                .and_then(|ext| ext.get("code"))
                .cloned();
            assert_eq!(
                code,
                Some(Value::from(GraphqlErrorCode::PageArgumentsConflict.code())),
                "expected conflict error for {args}: {:?}",
                response.errors
            );
        }

        for args in ["first: 0", "first: 101", "last: 0", "last: 101"] {
            let response = schema.execute(format!("{{ checkPage({args}) }}")).await;
            let code = response.errors[0]
                .extensions
                .as_ref()
                .and_then(|ext| ext.get("code"))
                .cloned();
            assert_eq!(
                code,
                Some(Value::from(GraphqlErrorCode::PageSizeInvalid.code())),
                "expected page size error for {args}: {:?}",
                response.errors
            );
        }

        let before_only = schema.execute("{ checkPage(before: \"cur\") }").await;
        assert!(before_only.errors.is_empty(), "{:?}", before_only.errors);
        let json = before_only.data.into_json().unwrap();
        assert_eq!(json["checkPage"], "backward:20:None:Some(\"cur\")");
    }

    fn base_type_name(ty: &Type) -> &str {
        match &ty.base {
            BaseType::Named(name) => name.as_str(),
            BaseType::List(inner) => base_type_name(inner),
        }
    }

    fn dummy_literal_for_type(
        ty: &Type,
        defs: &BTreeMap<String, TypeDefinition>,
        depth: usize,
    ) -> String {
        if depth > 6 {
            return "null".to_owned();
        }
        match &ty.base {
            BaseType::List(inner) => {
                if inner.nullable {
                    "[]".to_owned()
                } else {
                    format!("[{}]", dummy_literal_for_type(inner, defs, depth + 1))
                }
            }
            BaseType::Named(name) => match name.as_str() {
                "String" | "ID" | "DateTime" | "UUID" => {
                    "\"00000000-0000-0000-0000-000000000000\"".to_owned()
                }
                "Int" => "1".to_owned(),
                "Float" => "1.0".to_owned(),
                "Boolean" => "false".to_owned(),
                other => match defs.get(other).map(|def| &def.kind) {
                    Some(TypeKind::Enum(enum_def)) => enum_def
                        .values
                        .first()
                        .map(|val| val.node.value.node.to_string())
                        .unwrap_or_else(|| "UNKNOWN".to_owned()),
                    Some(TypeKind::InputObject(input_def)) => {
                        let fields = input_def
                            .fields
                            .iter()
                            .filter(|field| !field.node.ty.node.nullable)
                            .map(|field| {
                                format!(
                                    "{}: {}",
                                    field.node.name.node,
                                    dummy_literal_for_type(&field.node.ty.node, defs, depth + 1)
                                )
                            })
                            .collect::<Vec<_>>()
                            .join(", ");
                        format!("{{ {fields} }}")
                    }
                    _ => "\"0\"".to_owned(),
                },
            },
        }
    }

    fn format_required_args(
        field: &FieldDefinition,
        defs: &BTreeMap<String, TypeDefinition>,
        connection_override: Option<&str>,
    ) -> String {
        let mut parts = Vec::new();
        for arg in &field.arguments {
            let name = arg.node.name.node.as_str();
            if matches!(name, "first" | "after" | "last" | "before") {
                continue;
            }
            if !arg.node.ty.node.nullable {
                parts.push(format!(
                    "{name}: {}",
                    dummy_literal_for_type(&arg.node.ty.node, defs, 0)
                ));
            }
        }
        if let Some(extra) = connection_override {
            parts.push(extra.to_owned());
        } else if field
            .arguments
            .iter()
            .any(|arg| arg.node.name.node == "first")
        {
            parts.push("first: 1".to_owned());
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("({})", parts.join(", "))
        }
    }

    fn build_object_paths<'a>(
        query_name: &'a str,
        objects: &BTreeMap<String, &'a ObjectType>,
        defs: &BTreeMap<String, TypeDefinition>,
    ) -> HashMap<String, Vec<&'a FieldDefinition>> {
        let mut paths = HashMap::<String, Vec<&FieldDefinition>>::new();
        paths.insert(query_name.to_owned(), Vec::new());
        let mut queue = VecDeque::new();
        queue.push_back(query_name.to_owned());

        while let Some(type_name) = queue.pop_front() {
            let Some(obj) = objects.get(&type_name) else {
                continue;
            };
            let current_path = paths[&type_name].clone();
            for field in &obj.fields {
                if field.node.name.node.starts_with("__") {
                    continue;
                }
                let child_type = base_type_name(&field.node.ty.node);
                if objects.contains_key(child_type) && !paths.contains_key(child_type) {
                    let _ = defs;
                    let mut next_path = current_path.clone();
                    next_path.push(&field.node);
                    paths.insert(child_type.to_owned(), next_path);
                    queue.push_back(child_type.to_owned());
                }
            }
        }
        paths
    }

    fn wrap_selection(
        path: &[&FieldDefinition],
        target_call: String,
        defs: &BTreeMap<String, TypeDefinition>,
    ) -> String {
        let mut selection = target_call;
        for field in path.iter().rev() {
            let args = format_required_args(field, defs, None);
            selection = format!("{}{args} {{ {selection} }}", field.name.node);
        }
        format!("query {{ {selection} }}")
    }

    fn assert_has_complexity_rejection(errors: &[async_graphql::ServerError], context: &str) {
        let too_complex = GraphqlTransportErrorCode::QueryTooComplex.code();
        assert!(
            errors.iter().any(|error| {
                error.extensions.as_ref().and_then(|ext| ext.get("code"))
                    == Some(&Value::from(too_complex))
            }),
            "expected QueryTooComplex for {context}, got: {errors:?}"
        );
    }

    fn assert_no_complexity_rejection(errors: &[async_graphql::ServerError], context: &str) {
        let too_complex = GraphqlTransportErrorCode::QueryTooComplex.code();
        assert!(
            !errors.iter().any(|error| {
                error.extensions.as_ref().and_then(|ext| ext.get("code"))
                    == Some(&Value::from(too_complex))
            }),
            "unexpected QueryTooComplex for {context}, got: {errors:?}"
        );
    }

    #[tokio::test]
    async fn every_connection_field_enforces_relay_arguments_and_complexity() {
        let sdl = crate::graphql::schema_sdl();
        let document = parse_schema(&sdl).expect("executable schema SDL parses");

        let mut query_root = "Query".to_owned();
        let mut defs = BTreeMap::new();
        let mut objects = BTreeMap::new();

        for definition in &document.definitions {
            match definition {
                TypeSystemDefinition::Schema(schema) => {
                    if let Some(query) = &schema.node.query {
                        query_root = query.node.to_string();
                    }
                }
                TypeSystemDefinition::Type(type_def) => {
                    let name = type_def.node.name.node.to_string();
                    if let TypeKind::Object(obj) = &type_def.node.kind {
                        objects.insert(name.clone(), obj);
                    }
                    defs.insert(name, type_def.node.clone());
                }
                _ => {}
            }
        }

        let connection_types: BTreeSet<String> = objects
            .iter()
            .filter_map(|(name, obj)| {
                let has_page_info = obj.fields.iter().any(|f| f.node.name.node == "pageInfo");
                let has_edges = obj.fields.iter().any(|f| f.node.name.node == "edges");
                (has_page_info && has_edges).then_some(name.clone())
            })
            .collect();

        let paths = build_object_paths(&query_root, &objects, &defs);
        let schema = crate::graphql::schema::build_schema(16, 50);

        let mut verified_fields = 0usize;
        for (owner_name, obj) in &objects {
            for field in &obj.fields {
                let return_type = base_type_name(&field.node.ty.node);
                if !connection_types.contains(return_type) {
                    continue;
                }
                verified_fields += 1;

                for (arg_name, expected_type) in [
                    ("first", "Int"),
                    ("after", "String"),
                    ("last", "Int"),
                    ("before", "String"),
                ] {
                    let arg = field
                        .node
                        .arguments
                        .iter()
                        .find(|a| a.node.name.node == arg_name)
                        .unwrap_or_else(|| {
                            panic!(
                                "connection field {owner_name}.{} is missing `{arg_name}` argument",
                                field.node.name.node
                            )
                        });
                    assert!(
                        arg.node.ty.node.nullable,
                        "{owner_name}.{}.{arg_name} must be nullable",
                        field.node.name.node
                    );
                    assert_eq!(
                        base_type_name(&arg.node.ty.node),
                        expected_type,
                        "{owner_name}.{}.{arg_name} must have type {expected_type}",
                        field.node.name.node
                    );
                }

                let path = paths.get(owner_name).unwrap_or_else(|| {
                    panic!("connection owner {owner_name} is unreachable from {query_root}")
                });
                let field_name = field.node.name.node.as_str();

                for limit_arg in ["first: 100", "last: 100"] {
                    let args = format_required_args(&field.node, &defs, Some(limit_arg));
                    let leaf = format!(
                        "{field_name}{args} {{ pageInfo {{ hasNextPage }} edges {{ cursor }} }}"
                    );
                    let query = wrap_selection(path, leaf, &defs);
                    let response = schema.execute(Request::new(query)).await;
                    assert_has_complexity_rejection(
                        &response.errors,
                        &format!("{owner_name}.{field_name}({limit_arg})"),
                    );
                }

                let min_args = format_required_args(&field.node, &defs, Some("first: 1"));
                let min_leaf = format!("{field_name}{min_args} {{ pageInfo {{ hasNextPage }} }}");
                let min_query = wrap_selection(path, min_leaf, &defs);
                let min_response = schema.execute(Request::new(min_query)).await;
                assert_no_complexity_rejection(
                    &min_response.errors,
                    &format!("{owner_name}.{field_name}(first: 1)"),
                );
            }
        }

        assert!(
            verified_fields >= 15,
            "expected to verify at least 15 Relay connection fields, found {verified_fields}"
        );
    }

    #[test]
    fn every_connection_resolver_declares_bounded_page_size_validators() {
        let modules_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("graphql/schema/modules");
        let mut violations = Vec::new();
        let mut checked_params = Vec::new();
        scan_module_validators(&modules_root, &mut checked_params, &mut violations);

        assert!(
            checked_params.len() >= 30,
            "expected to inspect at least 30 `first`/`last` connection resolver parameters under {}, found {} ({checked_params:?})",
            modules_root.display(),
            checked_params.len(),
        );
        assert!(
            violations.is_empty(),
            "connection resolver page-size validator violations:\n{}",
            violations.join("\n")
        );
    }

    fn scan_module_validators(
        path: &Path,
        checked_params: &mut Vec<String>,
        violations: &mut Vec<String>,
    ) {
        if path.is_dir() {
            for entry in fs::read_dir(path).unwrap() {
                scan_module_validators(&entry.unwrap().path(), checked_params, violations);
            }
            return;
        }
        if path.extension().and_then(|ext| ext.to_str()) != Some("rs") {
            return;
        }

        let content = fs::read_to_string(path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        let mut in_object_attr = false;
        let mut brace_depth = 0usize;
        let mut saw_impl_brace = false;
        let mut in_test_mod = false;

        for (index, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed == "#[cfg(test)]" {
                in_test_mod = true;
            }
            if in_test_mod {
                continue;
            }
            if trimmed.starts_with("#[Object") {
                in_object_attr = true;
                brace_depth = 0;
                saw_impl_brace = false;
                continue;
            }
            if !in_object_attr {
                continue;
            }

            let opens = trimmed.bytes().filter(|&b| b == b'{').count();
            let closes = trimmed.bytes().filter(|&b| b == b'}').count();
            if opens > 0 {
                saw_impl_brace = true;
            }
            brace_depth = brace_depth.saturating_add(opens).saturating_sub(closes);

            for param in ["first: Option<i32>", "last: Option<i32>"] {
                if trimmed.contains(param) {
                    checked_params.push(format!("{}:{}", path.display(), index + 1));
                    let mut start = index;
                    while start > 0 {
                        let prev = lines[start - 1].trim();
                        if prev.ends_with(',') || prev.ends_with('(') {
                            break;
                        }
                        start -= 1;
                    }
                    let param_block = lines[start..=index].join(" ");
                    if !param_block.contains("minimum = 1")
                        || !param_block.contains("maximum = 100")
                    {
                        violations.push(format!(
                            "{}:{}: `{param}` must declare `#[graphql(validator(minimum = 1, maximum = 100))]`",
                            path.display(),
                            index + 1
                        ));
                    }
                }
            }

            if saw_impl_brace && brace_depth == 0 {
                in_object_attr = false;
            }
        }
    }
}
