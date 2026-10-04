use sea_orm::sea_query::{
    Expr, ExprTrait, Func, IntoColumnRef, Query, SelectStatement, extension::postgres::PgExpr,
};

pub fn json_text(column: impl IntoColumnRef, field: &str) -> Expr {
    Expr::col(column).cast_json_field(field)
}

pub fn jsonb_set(column: impl IntoColumnRef, field: &str, value: impl Into<Expr>) -> Expr {
    Func::cust("jsonb_set")
        .args([
            Expr::col(column),
            Expr::value(vec![field.to_owned()]).cast_as("text[]"),
            value.into(),
            Expr::value(true),
        ])
        .into()
}

pub fn advisory_transaction_lock(key: impl Into<Expr>) -> SelectStatement {
    Query::select()
        .expr(Func::cust("pg_advisory_xact_lock").arg(key))
        .to_owned()
}
