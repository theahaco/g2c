use worker::{event, Context, Env, Request, Response, Router};

mod handlers;
mod kv_store;

fn cors_headers(response: &mut Response) -> worker::Result<()> {
    let headers = response.headers_mut();
    headers.set("Access-Control-Allow-Origin", "*")?;
    headers.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")?;
    headers.set("Access-Control-Allow-Headers", "Content-Type")?;
    headers.set("Access-Control-Max-Age", "86400")?;
    Ok(())
}

fn handle_options(_req: Request, _ctx: worker::RouteContext<()>) -> worker::Result<Response> {
    let mut response = Response::ok("")?;
    cors_headers(&mut response)?;
    Ok(response)
}

#[event(fetch)]
async fn main(req: Request, env: Env, _ctx: Context) -> worker::Result<Response> {
    let router = Router::new();

    let mut response = router
        .get("/health", handlers::health)
        .post_async("/auth/challenge/:contract_id", handlers::create_challenge)
        .post_async("/auth/verify/:contract_id", handlers::verify)
        .options("/auth/challenge/:contract_id", handle_options)
        .options("/auth/verify/:contract_id", handle_options)
        .run(req, env)
        .await?;

    cors_headers(&mut response)?;

    Ok(response)
}
