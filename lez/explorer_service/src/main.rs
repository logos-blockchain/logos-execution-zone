#[expect(
    clippy::print_stdout,
    reason = "This is just simple and handy for such a small server"
)]
#[cfg(feature = "ssr")]
#[tokio::main]
async fn main() {
    use axum::Router;
    use clap::Parser;
    use explorer_service::App;
    use leptos::prelude::*;
    use leptos_axum::{LeptosRoutes as _, generate_route_list};
    use leptos_meta::MetaTags;

    /// LEZ Block Explorer Server CLI arguments.
    #[derive(Parser, Debug)]
    #[command(version, about, long_about = None)]
    struct Args {
        /// Indexer RPC URL.
        #[arg(long, env = "INDEXER_RPC_URL", default_value = "http://localhost:8779")]
        indexer_rpc_url: url::Url,
    }

    env_logger::init();

    let args = Args::parse();

    let conf = get_configuration(None).unwrap();
    let leptos_options = conf.leptos_options;
    let addr = leptos_options.site_addr;
    let routes = generate_route_list(App);

    // Create RPC client once
    let rpc_client = explorer_service::api::create_indexer_rpc_client(&args.indexer_rpc_url)
        .expect("Failed to create RPC client");

    // Build our application with routes
    let app = Router::new()
        .leptos_routes_with_context(
            &leptos_options,
            routes,
            {
                let rpc_client = rpc_client.clone();
                move || provide_context(rpc_client.clone())
            },
            {
                let leptos_options = leptos_options.clone();
                move || {
                    view! {
                        <!DOCTYPE html>
                        <html lang="en">
                            <head>
                                <meta charset="utf-8" />
                                <meta name="viewport" content="width=device-width, initial-scale=1" />
                                <AutoReload options=leptos_options.clone() />
                                <HydrationScripts options=leptos_options.clone() />
                                <MetaTags />
                            </head>
                            <body>
                                <App />
                            </body>
                        </html>
                    }
                }
            },
        )
        .fallback(leptos_axum::file_and_error_handler(|_| {
            view! { "Page not found" }
        }))
        .with_state(leptos_options);

    // Run the server
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    println!("Listening on http://{}", &addr);
    axum::serve(listener, app.into_make_service())
        .await
        .unwrap();
}

#[cfg(not(feature = "ssr"))]
fn main() {
    // Client-only main - no-op since hydration is done via wasm_bindgen
}
