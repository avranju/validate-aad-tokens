use anyhow::Result;
use azuread::AzureAd;
use clap::Parser;
use serde::Deserialize;

mod azuread;

/// Validate JWT tokens issued by Azure AD B2C
#[derive(Parser, Debug)]
struct Opts {
    /// Azure AD B2C tenant name
    #[clap(short, long)]
    tenant_name: String,

    /// Azure AD B2C policy name to use
    #[clap(short, long)]
    policy_name: String,

    /// Optional list of application IDs to validate against
    #[clap(short, long)]
    app_ids: Option<Vec<String>>,

    /// JWT access token issued by Azure AD B2C
    #[clap(long)]
    access_token: String,
}

#[derive(Deserialize, Debug, Clone)]
#[allow(dead_code)]
struct Claims {
    #[serde(rename = "iss")]
    issuer: String,

    #[serde(rename = "aud")]
    audience: String,

    #[serde(rename = "oid")]
    object_id: String,

    #[serde(rename = "sub")]
    subject: String,

    #[serde(rename = "tfp")]
    policy_name: String,

    #[serde(rename = "scp")]
    scopes: String,

    given_name: String,
    family_name: String,
    name: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Opts::parse();

    let mut aad = AzureAd::new(opts.tenant_name, opts.policy_name, opts.app_ids).await?;
    let claims = aad
        .validate_access_token::<Claims>(opts.access_token)
        .await?;

    println!("{claims:#?}");

    Ok(())
}
